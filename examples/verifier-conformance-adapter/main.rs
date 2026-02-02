use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::net::TcpListener;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;
use url::Url;

mod crypto;
mod server;

use server::{create_router, AppState, OidfConfig};

#[derive(Parser, Debug)]
#[command(about = "OID4VP 1.0 Verifier Adapter for Conformance Testing")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "3000", env = "PORT")]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "0.0.0.0", env = "HOST")]
    host: String,

    /// Public URL where this server is accessible (used for response_uri)
    #[arg(long, env = "PUBLIC_URL")]
    public_url: Url,

    /// Log level
    #[arg(long, default_value = "info", env = "LOG_LEVEL")]
    log_level: String,

    /// Response mode: "direct_post" or "direct_post.jwt"
    #[arg(long, default_value = "direct_post", env = "RESPONSE_MODE")]
    response_mode: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_max_level(Level::TRACE)
        .init();

    let use_encrypted_response = args.response_mode == "direct_post.jwt";

    let state = Arc::new(AppState::new(args.public_url.clone(), use_encrypted_response).await?);

    print_startup_banner(&args, &state.oidf_config);

    let app = create_router(state);

    let addr = format!("{}:{}", args.host, args.port);
    info!("Listening on {}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn print_startup_banner(args: &Args, oidf: &OidfConfig) {
    let base_url = args.public_url.as_str().trim_end_matches('/');
    let response_mode = &args.response_mode;

    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                      OID4VP 1.0 Verifier Adapter                             ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                              ║");
    println!("║  Public URL:    {:<60} ║", base_url);
    println!("║  Client ID:     {:<60} ║", oidf.client_id);
    println!("║  Response Mode: {:<60} ║", response_mode);
    println!("║                                                                              ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Endpoints:                                                                  ║");
    println!("║    POST {}/initiate", base_url);
    println!("║    GET  {}/request/{{session_id}}", base_url);
    println!("║    POST {}/response/{{session_id}}", base_url);
    println!("║    GET  {}/status/{{session_id}}", base_url);
    println!("║                                                                              ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  OIDF Test Configuration (signing_jwk) - Copy the JSON below:               ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("{{");
    println!("  \"x\": \"{}\",", oidf.x);
    println!("  \"y\": \"{}\",", oidf.y);
    println!("  \"d\": \"{}\",", oidf.d);
    println!("  \"x5c\": [\"{}\"]", oidf.x5c);
    println!("}}");
    println!();
    println!();
}
