use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod config;
mod credentials;
mod crypto;
mod dcql;
mod engine;
mod server;

use config::Config;
use engine::{HeadlessConfig, HeadlessEngine, WalletEngine};
use server::{create_router, AppState};

#[derive(Parser, Debug)]
#[command(name = "oid4vp-wallet-adapter")]
#[command(about = "Headless OID4VP wallet adapter for conformance testing")]
#[command(version)]
struct Cli {
    #[arg(short, long, default_value = "3000", env = "PORT")]
    port: u16,

    #[arg(short = 'H', long, default_value = "0.0.0.0", env = "HOST")]
    host: String,

    /// Public URL (for authorization_endpoint in metadata)
    ///
    /// Set this when using ngrok/cloudflared to expose the adapter.
    #[arg(long, env = "PUBLIC_URL")]
    public_url: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", env = "RUST_LOG")]
    log_level: String,

    /// Disable automatic consent (will decline all requests)
    #[arg(long, default_value = "false")]
    no_auto_consent: bool,

    /// Artificial response delay in milliseconds
    #[arg(long, default_value = "0", env = "RESPONSE_DELAY_MS")]
    response_delay_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Setup tracing/logging
    setup_logging(&cli.log_level);

    // Determine public URL
    let public_url = cli
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", cli.host, cli.port));

    // Create configuration
    let config = Config {
        authorization_endpoint: format!("{}/authorize", public_url).parse()?,
        public_url: public_url.parse()?,
        port: cli.port,
        host: cli.host.clone(),
    };

    // Create headless engine
    let engine_config = HeadlessConfig {
        auto_consent: !cli.no_auto_consent,
        response_delay_ms: cli.response_delay_ms,
    };

    let engine = Arc::new(HeadlessEngine::new(engine_config));

    // Create application state
    let state = AppState::new(engine.clone(), config.clone());

    // Create router
    let app = create_router(state);

    // Start server
    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port).parse()?;

    print_startup_banner(&config, engine.credentials_count());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Setup tracing subscriber for logging
fn setup_logging(log_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level))
        .add_directive("oid4vp_wallet_adapter=debug".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("tower_http=info".parse().unwrap());

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true).with_level(true))
        .init();
}

/// Print startup banner with configuration info
fn print_startup_banner(config: &Config, credentials_count: usize) {
    let base_url = config.public_url.as_str().trim_end_matches('/');

    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                   OID4VP 1.0 Wallet Adapter                      ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                  ║");
    println!("║  Public URL:           {:<40} ║", base_url);
    println!(
        "║  Authorization:        {:<40} ║",
        config.authorization_endpoint.as_str()
    );
    println!("║  Mock Credentials:     {:<40} ║", credentials_count);
    println!("║                                                                  ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Endpoints:                                                      ║");
    println!("║    {}/authorize", base_url);
    println!("║    {}/.well-known/openid-configuration", base_url);
    println!("║    {}/.well-known/jwks.json", base_url);
    println!("║                                                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
}
