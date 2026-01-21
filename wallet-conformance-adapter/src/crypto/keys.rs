//! Key management for SD-JWT key binding

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use josekit::jwk::alg::ec::EcKeyPair;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// The holder key pair - matches the cnf.jwk in mock SD-JWT credentials
static HOLDER_KEY: LazyLock<EcKeyPair> = LazyLock::new(|| {
    let jwk_json = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "CwNSKWddEnzdysuBW0aiQ2rvJl8UDL6o51qXeuw1goY",
        "y": "ENlE62SxzskwGMu3Poq0SDNRCxR7P4thyoxdURDonHs",
        "d": "DVt4adukimqmbPWT2g8amdJWUCBRuDOHorjeNQ0xTZk"
    });

    EcKeyPair::from_jwk(&josekit::jwk::Jwk::from_bytes(jwk_json.to_string().as_bytes()).unwrap())
        .expect("Failed to create holder key")
});

/// Get the public JWK for the JWKS endpoint
pub fn public_jwk() -> Value {
    let jwk = HOLDER_KEY.to_jwk_public_key();
    let mut jwk_value: Value = serde_json::from_str(&jwk.to_string()).unwrap_or(json!({}));

    if let Some(obj) = jwk_value.as_object_mut() {
        obj.insert("kid".to_string(), json!("holder-key"));
        obj.insert("use".to_string(), json!("sig"));
        obj.insert("alg".to_string(), json!("ES256"));
    }

    jwk_value
}

/// Create a Key Binding JWT for SD-JWT VC
pub fn create_key_binding_jwt(
    sd_jwt_without_kb: &str,
    nonce: &str,
    audience: &str,
) -> Result<String> {
    let now = chrono::Utc::now().timestamp();
    let sd_hash = compute_sd_hash(sd_jwt_without_kb);

    let header = json!({ "alg": "ES256", "typ": "kb+jwt" });
    let payload = json!({
        "nonce": nonce,
        "aud": audience,
        "iat": now,
        "sd_hash": sd_hash
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signer = josekit::jws::ES256
        .signer_from_jwk(&HOLDER_KEY.to_jwk_key_pair())
        .context("Failed to create signer")?;

    let signature = signer
        .sign(signing_input.as_bytes())
        .context("Failed to sign")?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

fn compute_sd_hash(sd_jwt_without_kb: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sd_jwt_without_kb.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}
