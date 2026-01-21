//! JWE encryption for direct_post.jwt responses

use anyhow::{Context, Result};
use josekit::jwe::{JweHeader, ECDH_ES};
use josekit::jwk::Jwk;
use serde_json::Value;

/// Encrypt a payload as JWE using ECDH-ES with A256GCM
pub fn encrypt_jwe(payload: &Value, recipient_key: &Value) -> Result<String> {
    let jwk_str = serde_json::to_string(recipient_key)?;
    let jwk = Jwk::from_bytes(jwk_str.as_bytes()).context("Invalid recipient JWK")?;

    let encrypter = ECDH_ES
        .encrypter_from_jwk(&jwk)
        .context("Failed to create ECDH-ES encrypter")?;

    let mut header = JweHeader::new();
    header.set_algorithm("ECDH-ES");
    header.set_content_encryption("A256GCM");
    header.set_token_type("JWT");

    let payload_bytes = serde_json::to_vec(payload)?;
    let jwe = josekit::jwe::serialize_compact(&payload_bytes, &header, &encrypter)
        .context("Failed to encrypt JWE")?;

    Ok(jwe)
}
