use anyhow::{Context, Result};
use josekit::jwe::ECDH_ES;
use josekit::jwk::Jwk;
use serde_json::Value;
use ssi::jwk::JWK;

/// Decrypt a JWE using ECDH-ES with our private key
pub fn decrypt_jwe(jwe: &str, private_key_jwk: &JWK) -> Result<Value> {
    let jwk_str = serde_json::to_string(private_key_jwk)?;
    let jwk = Jwk::from_bytes(jwk_str.as_bytes()).context("Invalid private key JWK")?;

    let decrypter: josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter<p256::NistP256> = ECDH_ES
        .decrypter_from_jwk(&jwk)
        .context("Failed to create ECDH-ES decrypter")?;

    let (payload, _header) =
        josekit::jwe::deserialize_compact(jwe, &decrypter).context("Failed to decrypt JWE")?;

    let value: Value =
        serde_json::from_slice(&payload).context("Failed to parse decrypted payload")?;

    Ok(value)
}
