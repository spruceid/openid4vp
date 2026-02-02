//! Key management for SD-JWT key binding

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// The holder key pair - matches the cnf.jwk in mock SD-JWT credentials
static HOLDER_KEY: LazyLock<SigningKey> = LazyLock::new(|| {
    // d parameter from the JWK (base64url-decoded to 32 bytes)
    let d_b64 = "DVt4adukimqmbPWT2g8amdJWUCBRuDOHorjeNQ0xTZk";
    let d_bytes = URL_SAFE_NO_PAD.decode(d_b64).expect("Failed to decode d parameter");

    let d_array: [u8; 32] = d_bytes.as_slice()
        .try_into()
        .expect("Invalid key length - expected 32 bytes");

    SigningKey::from_bytes(&d_array.into())
        .expect("Failed to create signing key")
});

/// Get the public JWK for the JWKS endpoint
pub fn public_jwk() -> Value {
    use p256::PublicKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let public_key: PublicKey = HOLDER_KEY.verifying_key().into();
    let encoded_point = public_key.to_encoded_point(false);

    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap()),
        "kid": "holder-key",
        "use": "sig",
        "alg": "ES256"
    })
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

    // Sign using p256
    let signature: Signature = HOLDER_KEY.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

fn compute_sd_hash(sd_jwt_without_kb: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sd_jwt_without_kb.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}
