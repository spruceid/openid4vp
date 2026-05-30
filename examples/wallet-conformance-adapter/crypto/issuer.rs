//! Issuer key + certificate and SD-JWT VC (re)issuance for HAIP conformance.
//!
//! HAIP Section 6.1.1 requires the SD-JWT VC issuer signature to be validated
//! via X.509: the issuer JWT MUST carry `typ: dc+sd-jwt` and an `x5c` chain
//! (leaf signed by a CA, not self-signed; trust anchor excluded from `x5c`).
//!
//! The issuer key and leaf certificate are hardcoded test fixtures (like the
//! holder key in `keys.rs`), so they are identical on every run and machine. The
//! issuing CA (credential trust anchor) PEM is published in the adapter README
//! for the conformance suite's "Credential Trust Anchor" field.

use anyhow::Result;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// PKCS#8 private key of the issuer leaf (base64).
const ISSUER_KEY_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgucnzHrLxzgG5AfzfyEngt9lHZjGiGA7eyq5tl7vdk06hRANCAATLJMxI8pODFtGRGpVe/TeeJgD7PHFkcTfKmfkwHggFB7zhMWVFRzD/TLRNZfdjsdIx0w30646Saac2ASYMFXWF";

/// DER-encoded issuer leaf certificate (base64) — goes in the `x5c` header.
const ISSUER_LEAF_DER_B64: &str = "MIIBijCCATCgAwIBAgIUJ0PCKRnkSmbwl+FPi49lSjIlOQQwCgYIKoZIzj0EAwIwSDEeMBwGA1UEAwwVT0lENFZQIElzc3VlciBUZXN0IENBMRkwFwYDVQQKDBBDb25mb3JtYW5jZSBUZXN0MQswCQYDVQQGDAJCUjAgFw03NTAxMDEwMDAwMDBaGA80MDk2MDEwMTAwMDAwMFowQDEWMBQGA1UEAwwNT0lENFZQIElzc3VlcjEZMBcGA1UECgwQQ29uZm9ybWFuY2UgVGVzdDELMAkGA1UEBgwCQlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATLJMxI8pODFtGRGpVe/TeeJgD7PHFkcTfKmfkwHggFB7zhMWVFRzD/TLRNZfdjsdIx0w30646Saac2ASYMFXWFMAoGCCqGSM49BAMCA0gAMEUCIEaIH3C/LCVDUhPZrVjbBnSQhLCoPVlCPQQXRgBgaBjYAiEApcOXzuZeL1j5Ma/nHuI8HG13lOPu/IYOoafbw1k4qxM=";

struct IssuerMaterial {
    signing_key: SigningKey,
    leaf_der: Vec<u8>,
}

static ISSUER: LazyLock<IssuerMaterial> = LazyLock::new(|| {
    let key_pkcs8 = STANDARD
        .decode(ISSUER_KEY_PKCS8_B64)
        .expect("invalid issuer key base64");
    let signing_key = SigningKey::from_pkcs8_der(&key_pkcs8).expect("invalid issuer signing key");

    IssuerMaterial {
        signing_key,
        leaf_der: STANDARD
            .decode(ISSUER_LEAF_DER_B64)
            .expect("invalid issuer leaf base64"),
    }
});

/// Sign an issuer-signed SD-JWT VC JWT (`typ: dc+sd-jwt`, `x5c: [leaf]`).
pub fn sign_issuer_jwt(payload: &Value) -> Result<String> {
    let header = json!({
        "alg": "ES256",
        "typ": "dc+sd-jwt",
        "x5c": [STANDARD.encode(&ISSUER.leaf_der)],
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature: Signature = ISSUER.signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{signing_input}.{signature_b64}"))
}
