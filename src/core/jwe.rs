use anyhow::{bail, Context, Result};
use josekit::{
    jwe::JweHeader,
    jwk::Jwk,
    jwt::{encode_with_encrypter, JwtPayload},
};
use serde_json::Value as Json;

/// Default supported algorithms for OID4VP JWE encryption.
pub const DEFAULT_ALG: &str = "ECDH-ES";
pub const DEFAULT_ENC: &str = "A256GCM";

/// Builder for creating JWE-encrypted authorization responses.
///
/// Per OID4VP v1.0 §8.3, responses are encrypted using ECDH-ES with A256GCM.
#[derive(Debug, Clone, Default)]
pub struct JweBuilder {
    payload: Option<Json>,
    recipient_key: Option<Jwk>,
    alg: Option<String>,
    enc: Option<String>,
    kid: Option<String>,
}

impl JweBuilder {
    /// Creates a new JWE builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the payload to encrypt.
    ///
    /// The payload should be a JSON object containing the authorization response
    /// parameters (e.g., `vp_token`, `state`).
    pub fn payload(mut self, payload: Json) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Sets the recipient's public key for encryption.
    pub fn recipient_key(mut self, jwk: Jwk) -> Self {
        self.recipient_key = Some(jwk);
        self
    }

    /// Sets the recipient's public key from a JSON value.
    pub fn recipient_key_json(mut self, jwk: &Json) -> Result<Self> {
        let jwk_str = serde_json::to_string(jwk)?;
        let jwk = Jwk::from_bytes(jwk_str.as_bytes()).context("invalid recipient JWK")?;
        self.recipient_key = Some(jwk);
        Ok(self)
    }

    /// Sets the key agreement algorithm (default: "ECDH-ES").
    pub fn alg(mut self, alg: impl Into<String>) -> Self {
        self.alg = Some(alg.into());
        self
    }

    /// Sets the content encryption algorithm (default: "A256GCM").
    pub fn enc(mut self, enc: impl Into<String>) -> Self {
        self.enc = Some(enc.into());
        self
    }

    /// Sets the key ID (kid) header parameter.
    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Builds the JWE string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is not set
    /// - The recipient key is not set
    /// - The algorithm is not supported (only "ECDH-ES" is currently supported)
    /// - Encryption fails
    pub fn build(self) -> Result<String> {
        let payload = self.payload.context("payload is required")?;
        let recipient_key = self.recipient_key.context("recipient_key is required")?;
        let alg = self.alg.unwrap_or_else(|| DEFAULT_ALG.to_string());
        let enc = self.enc.unwrap_or_else(|| DEFAULT_ENC.to_string());

        if alg != "ECDH-ES" {
            bail!("unsupported algorithm: {alg} (only ECDH-ES is supported)");
        }

        // Build JWT payload
        let mut jwt_payload = JwtPayload::new();
        if let Json::Object(map) = payload {
            for (key, value) in map {
                jwt_payload.set_claim(&key, Some(value))?;
            }
        } else {
            bail!("payload must be a JSON object");
        }

        // Build JWE header
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm(&alg);
        header.set_content_encryption(&enc);

        if let Some(kid) = &self.kid {
            header.set_key_id(kid);
        } else if let Some(kid) = recipient_key.key_id() {
            header.set_key_id(kid);
        }

        // Create encrypter and encrypt (using P-256 curve)
        let encrypter: josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter<p256::NistP256> =
            josekit::jwe::ECDH_ES.encrypter_from_jwk(&recipient_key)?;
        let jwe = encode_with_encrypter(&jwt_payload, &header, &encrypter)?;

        Ok(jwe)
    }
}

/// Finds a suitable encryption JWK from a JWKS.
///
/// This function searches for a P-256 key with `use: "enc"` that can be used
/// for encrypting the authorization response.
///
/// # Arguments
///
/// * `keys` - Iterator of JWK JSON objects from the client's JWKS
///
/// # Returns
///
/// The first suitable encryption key found, or an error if none is found.
///
/// # Example
///
/// ```ignore
/// use openid4vp::core::jwe::find_encryption_jwk;
///
/// let jwks = client_metadata.jwks()?;
/// let jwk = find_encryption_jwk(jwks.keys.iter())?;
/// ```
pub fn find_encryption_jwk<'a, I>(keys: I) -> Result<Jwk>
where
    I: Iterator<Item = &'a serde_json::Map<String, Json>>,
{
    keys.filter_map(|jwk_map| {
        let jwk_json = Json::Object(jwk_map.clone());
        let jwk_str = serde_json::to_string(&jwk_json).ok()?;
        let jwk = Jwk::from_bytes(jwk_str.as_bytes()).ok()?;
        Some(jwk)
    })
    .find(|jwk| {
        let Some(crv) = jwk.curve() else {
            tracing::warn!("JWK in keyset was missing 'crv'");
            return false;
        };
        if crv != "P-256" {
            return false;
        }
        match jwk.key_use() {
            Some(use_) => use_ == "enc",
            None => {
                tracing::warn!(
                    "JWK in keyset was missing 'use', assuming it can be used for encryption"
                );
                true
            }
        }
    })
    .context("no P-256 key with use='enc' found in JWKS")
}

/// Build a JWE-encrypted authorization response per OID4VP 1.0 spec §8.3.
///
/// This function constructs a JWE for `direct_post.jwt` response mode using:
/// - Algorithm: ECDH-ES with A256GCM (configurable via client metadata)
/// - Encryption key from client_metadata.jwks
///
/// # Arguments
///
/// * `request` - The authorization request object containing client metadata
/// * `vp_token` - The VP token to include in the response
/// * `state` - Optional state parameter to include in the response
///
/// # Returns
///
/// A JWE-encrypted `AuthorizationResponse` ready for submission.
///
/// # Spec References
///
/// - [OID4VP 1.0 §8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3)
pub fn build_encrypted_response(
    request: &crate::core::authorization_request::AuthorizationRequestObject,
    vp_token: &crate::core::response::parameters::VpToken,
    state: Option<&crate::core::authorization_request::parameters::State>,
) -> Result<crate::core::response::AuthorizationResponse> {
    use crate::core::{
        object::ParsingErrorContext,
        response::{AuthorizationResponse, JwtAuthorizationResponse},
    };

    // Build payload with vp_token and optional state
    let mut payload = serde_json::json!({
        "vp_token": vp_token
    });

    if let Some(s) = state {
        payload["state"] = serde_json::json!(s.0);
    }

    tracing::debug!("Building JWE encrypted response");

    // Get encryption key from client metadata
    let client_metadata = request
        .client_metadata()
        .context("missing client_metadata in request")?;

    let jwks = client_metadata
        .jwks()
        .parsing_error()
        .context("missing jwks in client_metadata")?;

    let keys: Vec<_> = jwks.keys.iter().collect();
    let jwk = find_encryption_jwk(keys.into_iter())?;

    // Convert JWK to JSON for the builder
    let jwk_json: Json = serde_json::to_value(&jwk).context("failed to serialize JWK")?;

    // Build JWE per OID4VP 1.0 spec §8.3
    let jwe = JweBuilder::new()
        .payload(payload)
        .recipient_key_json(&jwk_json)?
        .build()?;

    tracing::debug!("JWE response built successfully");

    Ok(AuthorizationResponse::Jwt(JwtAuthorizationResponse {
        response: jwe,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_jwk() -> Json {
        // A test P-256 public key for encryption
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "enc"
        })
    }

    #[test]
    fn jwe_builder_basic() {
        let payload = json!({
            "vp_token": { "cred1": ["presentation_data"] },
            "state": "abc123"
        });

        let jwe = JweBuilder::new()
            .payload(payload)
            .recipient_key_json(&test_jwk())
            .unwrap()
            .build()
            .unwrap();

        // JWE should have 5 parts separated by dots
        assert_eq!(jwe.split('.').count(), 5);
    }

    #[test]
    fn jwe_builder_custom_enc() {
        let payload = json!({"test": "value"});

        let jwe = JweBuilder::new()
            .payload(payload)
            .recipient_key_json(&test_jwk())
            .unwrap()
            .enc("A256GCM")
            .build()
            .unwrap();

        assert_eq!(jwe.split('.').count(), 5);
    }

    #[test]
    fn jwe_builder_missing_payload() {
        let result = JweBuilder::new()
            .recipient_key_json(&test_jwk())
            .unwrap()
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("payload"));
    }

    #[test]
    fn jwe_builder_missing_key() {
        let result = JweBuilder::new().payload(json!({"test": "value"})).build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("recipient_key"));
    }

    #[test]
    fn find_encryption_jwk_success() {
        let jwks = vec![
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "use": "sig"
            }),
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "use": "enc"
            }),
        ];

        let keys: Vec<_> = jwks.iter().filter_map(|j| j.as_object()).collect();

        let jwk = find_encryption_jwk(keys.into_iter()).unwrap();
        assert_eq!(jwk.key_use(), Some("enc"));
    }

    #[test]
    fn find_encryption_jwk_no_enc_key() {
        let jwks = vec![json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "sig"
        })];

        let keys: Vec<_> = jwks.iter().filter_map(|j| j.as_object()).collect();

        let result = find_encryption_jwk(keys.into_iter());
        assert!(result.is_err());
    }
}
