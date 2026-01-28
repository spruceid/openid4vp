use anyhow::{bail, Context, Result};
use josekit::{
    jwe::JweHeader,
    jwk::Jwk,
    jwt::{encode_with_encrypter, JwtPayload},
};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Default content encryption algorithm per OID4VP v1.0 §8.3.
pub const DEFAULT_ENC: &str = "A128GCM";

/// Information about an encryption JWK including the required `alg` parameter.
///
/// Per OID4VP v1.0 §8.3, the `alg` parameter MUST be present in JWKs used for encryption,
/// and the JWE `alg` MUST be equal to the `alg` value of the chosen JWK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionJwkInfo {
    /// The JWK for encryption.
    pub jwk: Jwk,
    /// The algorithm from the JWK (required per spec).
    pub alg: String,
    /// The key ID from the JWK (optional).
    pub kid: Option<String>,
}

/// Builder for creating JWE-encrypted authorization responses.
///
/// Per OID4VP v1.0 §8.3:
/// - The `alg` parameter MUST be present in the JWK and the JWE `alg` MUST equal it
/// - The `enc` is obtained from `encrypted_response_enc_values_supported` (default: A128GCM)
/// - If the JWK has a `kid`, the JWE MUST include it in the header
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

    /// Sets the key agreement algorithm.
    ///
    /// Per OID4VP v1.0 §8.3, this MUST be equal to the `alg` value of the chosen JWK.
    pub fn alg(mut self, alg: impl Into<String>) -> Self {
        self.alg = Some(alg.into());
        self
    }

    /// Sets the content encryption algorithm (default: "A128GCM").
    ///
    /// Per OID4VP v1.0 §8.3, this is obtained from `encrypted_response_enc_values_supported`.
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
    /// - The algorithm is not set (required per OID4VP v1.0 §8.3)
    /// - The algorithm is not supported (only "ECDH-ES" is currently supported)
    /// - Encryption fails
    pub fn build(self) -> Result<String> {
        let payload = self.payload.context("payload is required")?;
        let recipient_key = self.recipient_key.context("recipient_key is required")?;
        let alg = self
            .alg
            .context("alg is required (must match the JWK's alg per OID4VP v1.0 §8.3)")?;
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
/// Per OID4VP v1.0 §8.3, the Wallet selects a public key based on `kty`, `use`, `alg`,
/// and other JWK parameters. The `alg` parameter MUST be present in the JWKs.
///
/// # Arguments
///
/// * `keys` - Iterator of JWK JSON objects from the client's JWKS
///
/// # Returns
///
/// An `EncryptionJwkInfo` containing the JWK and its `alg`, or an error if no suitable key is found.
///
/// # Example
///
/// ```ignore
/// use openid4vp::core::jwe::find_encryption_jwk;
///
/// let jwks = client_metadata.jwks()?;
/// let jwk_info = find_encryption_jwk(jwks.keys.iter())?;
/// // jwk_info.alg contains the algorithm to use
/// ```
pub fn find_encryption_jwk<'a, I>(keys: I) -> Result<EncryptionJwkInfo>
where
    I: Iterator<Item = &'a serde_json::Map<String, Json>>,
{
    for jwk_map in keys {
        // Check for required `alg` parameter per OID4VP v1.0 §8.3
        let Some(alg) = jwk_map.get("alg").and_then(|v| v.as_str()) else {
            tracing::debug!("JWK missing required 'alg' parameter, skipping");
            continue;
        };

        // Currently only support ECDH-ES
        if alg != "ECDH-ES" {
            tracing::debug!("JWK has unsupported alg '{alg}', skipping");
            continue;
        }

        // Check curve - currently only P-256 supported
        let Some(crv) = jwk_map.get("crv").and_then(|v| v.as_str()) else {
            tracing::debug!("JWK missing 'crv' parameter, skipping");
            continue;
        };
        if crv != "P-256" {
            tracing::debug!("JWK has unsupported curve '{crv}', skipping");
            continue;
        }

        // Check use - should be "enc" for encryption
        match jwk_map.get("use").and_then(|v| v.as_str()) {
            Some("enc") => {}
            Some(other) => {
                tracing::debug!("JWK has use='{other}', not suitable for encryption");
                continue;
            }
            None => {
                tracing::warn!(
                    "JWK missing 'use' parameter, assuming it can be used for encryption"
                );
            }
        }

        // Parse the JWK
        let jwk_json = Json::Object(jwk_map.clone());
        let jwk_str = serde_json::to_string(&jwk_json).context("failed to serialize JWK")?;
        let jwk = Jwk::from_bytes(jwk_str.as_bytes()).context("failed to parse JWK")?;

        let kid = jwk_map
            .get("kid")
            .and_then(|v| v.as_str())
            .map(String::from);

        return Ok(EncryptionJwkInfo {
            jwk,
            alg: alg.to_string(),
            kid,
        });
    }

    bail!("no suitable encryption key found in JWKS (requires P-256 key with alg='ECDH-ES' and use='enc')")
}

/// Build a JWE-encrypted authorization response per OID4VP 1.0 spec §8.3.
///
/// This function constructs a JWE for `direct_post.jwt` response mode using:
/// - Algorithm (`alg`): From the selected JWK (MUST match per §8.3)
/// - Content encryption (`enc`): From `encrypted_response_enc_values_supported` (default: A128GCM)
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
        authorization_request::parameters::ClientMetadata,
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

    // Get client metadata
    let client_metadata = ClientMetadata::resolve(request)?;

    // Get encryption key from client metadata jwks
    let jwks = client_metadata
        .jwks()
        .parsing_error()
        .context("missing jwks in client_metadata")?;

    let keys: Vec<_> = jwks.keys.iter().collect();
    let jwk_info = find_encryption_jwk(keys.into_iter())?;

    tracing::debug!(
        "Selected encryption key: alg={}, kid={:?}",
        jwk_info.alg,
        jwk_info.kid
    );

    // Get enc from encrypted_response_enc_values_supported (default: A128GCM per §8.3)
    let enc_values = client_metadata.encrypted_response_enc_values_supported()?;
    let enc = enc_values
        .0
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_ENC.to_string());

    tracing::debug!("Using content encryption algorithm: {enc}");

    // Convert JWK to JSON for the builder
    let jwk_json: Json = serde_json::to_value(&jwk_info.jwk).context("failed to serialize JWK")?;

    // Build JWE per OID4VP 1.0 spec §8.3
    // - alg MUST equal the alg value of the chosen JWK
    // - kid MUST be included if present in the JWK
    let mut builder = JweBuilder::new()
        .payload(payload)
        .recipient_key_json(&jwk_json)?
        .alg(&jwk_info.alg)
        .enc(&enc);

    if let Some(kid) = &jwk_info.kid {
        builder = builder.kid(kid);
    }

    let jwe = builder.build()?;

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
        // A test P-256 public key for encryption per OID4VP v1.0 §8.3
        // Note: `alg` is required per spec
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "enc",
            "alg": "ECDH-ES"
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
            .alg("ECDH-ES")
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
            .alg("ECDH-ES")
            .enc("A256GCM")
            .build()
            .unwrap();

        assert_eq!(jwe.split('.').count(), 5);
    }

    #[test]
    fn jwe_builder_default_enc_is_a128gcm() {
        // Per OID4VP v1.0 §8.3, default enc is A128GCM
        assert_eq!(DEFAULT_ENC, "A128GCM");
    }

    #[test]
    fn jwe_builder_missing_payload() {
        let result = JweBuilder::new()
            .recipient_key_json(&test_jwk())
            .unwrap()
            .alg("ECDH-ES")
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("payload"));
    }

    #[test]
    fn jwe_builder_missing_key() {
        let result = JweBuilder::new()
            .payload(json!({"test": "value"}))
            .alg("ECDH-ES")
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("recipient_key"));
    }

    #[test]
    fn jwe_builder_missing_alg() {
        // Per OID4VP v1.0 §8.3, alg is required (must match JWK's alg)
        let result = JweBuilder::new()
            .payload(json!({"test": "value"}))
            .recipient_key_json(&test_jwk())
            .unwrap()
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alg"));
    }

    #[test]
    fn find_encryption_jwk_success() {
        let jwks = vec![
            // Signing key (should be skipped)
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "use": "sig",
                "alg": "ES256"
            }),
            // Encryption key (should be selected)
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "use": "enc",
                "alg": "ECDH-ES",
                "kid": "enc-key-1"
            }),
        ];

        let keys: Vec<_> = jwks.iter().filter_map(|j| j.as_object()).collect();

        let jwk_info = find_encryption_jwk(keys.into_iter()).unwrap();
        assert_eq!(jwk_info.alg, "ECDH-ES");
        assert_eq!(jwk_info.kid, Some("enc-key-1".to_string()));
        assert_eq!(jwk_info.jwk.key_use(), Some("enc"));
    }

    #[test]
    fn find_encryption_jwk_no_enc_key() {
        let jwks = vec![json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "sig",
            "alg": "ES256"
        })];

        let keys: Vec<_> = jwks.iter().filter_map(|j| j.as_object()).collect();

        let result = find_encryption_jwk(keys.into_iter());
        assert!(result.is_err());
    }

    #[test]
    fn find_encryption_jwk_missing_alg() {
        // Per OID4VP v1.0 §8.3, alg MUST be present in JWKs
        let jwks = vec![json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "enc"
            // Missing alg!
        })];

        let keys: Vec<_> = jwks.iter().filter_map(|j| j.as_object()).collect();

        let result = find_encryption_jwk(keys.into_iter());
        assert!(result.is_err());
    }
}
