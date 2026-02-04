use anyhow::{Context, Result};
use ciborium::Value as Cbor;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The fixed identifier string for OpenID4VPHandover (redirect flow).
pub const HANDOVER_TYPE_IDENTIFIER: &str = "OpenID4VPHandover";

/// The fixed identifier string for OpenID4VPDCAPIHandover (Digital Credentials API).
pub const DC_API_HANDOVER_TYPE_IDENTIFIER: &str = "OpenID4VPDCAPIHandover";

/// OID4VPHandover structure for OID4VP 1.0 spec §B.2.6.1 (Invocation via Redirects).
///
/// This is the handover structure used in the SessionTranscript for device authentication
/// when presenting mdoc credentials via OID4VP.
///
/// # Spec Reference
///
/// - [OID4VP 1.0 §B.2.6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handover {
    /// SHA-256 hash of CBOR-encoded OpenID4VPHandoverInfo
    handover_info_hash: Vec<u8>,
}

impl Handover {
    /// Creates a new Handover from the authorization request parameters.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The client_id from the authorization request, including prefix if applicable
    ///   (e.g., "x509_san_dns:example.com")
    /// * `nonce` - The nonce from the authorization request
    /// * `jwk_thumbprint` - The SHA-256 JWK Thumbprint of the verifier's encryption key (32 bytes),
    ///   or None if the response is not encrypted
    /// * `response_uri` - The response_uri or redirect_uri from the authorization request
    pub fn new(
        client_id: &str,
        nonce: &str,
        jwk_thumbprint: Option<&[u8]>,
        response_uri: &str,
    ) -> Result<Self> {
        // Build CBOR array OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
        let jwk_thumbprint_cbor = match jwk_thumbprint {
            Some(bytes) => Cbor::Bytes(bytes.to_vec()),
            None => Cbor::Null,
        };

        let handover_info = Cbor::Array(vec![
            Cbor::Text(client_id.to_string()),
            Cbor::Text(nonce.to_string()),
            jwk_thumbprint_cbor,
            Cbor::Text(response_uri.to_string()),
        ]);

        // Encode OpenID4VPHandoverInfo to CBOR bytes
        let handover_info_bytes =
            cbor_to_bytes(&handover_info).context("failed to encode OpenID4VPHandoverInfo CBOR")?;

        // Calculate SHA-256 hash of the CBOR bytes
        let handover_info_hash = Sha256::digest(&handover_info_bytes).to_vec();

        Ok(Self { handover_info_hash })
    }

    /// Returns the OpenID4VPHandoverInfoHash (SHA-256 hash).
    pub fn handover_info_hash(&self) -> &[u8] {
        &self.handover_info_hash
    }

    /// Serializes the Handover to CBOR bytes.
    ///
    /// The output is a CBOR array: `["OpenID4VPHandover", bstr(32)]`
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let cbor_value = Cbor::Array(vec![
            Cbor::Text(HANDOVER_TYPE_IDENTIFIER.to_string()),
            Cbor::Bytes(self.handover_info_hash.clone()),
        ]);
        cbor_to_bytes(&cbor_value).context("failed to serialize Handover to CBOR")
    }
}

impl Serialize for Handover {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as a CBOR array ["OpenID4VPHandover", bstr]
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(HANDOVER_TYPE_IDENTIFIER)?;
        tuple.serialize_element(serde_bytes::Bytes::new(&self.handover_info_hash))?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for Handover {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct HandoverVisitor;

        impl<'de> serde::de::Visitor<'de> for HandoverVisitor {
            type Value = Handover;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 2-element array [\"OpenID4VPHandover\", bstr]")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let type_id: String = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                if type_id != HANDOVER_TYPE_IDENTIFIER {
                    return Err(serde::de::Error::custom(format!(
                        "expected '{}', got '{}'",
                        HANDOVER_TYPE_IDENTIFIER, type_id
                    )));
                }

                let handover_info_hash: serde_bytes::ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                Ok(Handover {
                    handover_info_hash: handover_info_hash.into_vec(),
                })
            }
        }

        deserializer.deserialize_tuple(2, HandoverVisitor)
    }
}

/// OID4VPDCAPIHandover structure for OID4VP 1.0 spec §B.2.6.2 (Digital Credentials API).
///
/// This is the handover structure used in the SessionTranscript for device authentication
/// when presenting mdoc credentials via the Digital Credentials API.
///
/// # Spec Reference
///
/// - [OID4VP 1.0 §B.2.6.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcApiHandover {
    /// SHA-256 hash of CBOR-encoded OpenID4VPDCAPIHandoverInfo
    handover_info_hash: Vec<u8>,
}

impl DcApiHandover {
    /// Creates a new DcApiHandover from the authorization request parameters.
    ///
    /// # Arguments
    ///
    /// * `origin` - The Origin of the request. MUST NOT be prefixed with "origin:".
    /// * `nonce` - The nonce from the authorization request
    /// * `jwk_thumbprint` - The SHA-256 JWK Thumbprint of the verifier's encryption key (32 bytes),
    ///   or None if the response is not encrypted (response mode `dc_api`)
    pub fn new(origin: &str, nonce: &str, jwk_thumbprint: Option<&[u8]>) -> Result<Self> {
        // Build CBOR array OpenID4VPDCAPIHandoverInfo = [origin, nonce, jwkThumbprint]
        let jwk_thumbprint_cbor = match jwk_thumbprint {
            Some(bytes) => Cbor::Bytes(bytes.to_vec()),
            None => Cbor::Null,
        };

        let handover_info = Cbor::Array(vec![
            Cbor::Text(origin.to_string()),
            Cbor::Text(nonce.to_string()),
            jwk_thumbprint_cbor,
        ]);

        // Encode OpenID4VPDCAPIHandoverInfo to CBOR bytes
        let handover_info_bytes = cbor_to_bytes(&handover_info)
            .context("failed to encode OpenID4VPDCAPIHandoverInfo CBOR")?;

        // Calculate SHA-256 hash of the CBOR bytes
        let handover_info_hash = Sha256::digest(&handover_info_bytes).to_vec();

        Ok(Self { handover_info_hash })
    }

    /// Returns the OpenID4VPDCAPIHandoverInfoHash (SHA-256 hash).
    pub fn handover_info_hash(&self) -> &[u8] {
        &self.handover_info_hash
    }

    /// Serializes the DcApiHandover to CBOR bytes.
    ///
    /// The output is a CBOR array: `["OpenID4VPDCAPIHandover", bstr(32)]`
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let cbor_value = Cbor::Array(vec![
            Cbor::Text(DC_API_HANDOVER_TYPE_IDENTIFIER.to_string()),
            Cbor::Bytes(self.handover_info_hash.clone()),
        ]);
        cbor_to_bytes(&cbor_value).context("failed to serialize DcApiHandover to CBOR")
    }
}

impl Serialize for DcApiHandover {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(DC_API_HANDOVER_TYPE_IDENTIFIER)?;
        tuple.serialize_element(serde_bytes::Bytes::new(&self.handover_info_hash))?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for DcApiHandover {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DcApiHandoverVisitor;

        impl<'de> serde::de::Visitor<'de> for DcApiHandoverVisitor {
            type Value = DcApiHandover;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 2-element array [\"OpenID4VPDCAPIHandover\", bstr]")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let type_id: String = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                if type_id != DC_API_HANDOVER_TYPE_IDENTIFIER {
                    return Err(serde::de::Error::custom(format!(
                        "expected '{}', got '{}'",
                        DC_API_HANDOVER_TYPE_IDENTIFIER, type_id
                    )));
                }

                let handover_info_hash: serde_bytes::ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                Ok(DcApiHandover {
                    handover_info_hash: handover_info_hash.into_vec(),
                })
            }
        }

        deserializer.deserialize_tuple(2, DcApiHandoverVisitor)
    }
}

/// SessionTranscript structure for ISO 18013-7 Annex B.
///
/// The SessionTranscript is used as associated data for device authentication
/// when presenting mdoc credentials.
///
/// # Spec Reference
///
/// - ISO/IEC 18013-7 Annex B.4.1
#[derive(Debug, Clone)]
pub struct SessionTranscript<H = Handover> {
    handover: H,
}

impl<H> SessionTranscript<H> {
    /// Creates a new SessionTranscript with the given handover.
    ///
    /// The first two elements are always `null` for OID4VP as per ISO 18013-7 Annex B.
    pub fn new(handover: H) -> Self {
        Self { handover }
    }

    /// Returns a reference to the handover.
    pub fn handover(&self) -> &H {
        &self.handover
    }
}

impl<H: Serialize + DeserializeOwned> SessionTranscript<H> {
    /// Serializes the SessionTranscript to CBOR bytes.
    ///
    /// These bytes are used as the external payload for device authentication
    /// (COSE_Sign1 signature).
    ///
    /// The output is: `[null, null, Handover]`
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        // Serialize handover to CBOR value first
        let mut handover_bytes = Vec::new();
        ciborium::into_writer(&self.handover, &mut handover_bytes)
            .context("failed to serialize handover")?;
        let handover_cbor: Cbor =
            ciborium::from_reader(&handover_bytes[..]).context("failed to parse handover CBOR")?;

        // Build the array [null, null, handover]
        let transcript = Cbor::Array(vec![Cbor::Null, Cbor::Null, handover_cbor]);

        cbor_to_bytes(&transcript).context("failed to serialize SessionTranscript to CBOR")
    }
}

impl<H: PartialEq> PartialEq for SessionTranscript<H> {
    fn eq(&self, other: &Self) -> bool {
        self.handover == other.handover
    }
}

impl<H: Eq> Eq for SessionTranscript<H> {}

impl<H: Serialize> Serialize for SessionTranscript<H> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(3)?;
        tuple.serialize_element(&())?; // null
        tuple.serialize_element(&())?; // null
        tuple.serialize_element(&self.handover)?;
        tuple.end()
    }
}

impl<'de, H: Deserialize<'de>> Deserialize<'de> for SessionTranscript<H> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SessionTranscriptVisitor<H>(std::marker::PhantomData<H>);

        impl<'de, H: Deserialize<'de>> serde::de::Visitor<'de> for SessionTranscriptVisitor<H> {
            type Value = SessionTranscript<H>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 3-element array [null, null, Handover]")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // Skip first two nulls
                let _: Option<()> = seq.next_element()?;
                let _: Option<()> = seq.next_element()?;
                let handover: H = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                Ok(SessionTranscript { handover })
            }
        }

        deserializer.deserialize_tuple(3, SessionTranscriptVisitor(std::marker::PhantomData))
    }
}

/// Helper function to serialize a value to CBOR bytes.
fn cbor_to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// Get the JWK thumbprint of the verifier's encryption key from an authorization request.
///
/// Per OID4VP 1.0 §B.2.6.1, when the response is encrypted (e.g., `direct_post.jwt`),
/// the JWK thumbprint of the encryption key must be included in the HandoverInfo.
///
/// # Arguments
///
/// * `request` - The authorization request object containing client metadata
///
/// # Returns
///
/// The SHA-256 JWK thumbprint (32 bytes) of the first suitable encryption key found,
/// or `None` if no encryption key is available.
pub fn get_encryption_jwk_thumbprint(
    request: &crate::core::authorization_request::AuthorizationRequestObject,
) -> Option<[u8; 32]> {
    use crate::core::object::ParsingErrorContext;

    request
        .client_metadata()
        .ok()
        .and_then(|meta| meta.jwks().parsing_error().ok())
        .and_then(|jwks| {
            jwks.keys.iter().find_map(|key_map| {
                let jwk_json = serde_json::Value::Object(key_map.clone());
                let is_enc = key_map
                    .get("use")
                    .and_then(|v| v.as_str())
                    .map(|u| u == "enc")
                    .unwrap_or(true);
                if is_enc {
                    compute_jwk_thumbprint(&jwk_json).ok()
                } else {
                    None
                }
            })
        })
}

/// Compute the SHA-256 JWK Thumbprint according to RFC 7638.
///
/// For EC keys (P-256), the thumbprint is computed from the JSON object:
/// `{"crv":"P-256","kty":"EC","x":"<base64url>","y":"<base64url>"}`
///
/// The keys must be in lexicographic order as per RFC 7638 §3.
///
/// # Arguments
///
/// * `jwk` - A JSON object representing the JWK
///
/// # Returns
///
/// A 32-byte SHA-256 hash of the canonical JWK representation.
///
/// # Spec Reference
///
/// - [RFC 7638 - JSON Web Key (JWK) Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)
pub fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<[u8; 32]> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .context("JWK missing 'kty'")?;

    // Build canonical JSON with required members in lexicographic order
    let canonical_json = match kty {
        "EC" => {
            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .context("EC JWK missing 'crv'")?;
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .context("EC JWK missing 'x'")?;
            let y = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .context("EC JWK missing 'y'")?;

            // RFC 7638 §3.2: For EC keys, use crv, kty, x, y in lexicographic order
            format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y)
        }
        "RSA" => {
            let e = jwk
                .get("e")
                .and_then(|v| v.as_str())
                .context("RSA JWK missing 'e'")?;
            let n = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .context("RSA JWK missing 'n'")?;

            // RFC 7638 §3.2: For RSA keys, use e, kty, n in lexicographic order
            format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
        }
        _ => anyhow::bail!("unsupported key type for JWK thumbprint: {}", kty),
    };

    let hash = Sha256::digest(canonical_json.as_bytes());
    Ok(hash.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn handover_construction_with_thumbprint() {
        let jwk_thumbprint = [0u8; 32]; // Mock thumbprint
        let handover = Handover::new(
            "x509_san_dns:verifier.example.com",
            "nonce123",
            Some(&jwk_thumbprint),
            "https://verifier.example.com/callback",
        )
        .unwrap();

        // Verify hash length (SHA-256 = 32 bytes)
        assert_eq!(handover.handover_info_hash().len(), 32);
    }

    #[test]
    fn handover_construction_without_thumbprint() {
        let handover = Handover::new(
            "x509_san_dns:verifier.example.com",
            "nonce123",
            None,
            "https://verifier.example.com/callback",
        )
        .unwrap();

        // Verify hash length (SHA-256 = 32 bytes)
        assert_eq!(handover.handover_info_hash().len(), 32);
    }

    #[test]
    fn handover_deterministic() {
        let thumbprint = [1u8; 32];

        let h1 = Handover::new("client", "nonce", Some(&thumbprint), "uri").unwrap();
        let h2 = Handover::new("client", "nonce", Some(&thumbprint), "uri").unwrap();

        assert_eq!(h1.handover_info_hash(), h2.handover_info_hash());
    }

    #[test]
    fn handover_different_inputs_different_hashes() {
        let thumbprint = [1u8; 32];

        let h1 = Handover::new("client1", "nonce", Some(&thumbprint), "uri").unwrap();
        let h2 = Handover::new("client2", "nonce", Some(&thumbprint), "uri").unwrap();

        assert_ne!(h1.handover_info_hash(), h2.handover_info_hash());
    }

    #[test]
    fn session_transcript_structure() {
        let handover = Handover::new("client", "nonce", None, "uri").unwrap();
        let transcript = SessionTranscript::new(handover.clone());

        assert_eq!(transcript.handover(), &handover);
    }

    #[test]
    fn session_transcript_to_cbor() {
        let handover = Handover::new("client", "nonce", None, "uri").unwrap();
        let transcript = SessionTranscript::new(handover);

        let bytes = transcript.to_cbor_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Verify it's a valid CBOR array starting with 0x83 (3-element array)
        assert_eq!(bytes[0], 0x83);
    }

    #[test]
    fn handover_cbor_roundtrip() {
        let handover = Handover::new("client", "nonce", None, "uri").unwrap();
        let bytes = handover.to_cbor_bytes().unwrap();

        let decoded: Handover = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(handover, decoded);
    }

    #[test]
    fn handover_cbor_structure() {
        let handover = Handover::new("client", "nonce", None, "uri").unwrap();
        let bytes = handover.to_cbor_bytes().unwrap();

        // Should be a 2-element array: ["OpenID4VPHandover", bstr(32)]
        assert_eq!(bytes[0], 0x82); // CBOR array of 2 elements
    }

    #[test]
    fn session_transcript_cbor_roundtrip() {
        let handover = Handover::new("client", "nonce", None, "uri").unwrap();
        let transcript = SessionTranscript::new(handover);

        let bytes = transcript.to_cbor_bytes().unwrap();
        let decoded: SessionTranscript<Handover> = ciborium::from_reader(&bytes[..]).unwrap();

        assert_eq!(transcript, decoded);
    }

    #[test]
    fn compute_ec_jwk_thumbprint() {
        // Test vector from RFC 7638 example
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "1"
        });

        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();

        // Thumbprint should be 32 bytes
        assert_eq!(thumbprint.len(), 32);
    }

    #[test]
    fn jwk_thumbprint_ignores_extra_fields() {
        // Two JWKs with different extra fields should have the same thumbprint
        let jwk1 = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "test_x",
            "y": "test_y",
            "use": "enc"
        });

        let jwk2 = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "test_x",
            "y": "test_y",
            "kid": "key-1",
            "alg": "ECDH-ES"
        });

        let t1 = compute_jwk_thumbprint(&jwk1).unwrap();
        let t2 = compute_jwk_thumbprint(&jwk2).unwrap();

        assert_eq!(t1, t2);
    }

    // =========================================================================
    // DC API Handover Tests
    // =========================================================================

    #[test]
    fn dc_api_handover_construction_with_thumbprint() {
        let jwk_thumbprint = [0u8; 32];
        let handover =
            DcApiHandover::new("https://example.com", "nonce123", Some(&jwk_thumbprint)).unwrap();

        assert_eq!(handover.handover_info_hash().len(), 32);
    }

    #[test]
    fn dc_api_handover_construction_without_thumbprint() {
        let handover = DcApiHandover::new("https://example.com", "nonce123", None).unwrap();

        assert_eq!(handover.handover_info_hash().len(), 32);
    }

    #[test]
    fn dc_api_handover_deterministic() {
        let thumbprint = [1u8; 32];

        let h1 = DcApiHandover::new("https://example.com", "nonce", Some(&thumbprint)).unwrap();
        let h2 = DcApiHandover::new("https://example.com", "nonce", Some(&thumbprint)).unwrap();

        assert_eq!(h1.handover_info_hash(), h2.handover_info_hash());
    }

    #[test]
    fn dc_api_handover_cbor_structure() {
        let handover = DcApiHandover::new("https://example.com", "nonce", None).unwrap();
        let bytes = handover.to_cbor_bytes().unwrap();

        // Should be a 2-element array: ["OpenID4VPDCAPIHandover", bstr(32)]
        assert_eq!(bytes[0], 0x82); // CBOR array of 2 elements
    }

    #[test]
    fn dc_api_handover_cbor_roundtrip() {
        let thumbprint = [42u8; 32];
        let handover =
            DcApiHandover::new("https://example.com", "nonce", Some(&thumbprint)).unwrap();
        let bytes = handover.to_cbor_bytes().unwrap();

        let decoded: DcApiHandover = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(handover, decoded);
    }

    #[test]
    fn dc_api_session_transcript_to_cbor() {
        let handover = DcApiHandover::new("https://example.com", "nonce", None).unwrap();
        let transcript = SessionTranscript::new(handover);

        let bytes = transcript.to_cbor_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Verify it's a valid CBOR array starting with 0x83 (3-element array)
        assert_eq!(bytes[0], 0x83);
    }

    // =========================================================================
    // Spec Vector Tests - OID4VP v1.0 §B.2.6.1 and §B.2.6.2
    // =========================================================================

    #[test]
    fn spec_vector_redirect_handover_info_hash() {
        // Test vector from OID4VP v1.0 spec §B.2.6.1
        // Input values from the spec example:
        // - client_id: "x509_san_dns:example.com"
        // - nonce: "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
        // - jwkThumbprint: computed from spec JWK
        // - responseUri: "https://example.com/response"
        //
        // Expected OpenID4VPHandover hex:
        // 82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494c
        // efdd9d95240d254b046b11b68013722aad38ac

        // First, compute the JWK thumbprint from the spec example JWK
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "1"
        });
        let jwk_thumbprint = compute_jwk_thumbprint(&jwk).unwrap();

        let handover = Handover::new(
            "x509_san_dns:example.com",
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            Some(&jwk_thumbprint),
            "https://example.com/response",
        )
        .unwrap();

        // The expected hash from spec (second element of OpenID4VPHandover):
        // 048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac
        let expected_hash =
            hex::decode("048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac")
                .unwrap();

        assert_eq!(
            handover.handover_info_hash(),
            expected_hash.as_slice(),
            "Handover info hash should match spec vector"
        );
    }

    #[test]
    fn spec_vector_redirect_handover_cbor() {
        // Test the full CBOR encoding matches the spec
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "1"
        });
        let jwk_thumbprint = compute_jwk_thumbprint(&jwk).unwrap();

        let handover = Handover::new(
            "x509_san_dns:example.com",
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            Some(&jwk_thumbprint),
            "https://example.com/response",
        )
        .unwrap();

        let cbor_bytes = handover.to_cbor_bytes().unwrap();

        // Expected from spec:
        // 82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494c
        // efdd9d95240d254b046b11b68013722aad38ac
        let expected_cbor = hex::decode(
            "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
        ).unwrap();

        assert_eq!(
            cbor_bytes, expected_cbor,
            "Handover CBOR should match spec vector"
        );
    }

    #[test]
    fn spec_vector_redirect_session_transcript_cbor() {
        // Test the full SessionTranscript CBOR encoding matches the spec
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "1"
        });
        let jwk_thumbprint = compute_jwk_thumbprint(&jwk).unwrap();

        let handover = Handover::new(
            "x509_san_dns:example.com",
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            Some(&jwk_thumbprint),
            "https://example.com/response",
        )
        .unwrap();

        let transcript = SessionTranscript::new(handover);
        let cbor_bytes = transcript.to_cbor_bytes().unwrap();

        // Expected from spec:
        // 83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e
        // ed494cefdd9d95240d254b046b11b68013722aad38ac
        let expected_cbor = hex::decode(
            "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
        ).unwrap();

        assert_eq!(
            cbor_bytes, expected_cbor,
            "SessionTranscript CBOR should match spec vector"
        );
    }

    #[test]
    fn spec_vector_dc_api_handover_info_hash() {
        // Test vector from OID4VP v1.0 spec §B.2.6.2
        // Input values from the spec example:
        // - origin: "https://example.com"
        // - nonce: "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
        // - jwkThumbprint: computed from spec JWK
        //
        // Expected OpenID4VPDCAPIHandover hex:
        // 82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f97
        // 62c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a

        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "1"
        });
        let jwk_thumbprint = compute_jwk_thumbprint(&jwk).unwrap();

        let handover = DcApiHandover::new(
            "https://example.com",
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            Some(&jwk_thumbprint),
        )
        .unwrap();

        // The expected hash from spec (second element of OpenID4VPDCAPIHandover):
        // fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a
        let expected_hash =
            hex::decode("fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a")
                .unwrap();

        assert_eq!(
            handover.handover_info_hash(),
            expected_hash.as_slice(),
            "DC API Handover info hash should match spec vector"
        );
    }

    #[test]
    fn spec_vector_dc_api_handover_cbor() {
        // Test the full CBOR encoding matches the spec
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "1"
        });
        let jwk_thumbprint = compute_jwk_thumbprint(&jwk).unwrap();

        let handover = DcApiHandover::new(
            "https://example.com",
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            Some(&jwk_thumbprint),
        )
        .unwrap();

        let cbor_bytes = handover.to_cbor_bytes().unwrap();

        // Expected from spec:
        // 82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f97
        // 62c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a
        let expected_cbor = hex::decode(
            "82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
        ).unwrap();

        assert_eq!(
            cbor_bytes, expected_cbor,
            "DC API Handover CBOR should match spec vector"
        );
    }
}
