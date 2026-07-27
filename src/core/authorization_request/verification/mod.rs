use crate::{
    core::{
        jwe::find_encryption_jwk,
        metadata::parameters::{
            verifier::{EncryptedResponseEncValuesSupported, JWKs},
            wallet::{
                AuthorizationEncryptionAlgValuesSupported,
                AuthorizationEncryptionEncValuesSupported, ClientIdPrefixesSupported,
            },
        },
        object::ParsingErrorContext,
    },
    wallet::Wallet,
};
use anyhow::{bail, Error, Result};
use async_trait::async_trait;

use super::{
    parameters::{ClientIdScheme, ClientMetadata, ResponseMode},
    AuthorizationRequestObject,
};

pub mod did;
pub mod verifier;
pub mod x509;
pub mod x509_hash;
pub mod x509_san;

/// Verifies Authorization Request Objects based on Client Identifier Prefix.
///
/// Per OID4VP v1.0 Section 5.9, the Client Identifier Prefix determines how the
/// Wallet validates the Verifier's identity and the Authorization Request.
#[allow(unused_variables)]
#[async_trait]
pub trait RequestVerifier {
    /// Performs verification when the Client Identifier Prefix is `decentralized_identifier`.
    /// Per Section 5.9.3, the request MUST be signed with a private key associated with the DID.
    async fn decentralized_identifier(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'decentralized_identifier' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `openid_federation`.
    async fn openid_federation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'openid_federation' client verification not implemented")
    }

    /// Performs verification for pre-registered clients.
    ///
    /// Per Section 5.9.2, if no `:` is present in the client_id, or if an unrecognized
    /// prefix is present, the client is treated as pre-registered. The Verifier metadata
    /// is obtained using RFC7591 or through out-of-band mechanisms.
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'pre-registered' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `redirect_uri`.
    /// Per Section 5.9.3, requests using this prefix cannot be signed.
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'redirect_uri' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `verifier_attestation`.
    async fn verifier_attestation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'verifier_attestation' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `x509_san_dns`.
    /// Per Section 5.9.3, the request MUST be signed with the private key corresponding
    /// to the public key in the leaf X.509 certificate.
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'x509_san_dns' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `x509_hash`.
    /// Per Section 5.9.3, the request MUST be signed with the private key corresponding
    /// to the public key in the leaf X.509 certificate.
    async fn x509_hash(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'x509_hash' client verification not implemented")
    }

    /// Performs verification for custom/extension Client Identifier Prefixes.
    ///
    /// Per Section 5.9.3, other specifications can define further Client Identifier Prefixes.
    /// Per Section 5.9.2, if the prefix is not recognized, the Wallet can either treat the
    /// client as pre-registered or refuse the request.
    async fn other(
        &self,
        prefix: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'{prefix}' client verification not implemented")
    }
}

pub(crate) async fn verify_request<W: Wallet + ?Sized>(
    wallet: &W,
    decoded_request: &AuthorizationRequestObject,
    jwt: Option<String>,
) -> Result<()> {
    validate_request_against_metadata(wallet, decoded_request).await?;

    // Get the Client Identifier Prefix from client_id
    // Per Section 5.9.2: If no ':' is present, treat as pre-registered
    let client_id_prefix = decoded_request.client_id_scheme();

    match client_id_prefix.map(|prefix| prefix.0.as_str()) {
        Some(ClientIdScheme::DECENTRALIZED_IDENTIFIER) => {
            wallet
                .decentralized_identifier(decoded_request, jwt)
                .await?
        }
        Some(ClientIdScheme::OPENID_FEDERATION) => {
            wallet.openid_federation(decoded_request, jwt).await?
        }
        Some(ClientIdScheme::REDIRECT_URI) => wallet.redirect_uri(decoded_request, jwt).await?,
        Some(ClientIdScheme::VERIFIER_ATTESTATION) => {
            wallet.verifier_attestation(decoded_request, jwt).await?
        }
        Some(ClientIdScheme::X509_SAN_DNS) => wallet.x509_san_dns(decoded_request, jwt).await?,
        Some(ClientIdScheme::X509_HASH) => wallet.x509_hash(decoded_request, jwt).await?,
        Some(ClientIdScheme::ORIGIN) => {
            bail!("'origin' Client Identifier Prefix is reserved for Digital Credentials API and MUST NOT be accepted")
        }
        Some(prefix) => {
            // Per Section 5.9.2: If prefix is not recognized, the Wallet can treat
            // the Client Identifier as referring to a pre-registered client or refuse.
            // Here we delegate to the `other` method to let the implementation decide.
            wallet.other(prefix, decoded_request, jwt).await?
        }
        None => {
            // Per Section 5.9.2: If no ':' is present, treat as pre-registered client
            wallet.preregistered(decoded_request, jwt).await?
        }
    };

    Ok(())
}

pub(crate) async fn validate_request_against_metadata<W: Wallet + ?Sized>(
    wallet: &W,
    request: &AuthorizationRequestObject,
) -> Result<(), Error> {
    let wallet_metadata = wallet.metadata();

    // Validate that the wallet supports the Client Identifier Prefix (if present)
    // Per Section 5.9.2: If no ':' is present, treat as pre-registered (no prefix to validate)
    if let Some(prefix) = request.client_id_scheme() {
        if !wallet_metadata
            .get_or_default::<ClientIdPrefixesSupported>()?
            .0
            .contains(prefix)
        {
            bail!(
                "wallet does not support Client Identifier Prefix '{}'",
                prefix.0
            )
        }
    }

    let client_metadata = ClientMetadata::resolve(request)?.0;

    let response_mode = request.get::<ResponseMode>().parsing_error()?;

    // Validate encrypted response parameters per OID4VP v1.0 Section 8.3
    // For JARM (encrypted responses), the verifier provides:
    // - `alg` in each JWK within `jwks` (MUST be present)
    // - `enc` via `encrypted_response_enc_values_supported` (default: A128GCM)
    if response_mode.is_jarm()? {
        // Get JWKs from client_metadata - required for encrypted responses
        let jwks = client_metadata
            .get::<JWKs>()
            .ok_or_else(|| anyhow::anyhow!("'jwks' is required for encrypted responses"))?
            .map_err(|e| anyhow::anyhow!("failed to parse 'jwks': {e}"))?;

        // Collect the `alg` values of the candidate encryption keys per OID4VP v1.0 Section 8.3.
        let jwk_info = find_encryption_jwk(jwks.keys.iter()).map_err(|e| {
            anyhow::anyhow!("no usable encryption key in jwks per OID4VP v1.0 Section 8.3: {e}")
        })?;

        // Validate the selected key's alg against wallet supported values
        if let Some(supported_algs) =
            wallet_metadata.get::<AuthorizationEncryptionAlgValuesSupported>()
        {
            let supported = supported_algs?;
            if !supported.0.contains(&jwk_info.alg) {
                bail!(
                    "encryption algorithm '{}' in jwks is not supported by the wallet ({:?})",
                    jwk_info.alg,
                    supported.0
                )
            }
        }

        // Get enc values from encrypted_response_enc_values_supported (default: A128GCM)
        let enc_values = client_metadata
            .get::<EncryptedResponseEncValuesSupported>()
            .transpose()?
            .unwrap_or_default();

        // Validate enc against wallet supported values
        if let Some(supported_encs) =
            wallet_metadata.get::<AuthorizationEncryptionEncValuesSupported>()
        {
            let supported = supported_encs?;
            let has_supported_enc = enc_values.0.iter().any(|enc| supported.0.contains(enc));
            if !has_supported_enc {
                bail!(
                    "none of the content encryption algorithms ({:?}) are supported by the wallet ({:?})",
                    enc_values.0,
                    supported.0
                )
            }
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod test_util {
    use base64::prelude::*;

    use crate::core::metadata::WalletMetadata;
    use x509_cert::{
        der::{Decode, Encode},
        Certificate,
    };

    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{DistinguishedName, KeyUsagePurpose::KeyCertSign, SignatureAlgorithm};
    use serde_json::json;
    pub enum SigningKey {
        P256(p256::ecdsa::SigningKey),
        P384(p384::ecdsa::SigningKey),
    }

    impl SigningKey {
        /// Parse a PKCS#8 DER key, trying P-256 first then falling back to P-384.
        pub fn from_pkcs8_der(der: &[u8]) -> anyhow::Result<Self> {
            if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
                Ok(SigningKey::P256(key))
            } else {
                Ok(SigningKey::P384(p384::ecdsa::SigningKey::from_pkcs8_der(
                    der,
                )?))
            }
        }

        /// Sign a message, returning the raw (fixed-width) signature bytes.
        pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
            use p256::ecdsa::signature::Signer as _;
            match self {
                SigningKey::P256(key) => {
                    let sig: p256::ecdsa::Signature = key.sign(msg);
                    sig.to_bytes().to_vec()
                }
                SigningKey::P384(key) => {
                    let sig: p384::ecdsa::Signature = key.sign(msg);
                    sig.to_bytes().to_vec()
                }
            }
        }
    }

    pub fn to_x509(rcgen_cert: &rcgen::Certificate) -> Certificate {
        Certificate::from_der(&rcgen_cert.der().to_vec()).unwrap()
    }

    /// Given algorithms for each certificate, issue a chain that links 2+ certificates
    pub fn issued_chain(algs: &[&'static SignatureAlgorithm]) -> (Vec<Certificate>, SigningKey) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        assert!(algs.len() >= 2, "issued_chain needs at least root + leaf");

        let root_key = KeyPair::generate_for(&algs.first().unwrap()).unwrap();
        let mut root_params = CertificateParams::new(vec!["root.example".into()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyCertSign];
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let mut chain = vec![to_x509(&root_cert)]; // root ends up last after inserts

        let mut issuer = root_cert;
        let mut issuer_key = root_key;

        for (i, alg) in algs[1..].iter().enumerate() {
            let is_leaf = i == algs.len() - 2;

            let key = KeyPair::generate_for(alg).unwrap();
            let mut params = CertificateParams::new(vec![if is_leaf {
                "leaf.example"
            } else {
                "inter.example"
            }
            .into()])
            .unwrap();
            let mut dn = DistinguishedName::new();
            dn.push(
                DnType::CommonName,
                if is_leaf {
                    "leaf.example".to_string()
                } else {
                    format!("inter_{}.example", i)
                },
            );
            params.distinguished_name = dn;
            if !is_leaf {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.key_usages = vec![KeyCertSign];
            }
            let cert = params.signed_by(&key, &issuer, &issuer_key).unwrap();

            chain.insert(0, to_x509(&cert));
            issuer = cert;
            issuer_key = key;
        }

        let key = SigningKey::from_pkcs8_der(&issuer_key.serialize_der()).unwrap();
        (chain, key)
    }

    pub fn wallet() -> WalletMetadata {
        WalletMetadata::openid4vp_scheme_static() // supports ES256
    }

    /// Builds a signed JWT; x5c or alg can be invalid to test error paths
    pub fn make_jwt(header: serde_json::Value, key: &SigningKey) -> String {
        let body = json!({ "age": "30" });
        let h = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let b: String = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).unwrap());
        let signing_input = format!("{h}.{b}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", BASE64_URL_SAFE_NO_PAD.encode(sig))
    }

    /// Builds header containing specified alg and cert chain
    pub fn x5c_header(alg: &str, chain: &[&Certificate]) -> serde_json::Value {
        let x5c: Vec<String> = chain
            .iter()
            .map(|c| BASE64_STANDARD.encode(c.to_der().unwrap()))
            .collect();
        json!({ "alg": alg, "x5c": x5c })
    }
}
