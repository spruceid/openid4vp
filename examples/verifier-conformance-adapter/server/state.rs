use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::prelude::*;
use openid4vp::{
    core::{
        authorization_request::parameters::{
            ClientIdScheme, ClientMetadata, ResponseMode, ResponseType,
        },
        credential_format::{ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload},
        dcql_query::{DcqlCredentialQuery, DcqlQuery},
        metadata::{
            parameters::{
                verifier::{EncryptedResponseEncValuesSupported, JWKs},
                wallet::{AuthorizationEndpoint, ClientIdPrefixesSupported, VpFormatsSupported},
            },
            WalletMetadata,
        },
        object::UntypedObject,
    },
    utils::NonEmptyVec,
    verifier::{
        client::{Client, X509HashClient, X509SanDnsClient},
        request_signer::P256Signer,
        session::MemoryStore,
        Verifier,
    },
};
use p256::{ecdsa::SigningKey, SecretKey};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use ssi::jwk::JWK;
use tracing::info;
use url::Url;
use x509_cert::{der::Decode, Certificate};

const WALLET_AUTHORIZATION_ENDPOINT: &str =
    "https://demo.certification.openid.net/test/a/my-verifier-oid4vp1/authorize";

const CACHE_DIR: &str = "examples/verifier-conformance-adapter/.cache/certs";

/// OIDF configuration info for display
pub struct OidfConfig {
    pub x: String,
    pub y: String,
    pub d: String,
    pub x5c: String,
    pub client_id: String,
    /// PEM of the root CA that signed the leaf. Paste this into the conformance
    /// suite's "Request Object Trust Anchor" field so it can validate the x5c
    /// chain of the signed request object.
    pub trust_anchor_pem: String,
}

pub struct AppState {
    pub verifier: Verifier,
    pub wallet_metadata: WalletMetadata,
    pub public_url: Url,
    pub oidf_config: OidfConfig,
    pub encryption_key_jwk: JWK,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedCredentials {
    /// Domain this certificate was generated for
    domain: String,
    /// DER-encoded leaf certificate (base64)
    cert_der_b64: String,
    /// DER-encoded root CA certificate (base64). Not sent in x5c, but used as
    /// the trust anchor for the request object's certificate chain.
    ca_cert_der_b64: String,
    /// PKCS#8 private key of the leaf (base64)
    key_pkcs8_b64: String,
}

impl AppState {
    pub async fn new(
        public_url: Url,
        use_encrypted_response: bool,
        client_id_prefix: &str,
    ) -> Result<Self> {
        let wallet_authorization_endpoint: Url = WALLET_AUTHORIZATION_ENDPOINT.parse()?;

        let domain = public_url
            .host_str()
            .context("Public URL must have a host")?
            .to_string();

        info!("Initializing verifier for domain: {}", domain);

        let (signing_key, cert, cert_der, ca_der) = get_or_generate_cert(&domain)?;

        let oidf_config = build_oidf_config(&signing_key, &cert_der, &ca_der, &domain);

        let signer = Arc::new(P256Signer::new(signing_key)?);

        let client: Arc<dyn Client + Send + Sync> = match client_id_prefix {
            "x509_hash" => Arc::new(X509HashClient::new(vec![cert], signer)?),
            "x509_san_dns" => Arc::new(X509SanDnsClient::new(vec![cert], signer)?),
            other => anyhow::bail!("unsupported client_id_prefix: {other}"),
        };

        info!(
            "Created client ({}) with client_id: {}",
            client_id_prefix,
            client.id().0
        );

        let session_store = Arc::new(MemoryStore::default());

        let submission_endpoint = public_url.join("response")?;

        let request_uri_base = public_url.join("request")?;

        info!("Submission endpoint: {}", submission_endpoint);
        info!("Request URI base: {}", request_uri_base);

        let (encryption_key_jwk, public_jwk) = generate_encryption_key()?;
        info!("Generated encryption key for JARM responses");

        let client_metadata = build_client_metadata(use_encrypted_response.then_some(&public_jwk));

        let response_mode = if use_encrypted_response {
            info!("Using encrypted response mode (direct_post.jwt)");
            ResponseMode::DirectPostJwt
        } else {
            info!("Using plain response mode (direct_post)");
            ResponseMode::DirectPost
        };

        let verifier = Verifier::builder()
            .with_client(client)
            .with_session_store(session_store)
            .with_submission_endpoint(submission_endpoint)
            .by_reference(request_uri_base)
            .with_default_request_parameter(ResponseType::VpToken)
            .with_default_request_parameter(response_mode)
            .with_default_request_parameter(client_metadata)
            // The request object `aud` (OID4VP §5.8) is defaulted by the library
            // to "https://self-issued.me/v2" for static Wallet metadata.
            .build()
            .await?;

        let wallet_metadata = create_wallet_metadata(wallet_authorization_endpoint)?;

        Ok(Self {
            verifier,
            wallet_metadata,
            public_url,
            oidf_config,
            encryption_key_jwk,
        })
    }

    pub fn build_dcql_query() -> DcqlQuery {
        // Request an SD-JWT VC with the EUDI PID vct
        // The conformance test expects vct of "urn:eudi:pid:1"
        let mut credential_query = DcqlCredentialQuery::new(
            "pid".to_string(),
            ClaimFormatDesignation::Other("dc+sd-jwt".to_string()),
        );

        // Set meta with vct_values
        let mut meta = serde_json::Map::new();
        meta.insert(
            "vct_values".to_string(),
            serde_json::json!(["urn:eudi:pid:1"]),
        );
        credential_query.set_meta(meta);

        DcqlQuery::new(NonEmptyVec::new(credential_query))
    }
}

/// Get cached certificate material or generate new material for the given domain.
fn get_or_generate_cert(domain: &str) -> Result<(SigningKey, Certificate, Vec<u8>, Vec<u8>)> {
    let cache_dir = PathBuf::from(CACHE_DIR);
    let cache_file = cache_dir.join(format!("{}.json", domain.replace('.', "_")));

    // Try to load from cache
    if cache_file.exists() {
        info!("Loading cached certificate for domain: {}", domain);
        if let Ok(cached) = load_cached_cert(&cache_file, domain) {
            return Ok(cached);
        }
        info!("Cache invalid or expired, regenerating certificate");
    }

    // Generate new certificate
    info!("Generating new certificate for domain: {}", domain);
    let (signing_key, cert, ca_cert, key_pkcs8) = generate_cert(domain)?;

    // Get cert DER for return
    use x509_cert::der::Encode;
    let cert_der = cert.to_der()?;
    let ca_der = ca_cert.to_der()?;

    // Cache it
    if let Err(e) = save_cert_to_cache(&cache_file, domain, &cert, &ca_cert, &key_pkcs8) {
        tracing::warn!("Failed to cache certificate: {}", e);
    }

    Ok((signing_key, cert, cert_der, ca_der))
}

/// Load certificate material from cache file
fn load_cached_cert(
    cache_file: &PathBuf,
    expected_domain: &str,
) -> Result<(SigningKey, Certificate, Vec<u8>, Vec<u8>)> {
    let content = fs::read_to_string(cache_file)?;
    let cached: CachedCredentials = serde_json::from_str(&content)?;

    if cached.domain != expected_domain {
        anyhow::bail!("Cached domain mismatch");
    }

    use p256::pkcs8::DecodePrivateKey;
    let key_pkcs8 = BASE64_STANDARD.decode(&cached.key_pkcs8_b64)?;
    let signing_key =
        SigningKey::from_pkcs8_der(&key_pkcs8).context("Failed to decode cached private key")?;

    let cert_der = BASE64_STANDARD.decode(&cached.cert_der_b64)?;
    let cert = Certificate::from_der(&cert_der)?;

    let ca_der = BASE64_STANDARD.decode(&cached.ca_cert_der_b64)?;

    info!("Successfully loaded cached certificate");
    Ok((signing_key, cert, cert_der, ca_der))
}

fn save_cert_to_cache(
    cache_file: &PathBuf,
    domain: &str,
    cert: &Certificate,
    ca_cert: &Certificate,
    key_pkcs8: &[u8],
) -> Result<()> {
    use base64::prelude::*;
    use x509_cert::der::Encode;

    if let Some(parent) = cache_file.parent() {
        fs::create_dir_all(parent)?;
    }

    let cached = CachedCredentials {
        domain: domain.to_string(),
        cert_der_b64: BASE64_STANDARD.encode(cert.to_der()?),
        ca_cert_der_b64: BASE64_STANDARD.encode(ca_cert.to_der()?),
        key_pkcs8_b64: BASE64_STANDARD.encode(key_pkcs8),
    };

    let content = serde_json::to_string_pretty(&cached)?;
    fs::write(cache_file, content)?;

    info!("Cached certificate to {:?}", cache_file);
    Ok(())
}

/// Generate a leaf certificate and its issuing CA for the given domain.
///
/// Returns the leaf signing key, the leaf certificate, the CA certificate, and
/// the leaf's PKCS#8 private key.
fn generate_cert(domain: &str) -> Result<(SigningKey, Certificate, Certificate, Vec<u8>)> {
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, IsCa};

    // 1. Self-signed CA used only to sign the leaf (acts as the trust anchor).
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("Failed to generate CA key pair")?;

    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OID4VP Conformance Test CA");
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "Conformance Test");
    ca_params.distinguished_name.push(DnType::CountryName, "BR");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let ca_cert_rcgen = ca_params
        .self_signed(&ca_key)
        .context("Failed to generate CA certificate")?;

    // 2. Leaf certificate signed by the CA (not self-signed).
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("Failed to generate leaf key pair")?;

    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "OID4VP Verifier");
    leaf_params
        .distinguished_name
        .push(DnType::OrganizationName, "Conformance Test");
    leaf_params
        .distinguished_name
        .push(DnType::CountryName, "BR");
    leaf_params.subject_alt_names = vec![SanType::DnsName(domain.to_string().try_into()?)];

    let leaf_cert_rcgen = leaf_params
        .signed_by(&leaf_key, &ca_cert_rcgen, &ca_key)
        .context("Failed to generate leaf certificate")?;

    let leaf_der = leaf_cert_rcgen.der().to_vec();
    let ca_der = ca_cert_rcgen.der().to_vec();

    let leaf_cert =
        Certificate::from_der(&leaf_der).context("Failed to parse generated leaf certificate")?;
    let ca_cert =
        Certificate::from_der(&ca_der).context("Failed to parse generated CA certificate")?;

    let key_pkcs8 = leaf_key.serialize_der();

    let signing_key = SigningKey::from_pkcs8_der(&key_pkcs8)
        .context("Failed to create signing key from leaf key")?;

    info!(
        "Generated CA-signed leaf certificate for domain: {}",
        domain
    );

    Ok((signing_key, leaf_cert, ca_cert, key_pkcs8))
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(der);
    let mut body = String::new();
    for chunk in b64.as_bytes().chunks(64) {
        body.push_str(std::str::from_utf8(chunk).unwrap());
        body.push('\n');
    }
    format!("-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n")
}

fn build_oidf_config(
    signing_key: &SigningKey,
    cert_der: &[u8],
    ca_der: &[u8],
    domain: &str,
) -> OidfConfig {
    let point = signing_key.verifying_key().to_encoded_point(false);

    OidfConfig {
        x: BASE64_URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        y: BASE64_URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        d: BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        x5c: BASE64_STANDARD.encode(cert_der),
        client_id: domain.to_string(),
        trust_anchor_pem: der_to_pem(ca_der),
    }
}

/// Generate an encryption key pair for JARM (direct_post.jwt)
///
/// Returns (private_jwk, public_jwk_map) where:
/// - private_jwk is a typed JWK for decryption
/// - public_jwk_map is a JSON Map for the JWKs metadata (includes "alg" for ECDH-ES)
fn generate_encryption_key() -> Result<(JWK, serde_json::Map<String, serde_json::Value>)> {
    use rand::rngs::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();

    let mut private_jwk: JWK = serde_json::from_str(&secret_key.to_jwk_string())
        .context("Failed to parse private key JWK")?;

    // Add required fields for JARM encryption
    private_jwk.public_key_use = Some("enc".into());
    private_jwk.key_id = Some("enc-key-1".into());

    let mut public_jwk_map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&public_key.to_jwk_string())
            .context("Failed to parse public key JWK")?;
    public_jwk_map.insert("use".to_string(), serde_json::json!("enc"));
    public_jwk_map.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    public_jwk_map.insert("kid".to_string(), serde_json::json!("enc-key-1"));

    Ok((private_jwk, public_jwk_map))
}

/// Build client_metadata with vp_formats_supported for the authorization request
/// client_metadata must include vp_formats_supported
/// For direct_post.jwt, we also include jwks with the encryption key
fn build_client_metadata(
    encryption_public_jwk: Option<&serde_json::Map<String, serde_json::Value>>,
) -> ClientMetadata {
    let mut vp_formats = ClaimFormatMap::new();
    vp_formats.insert(
        ClaimFormatDesignation::Other("dc+sd-jwt".to_string()),
        ClaimFormatPayload::Other(serde_json::json!({})),
    );

    let mut inner = UntypedObject::default();
    inner.insert(VpFormatsSupported(vp_formats));

    if let Some(public_jwk) = encryption_public_jwk {
        let jwks = JWKs {
            keys: vec![public_jwk.clone()],
        };
        inner.insert(jwks);

        // HAIP Section 5: Verifiers MUST list both A128GCM and A256GCM in
        // `encrypted_response_enc_values_supported`.
        inner.insert(EncryptedResponseEncValuesSupported(vec![
            "A128GCM".to_string(),
            "A256GCM".to_string(),
        ]));
    }

    ClientMetadata(inner)
}

fn create_wallet_metadata(authorization_endpoint: Url) -> Result<WalletMetadata> {
    let mut vp_formats = ClaimFormatMap::new();
    vp_formats.insert(
        ClaimFormatDesignation::Other("dc+sd-jwt".to_string()),
        ClaimFormatPayload::Other(serde_json::json!({})),
    );

    let mut metadata = WalletMetadata::new(
        AuthorizationEndpoint(authorization_endpoint),
        VpFormatsSupported(vp_formats),
        None,
    );

    metadata.insert(ClientIdPrefixesSupported(vec![
        ClientIdScheme(ClientIdScheme::X509_SAN_DNS.to_string()),
        ClientIdScheme(ClientIdScheme::X509_HASH.to_string()),
    ]));

    Ok(metadata)
}
