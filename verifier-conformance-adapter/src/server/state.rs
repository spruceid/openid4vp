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
                verifier::JWKs,
                wallet::{AuthorizationEndpoint, ClientIdSchemesSupported, VpFormatsSupported},
            },
            WalletMetadata,
        },
        object::UntypedObject,
    },
    utils::NonEmptyVec,
    verifier::{
        client::{Client, X509SanDnsClient},
        request_signer::P256Signer,
        session::MemoryStore,
        Verifier,
    },
};
use p256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use tracing::info;
use url::Url;
use x509_cert::{der::Decode, Certificate};

const WALLET_AUTHORIZATION_ENDPOINT: &str =
    "https://demo.certification.openid.net/test/a/my-verifier-oid4vp1/authorize";

const CACHE_DIR: &str = "verifier-conformance-adapter/.cache/certs";

/// OIDF configuration info for display
pub struct OidfConfig {
    pub x: String,
    pub y: String,
    pub d: String,
    pub x5c: String,
    pub client_id: String,
}

pub struct AppState {
    pub verifier: Verifier,
    pub wallet_metadata: WalletMetadata,
    pub public_url: Url,
    pub oidf_config: OidfConfig,
    pub encryption_key_jwk: serde_json::Value,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedCredentials {
    /// Domain this certificate was generated for
    domain: String,
    /// DER-encoded certificate (base64)
    cert_der_b64: String,
    /// PKCS#8 private key (base64)
    key_pkcs8_b64: String,
}

impl AppState {
    pub async fn new(public_url: Url, use_encrypted_response: bool) -> Result<Self> {
        let wallet_authorization_endpoint: Url = WALLET_AUTHORIZATION_ENDPOINT.parse()?;

        let domain = public_url
            .host_str()
            .context("Public URL must have a host")?
            .to_string();

        info!("Initializing verifier for domain: {}", domain);

        let (signing_key, cert, cert_der) = get_or_generate_cert(&domain)?;

        let oidf_config = build_oidf_config(&signing_key, &cert_der, &domain);

        let signer = Arc::new(P256Signer::new(signing_key)?);

        let client = Arc::new(X509SanDnsClient::new(vec![cert], signer)?);

        info!("Created X509SanDnsClient with client_id: {}", client.id().0);

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
        credential_query.set_meta(Some(meta));

        DcqlQuery::new(NonEmptyVec::new(credential_query))
    }
}

/// Get cached certificate or generate a new one for the given domain
fn get_or_generate_cert(domain: &str) -> Result<(SigningKey, Certificate, Vec<u8>)> {
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
    let (signing_key, cert, key_pkcs8) = generate_cert(domain)?;

    // Get cert DER for return
    use x509_cert::der::Encode;
    let cert_der = cert.to_der()?;

    // Cache it
    if let Err(e) = save_cert_to_cache(&cache_file, domain, &cert, &key_pkcs8) {
        tracing::warn!("Failed to cache certificate: {}", e);
    }

    Ok((signing_key, cert, cert_der))
}

/// Load certificate from cache file
fn load_cached_cert(
    cache_file: &PathBuf,
    expected_domain: &str,
) -> Result<(SigningKey, Certificate, Vec<u8>)> {
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

    info!("Successfully loaded cached certificate");
    Ok((signing_key, cert, cert_der))
}

fn save_cert_to_cache(
    cache_file: &PathBuf,
    domain: &str,
    cert: &Certificate,
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
        key_pkcs8_b64: BASE64_STANDARD.encode(key_pkcs8),
    };

    let content = serde_json::to_string_pretty(&cached)?;
    fs::write(cache_file, content)?;

    info!("Cached certificate to {:?}", cache_file);
    Ok(())
}

fn generate_cert(domain: &str) -> Result<(SigningKey, Certificate, Vec<u8>)> {
    use p256::pkcs8::DecodePrivateKey;

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("Failed to generate key pair")?;

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "OID4VP Verifier");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Conformance Test");
    params.distinguished_name.push(DnType::CountryName, "BR");

    params.subject_alt_names = vec![SanType::DnsName(domain.to_string().try_into()?)];

    let cert_rcgen = params
        .self_signed(&key_pair)
        .context("Failed to generate self-signed certificate")?;

    let cert_der = cert_rcgen.der().to_vec();

    let cert = Certificate::from_der(&cert_der).context("Failed to parse generated certificate")?;

    let key_pkcs8 = key_pair.serialize_der();

    let signing_key = SigningKey::from_pkcs8_der(&key_pkcs8)
        .context("Failed to create signing key from generated key")?;

    info!("Generated self-signed certificate for domain: {}", domain);

    Ok((signing_key, cert, key_pkcs8))
}

fn build_oidf_config(signing_key: &SigningKey, cert_der: &[u8], domain: &str) -> OidfConfig {
    let point = signing_key.verifying_key().to_encoded_point(false);

    OidfConfig {
        x: BASE64_URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        y: BASE64_URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        d: BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        x5c: BASE64_STANDARD.encode(cert_der),
        client_id: domain.to_string(),
    }
}

/// Generate an encryption key pair for JARM (direct_post.jwt)
fn generate_encryption_key() -> Result<(
    serde_json::Value,
    serde_json::Map<String, serde_json::Value>,
)> {
    use rand::rngs::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(false);

    let x = BASE64_URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = BASE64_URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let d = BASE64_URL_SAFE_NO_PAD.encode(secret_key.to_bytes());

    let mut public_jwk = serde_json::Map::new();
    public_jwk.insert("kty".to_string(), serde_json::json!("EC"));
    public_jwk.insert("crv".to_string(), serde_json::json!("P-256"));
    public_jwk.insert("x".to_string(), serde_json::json!(x));
    public_jwk.insert("y".to_string(), serde_json::json!(y));
    public_jwk.insert("use".to_string(), serde_json::json!("enc"));
    public_jwk.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    public_jwk.insert("kid".to_string(), serde_json::json!("enc-key-1"));

    let private_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "d": d,
        "use": "enc",
        "kid": "enc-key-1"
    });

    Ok((private_jwk, public_jwk))
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

    metadata.insert(ClientIdSchemesSupported(vec![ClientIdScheme(
        ClientIdScheme::X509_SAN_DNS.to_string(),
    )]));

    Ok(metadata)
}
