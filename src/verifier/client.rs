use std::{fmt::Debug, sync::Arc};

use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;
use base64::prelude::*;
use serde_json::{json, Value as Json};
use ssi::jwk::JWKResolver;

use tracing::debug;
use x509_cert::{
    der::Encode,
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::core::authorization_request::{
    parameters::{ClientId, ClientIdScheme},
    AuthorizationRequestObject,
};

use super::request_signer::RequestSigner;

#[async_trait]
pub trait Client: Debug {
    fn id(&self) -> &ClientId;

    fn scheme(&self) -> ClientIdScheme;

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String>;
}

/// A [Client](crate::verifier::client::Client) with the `decentralized_identifier` Client Identifier prefix.
/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3
#[derive(Debug, Clone)]
pub struct DIDClient {
    id: ClientId,
    vm: String,
    signer: Arc<dyn RequestSigner<Error = anyhow::Error> + Send + Sync>,
}

impl DIDClient {
    pub async fn new(
        vm: String,
        signer: Arc<dyn RequestSigner<Error = anyhow::Error> + Send + Sync>,
        resolver: impl JWKResolver,
    ) -> Result<Self> {
        let (id, _f) = vm.rsplit_once('#').context(format!(
            "expected a DID verification method, received '{vm}'"
        ))?;

        let jwk = resolver
            .fetch_public_jwk(Some(&vm))
            .await
            .context("unable to resolve key from verification method")?;

        if *jwk != signer.jwk().context("signer did not have a JWK")? {
            bail!(
                "verification method resolved from DID document did not match public key of signer"
            )
        }

        // client_id for decentralized_identifier scheme must be prefixed with "decentralized_identifier:"
        // See https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3
        let prefixed_id = format!("{}:{}", ClientIdScheme::DECENTRALIZED_IDENTIFIER, id);
        Ok(Self {
            id: ClientId(prefixed_id),
            vm,
            signer,
        })
    }
}

/// A [Client](crate::verifier::client::Client) with the `x509_san_dns` Client Identifier.
/// See: Section 5.9.3
#[derive(Debug, Clone)]
pub struct X509SanDnsClient {
    id: ClientId,
    x5c: Vec<Certificate>,
    signer: Arc<dyn RequestSigner<Error = anyhow::Error> + Send + Sync>,
}

impl X509SanDnsClient {
    pub fn new(
        x5c: Vec<Certificate>,
        signer: Arc<dyn RequestSigner<Error = anyhow::Error> + Send + Sync>,
    ) -> Result<Self> {
        let leaf = &x5c[0];
        let id = if let Some(san) = leaf
            .tbs_certificate
            .filter::<SubjectAltName>()
            .filter_map(|r| match r {
                Ok((_crit, san)) => Some(san.0.into_iter()),
                Err(e) => {
                    debug!("unable to parse SubjectAlternativeName from DER: {e}");
                    None
                }
            })
            .flatten()
            .filter_map(|general_name| match general_name {
                GeneralName::DnsName(dns) => Some(dns.to_string()),
                gn => {
                    debug!("found non-DNS SAN: {gn:?}");
                    None
                }
            })
            .next()
        {
            san
        } else {
            bail!("x509 certificate does not contain DNS Subject Alternative Name");
        };
        // client_id for x509_san_dns scheme must be prefixed with "x509_san_dns:"
        // See https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3
        let prefixed_id = format!("{}:{}", ClientIdScheme::X509_SAN_DNS, id);
        Ok(X509SanDnsClient {
            id: ClientId(prefixed_id),
            x5c,
            signer,
        })
    }
}

#[async_trait]
impl Client for DIDClient {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn scheme(&self) -> ClientIdScheme {
        ClientIdScheme(ClientIdScheme::DECENTRALIZED_IDENTIFIER.to_string())
    }

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String> {
        let algorithm = self
            .signer
            .alg()
            .context("failed to retrieve signing algorithm")?;
        let header = json!({
            "alg": algorithm,
            "kid": self.vm,
            "typ": "oauth-authz-req+jwt"
        });
        make_jwt(header, body, self.signer.as_ref()).await
    }
}

#[async_trait]
impl Client for X509SanDnsClient {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn scheme(&self) -> ClientIdScheme {
        ClientIdScheme(ClientIdScheme::X509_SAN_DNS.to_string())
    }

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String> {
        let algorithm = self
            .signer
            .alg()
            .context("failed to retrieve signing algorithm")?;
        let x5c: Vec<String> = self
            .x5c
            .iter()
            .map(|x509| x509.to_der())
            .map(|der| Ok(BASE64_STANDARD.encode(der?)))
            .collect::<Result<_>>()?;
        let header = json!({
            "alg": algorithm,
            "x5c": x5c,
            "typ": "oauth-authz-req+jwt"
        });
        make_jwt(header, body, self.signer.as_ref()).await
    }
}

async fn make_jwt<S: RequestSigner + ?Sized>(
    header: Json,
    body: &AuthorizationRequestObject,
    signer: &S,
) -> Result<String> {
    let header_b64: String =
        serde_json::to_vec(&header).map(|b| BASE64_URL_SAFE_NO_PAD.encode(b))?;
    let body_b64 = serde_json::to_vec(body).map(|b| BASE64_URL_SAFE_NO_PAD.encode(b))?;
    let payload = [header_b64.as_bytes(), b".", body_b64.as_bytes()].concat();
    let signature = signer.sign(&payload).await;
    let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{header_b64}.{body_b64}.{signature_b64}"))
}
