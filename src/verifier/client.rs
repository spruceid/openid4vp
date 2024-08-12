use std::{fmt::Debug, str::FromStr, sync::Arc};

use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;
use base64::prelude::*;
use serde_json::{json, Value as Json};
use ssi::{
    dids::{DIDBuf, DIDResolver, DIDURLBuf, VerificationMethodDIDResolver, DIDURL},
    jwk::JWKResolver,
    verification_methods::{
        GenericVerificationMethod, InvalidVerificationMethod, MaybeJwkVerificationMethod,
        VerificationMethodSet,
    },
    JWK,
};
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

    fn scheme(&self) -> &ClientIdScheme;

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String>;
}

/// A [Client] with the `did` Client Identifier.
#[derive(Debug, Clone)]
pub struct DIDClient {
    id: ClientId,
    vm: String,
    signer: Arc<dyn RequestSigner + Send + Sync>,
}

impl DIDClient {
    pub async fn new(
        vm: String,
        signer: Arc<dyn RequestSigner + Send + Sync>,
        resolver: &VerificationMethodDIDResolver<
            impl DIDResolver,
            impl MaybeJwkVerificationMethod
                + VerificationMethodSet
                + TryFrom<GenericVerificationMethod, Error = InvalidVerificationMethod>,
        >,
    ) -> Result<Self> {
        let (id, _f) = vm.rsplit_once('#').context(format!(
            "expected a DID verification method, received '{vm}'"
        ))?;

        let jwk = resolver
            .fetch_public_jwk(Some(&vm))
            .await
            .context("unable to resolve key from verification method")?;

        if &*jwk != signer.jwk() {
            bail!(
                "verification method resolved from DID document did not match public key of signer"
            )
        }

        Ok(Self {
            id: ClientId(id.to_string()),
            vm,
            signer,
        })
    }
}

/// A [Client] with the `x509_san_dns` or `x509_san_uri` Client Identifier.
#[derive(Debug, Clone)]
pub struct X509SanClient {
    id: ClientId,
    x5c: Vec<Certificate>,
    signer: Arc<dyn RequestSigner + Send + Sync>,
    variant: X509SanVariant,
}

impl X509SanClient {
    pub fn new(
        x5c: Vec<Certificate>,
        signer: Arc<dyn RequestSigner + Send + Sync>,
        variant: X509SanVariant,
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
            .filter_map(|general_name| match (general_name, variant) {
                (GeneralName::DnsName(uri), X509SanVariant::Dns) => Some(uri.to_string()),
                (gn, X509SanVariant::Dns) => {
                    debug!("found non-DNS SAN: {gn:?}");
                    None
                }
                (GeneralName::UniformResourceIdentifier(uri), X509SanVariant::Uri) => {
                    Some(uri.to_string())
                }
                (gn, X509SanVariant::Uri) => {
                    debug!("found non-URI SAN: {gn:?}");
                    None
                }
            })
            .next()
        {
            san
        } else {
            bail!("x509 certificate does not contain Subject Alternative Name");
        };
        Ok(X509SanClient {
            id: ClientId(id),
            x5c,
            signer,
            variant,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum X509SanVariant {
    Uri,
    Dns,
}

#[async_trait]
impl Client for DIDClient {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn scheme(&self) -> &ClientIdScheme {
        &ClientIdScheme::Did
    }

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String> {
        let algorithm = self.signer.alg();
        let header = json!({
            "alg": algorithm,
            "kid": self.vm,
            "typ": "JWT"
        });
        make_jwt(header, body, self.signer.as_ref()).await
    }
}

#[async_trait]
impl Client for X509SanClient {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn scheme(&self) -> &ClientIdScheme {
        match self.variant {
            X509SanVariant::Dns => &ClientIdScheme::X509SanDns,
            X509SanVariant::Uri => &ClientIdScheme::X509SanUri,
        }
    }

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String> {
        let algorithm = self.signer.alg();
        let x5c: Vec<String> = self
            .x5c
            .iter()
            .map(|x509| x509.to_der())
            .map(|der| Ok(BASE64_STANDARD.encode(der?)))
            .collect::<Result<_>>()?;
        let header = json!({
            "alg": algorithm,
            "x5c": x5c,
            "typ": "JWT"
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
