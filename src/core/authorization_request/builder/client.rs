use anyhow::Result;
use base64::prelude::*;
use serde_json::{json, Value as Json};
use x509_cert::{der::Encode, Certificate};

use crate::core::authorization_request::{
    builder::request_signer::RequestSigner,
    parameters::{ClientId, ClientIdScheme},
    AuthorizationRequestObject,
};

#[derive(Debug, Clone)]
pub(crate) enum Client<S: RequestSigner> {
    Did {
        id: ClientId,
        vm: String,
        signer: S,
    },
    X509SanUri {
        id: ClientId,
        x5c: Vec<Certificate>,
        signer: S,
    },
}

impl<S: RequestSigner> Client<S> {
    pub fn id(&self) -> &ClientId {
        match self {
            Client::Did { id, .. } => id,
            Client::X509SanUri { id, .. } => id,
        }
    }

    pub fn scheme(&self) -> &ClientIdScheme {
        match self {
            Client::Did { .. } => &ClientIdScheme::Did,
            Client::X509SanUri { .. } => &ClientIdScheme::X509SanUri,
        }
    }

    pub async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String> {
        match self {
            Client::Did {
                vm: kid, signer, ..
            } => {
                let algorithm = signer.alg();
                let header = json!({
                    "alg": algorithm,
                    "kid": kid,
                    "typ": "JWT"
                });
                make_jwt(header, body, signer).await
            }
            Client::X509SanUri { x5c, signer, .. } => {
                let algorithm = signer.alg();
                let x5c: Vec<String> = x5c
                    .iter()
                    .map(|x509| x509.to_der())
                    .map(|der| Ok(BASE64_STANDARD.encode(der?)))
                    .collect::<Result<_>>()?;
                let header = json!({
                    "alg": algorithm,
                    "x5c": x5c,
                    "typ": "JWT"
                });
                make_jwt(header, body, signer).await
            }
        }
    }
}

async fn make_jwt<S: RequestSigner>(
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
