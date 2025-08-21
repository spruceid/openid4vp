use anyhow::Context;
use isomdl::{
    definitions::{
        helpers::{ByteStr, NonEmptyMap, NonEmptyVec},
        x509::trust_anchor::TrustAnchorRegistry,
        CoseKey,
    },
    presentation::authentication::ResponseAuthenticationOutcome,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

// #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
// pub enum SessionState {
//     Initiated {
//         annex_c: annexc::InitiatedSessionState,
//         annex_d: annexd::InitiatedSessionState,
//     },
//     Complete(ResponseAuthenticationOutcome),
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptionInfo(String, EncryptionParameters);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptionParameters {
    nonce: ByteStr,
    recipient_public_key: CoseKey,
}

#[derive(Clone, Deserialize)]
pub struct DCAPIInitiate {
    pub namespaces: NonEmptyMap<String, NonEmptyVec<String>>,
    // Not using Url, mainly to avoid an extraneous `/` during serialization.
    pub origin: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiateResponse {
    pub requests: Vec<DCAPIRequest>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "protocol")]
pub enum DCAPIRequest {
    // #[serde(rename = "org-iso-mdoc")]
    // AnnexC { data: annexc::InitiateResponse },
    #[serde(rename = "openid4vp")]
    AnnexD { data: DCAPIRequestAnnexD },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DCAPIRequestAnnexD {
    pub request: String,
}

// #[derive(Deserialize, Serialize)]
// #[serde(rename_all = "camelCase", tag = "protocol")]
// pub enum DCAPIResponse {
//     #[serde(rename = "org-iso-mdoc")]
//     AnnexC { data: annexc::DCAPIResponseData },
//     #[serde(rename = "openid4vp")]
//     AnnexD { data: annexd::DCAPIResponseData },
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedResponse(String, EncryptedResponseData);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedResponseData {
    enc: ByteStr,
    cipher_text: ByteStr,
}
