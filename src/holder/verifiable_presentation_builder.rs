use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use ssi_claims::vc::{v1::VerifiableCredential, v2::syntax::VERIFIABLE_CREDENTIAL_TYPE};
use ssi_dids::{DIDURLBuf, DIDURL};

pub const VERIFIABLE_PRESENTATION_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";

// NOTE: This may make more sense to be moved to ssi_claims lib.
pub const VERIFIABLE_PRESENTATION_TYPE: &str = "VerifiablePresentation";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifiablePresentationBuilder {
    /// The issuer of the presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>, // TODO: Should this be a DIDURLBuf or IRI/URI type?
    /// The Json Web Token ID of the presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
    /// The audience of the presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>, // TODO: Should this be a DIDURLBuf?
    /// The issuance date of the presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    /// The expiration date of the presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    /// The nonce of the presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    /// The verifiable presentation format.
    #[serde(skip_serializing_if = "Option::is_none")]
    vp: Option<VerifiablePresentationCredentialBuilder>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifiablePresentationCredentialBuilder {
    /// The context of the presentation.
    #[serde(rename = "@context")]
    context: Vec<String>,
    /// The type of the presentation.
    #[serde(rename = "type")]
    type_: Vec<String>,
    /// The verifiable credentials list of the presentation.
    verifiable_credential: Vec<VerifiableCredentialBuilder>,
}

impl Default for VerifiablePresentationCredentialBuilder {
    fn default() -> Self {
        Self {
            context: vec![VERIFIABLE_PRESENTATION_CONTEXT_V1.into()],
            type_: vec![VERIFIABLE_PRESENTATION_TYPE.into()],
            verifiable_credential: vec![],
        }
    }
}

impl VerifiablePresentationCredentialBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a verifiable credential to the presentation.
    pub fn add_verifiable_credential(
        mut self,
        verifiable_credential: VerifiableCredentialBuilder,
    ) -> Self {
        self.verifiable_credential.push(verifiable_credential);
        self
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifiableCredentialBuilder {
    /// The context of the credential.
    #[serde(rename = "@context")]
    context: Vec<String>,
    /// The type of the credential.
    #[serde(rename = "type")]
    type_: Vec<String>,
    /// The issuer of the credential.
    issuer: Option<String>,
    // TODO: Determine if we should use a DateTime<Utc> type here, use chrono lib?
    #[serde(rename = "issuanceDate")]
    issuance_date: Option<String>,
    #[serde(rename = "credentialSubject")]
    credential_subject: Option<serde_json::Value>,
}

impl Default for VerifiableCredentialBuilder {
    fn default() -> Self {
        Self {
            context: vec![VERIFIABLE_PRESENTATION_CONTEXT_V1.into()],
            type_: vec![VERIFIABLE_CREDENTIAL_TYPE.into()],
            issuer: None,
            issuance_date: None,
            credential_subject: None,
        }
    }
}

impl VerifiableCredentialBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a credential to the credential builder, e.g. `IdentityCredential` or `mDL`.
    ///
    /// By default, the `VerifiableCredential` type is added to the credential.
    pub fn add_type(mut self, credential_type: String) -> Self {
        self.type_.push(credential_type);
        self
    }

    /// Set the issuer of the credential.
    ///
    /// The value of the issuer property MUST be either a URI or an object containing an id property.
    /// It is RECOMMENDED that the URI in the issuer or its id be one which, if dereferenced, results
    /// in a document containing machine-readable information about the issuer that can be used to verify
    /// the information expressed in the credential.
    ///
    /// See: [https://www.w3.org/TR/vc-data-model-1.0/#issuer](https://www.w3.org/TR/vc-data-model-1.0/#issuer)
    pub fn set_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Set the issuance date of the credential.
    ///
    /// A credential MUST have an issuanceDate property.
    /// The value of the issuanceDate property MUST be a string value of an [RFC3339](https://www.w3.org/TR/vc-data-model-1.0/#bib-rfc3339)
    /// combined date and time string representing the date and time the credential becomes valid,
    /// which could be a date and time in the future. Note that this value represents the earliest
    /// point in time at which the information associated with the credentialSubject property becomes valid.
    ///
    /// See: [https://www.w3.org/TR/vc-data-model-1.0/#issuance-date](https://www.w3.org/TR/vc-data-model-1.0/#issuance-date)
    pub fn set_issuance_date(mut self, issuance_date: String) -> Self {
        self.issuance_date = Some(issuance_date);
        self
    }

    /// Set the credential subject of the credential.
    ///
    /// The value of the credentialSubject property is defined as a set of objects that contain
    /// one or more properties that are each related to a subject of the verifiable credential.
    /// Each object MAY contain an id, as described in [Section § 4.2 Identifiers](https://www.w3.org/TR/vc-data-model-1.0/#identifiers)
    /// section of the specification.
    pub fn set_credential_subject(mut self, credential_subject: serde_json::Value) -> Self {
        self.credential_subject = Some(credential_subject);
        self
    }
}
