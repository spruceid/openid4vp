use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ssi_claims::jwt::{VerifiableCredential, VerifiablePresentation};
use ssi_claims::vc::v2::syntax::VERIFIABLE_PRESENTATION_TYPE;
use ssi_dids::ssi_json_ld::CREDENTIALS_V1_CONTEXT;
use ssi_dids::{
    ssi_json_ld::syntax::{Object, Value},
    DIDURLBuf,
};

#[derive(Debug, Clone)]
pub struct VerifiablePresentationBuilderOptions {
    pub issuer: DIDURLBuf,
    pub subject: DIDURLBuf,
    pub audience: DIDURLBuf,
    pub nonce: String,
    // TODO: we may wish to support an explicit
    // issuance and expiration date rather than seconds from now.
    /// Expiration is in seconds from `now`.
    /// e.g. 3600 for 1 hour.
    pub expiration_secs: u64,
    pub credentials: Vec<VerifiableCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiablePresentationBuilder(VerifiablePresentation);

impl From<VerifiablePresentationBuilder> for VerifiablePresentation {
    fn from(builder: VerifiablePresentationBuilder) -> Self {
        builder.0
    }
}

impl Default for VerifiablePresentationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifiablePresentationBuilder {
    /// Returns an empty verifiable presentation builder.
    pub fn new() -> Self {
        Self(VerifiablePresentation(Value::Object(Object::new())))
    }

    /// Returns a verifiable presentation builder from options.
    ///
    /// This will set the issuance date to the current time and the expiration
    /// date to the expiration secs from the issuance date.
    pub fn from_options(options: VerifiablePresentationBuilderOptions) -> VerifiablePresentation {
        let mut verifiable_presentation = VerifiablePresentation(Value::Object(Object::new()));

        if let Some(obj) = verifiable_presentation.0.as_object_mut() {
            // The issuer is the holder of the verifiable credential (subject of the verifiable credential).
            obj.insert("iss".into(), Value::String(options.issuer.as_str().into()));

            // The audience is the verifier of the verifiable credential.
            obj.insert(
                "aud".into(),
                Value::String(options.audience.as_str().into()),
            );

            if let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
                // The issuance date is the current time.
                obj.insert("iat".into(), Value::Number(dur.as_secs().into()));

                // The expiration date is 1 hour from the current time.
                obj.insert(
                    "exp".into(),
                    Value::Number((dur.as_secs() + options.expiration_secs).into()),
                );
            }

            obj.insert("nonce".into(), Value::String(options.nonce.into()));

            let mut verifiable_credential_field = Value::Object(Object::new());

            if let Some(cred) = verifiable_credential_field.as_object_mut() {
                cred.insert(
                    "@context".into(),
                    Value::String(CREDENTIALS_V1_CONTEXT.to_string().into()),
                );

                cred.insert(
                    "type".into(),
                    Value::String(VERIFIABLE_PRESENTATION_TYPE.to_string().into()),
                );

                cred.insert(
                    "verifiableCredential".into(),
                    Value::Array(options.credentials.into_iter().map(|vc| vc.0).collect()),
                );
            }

            obj.insert("vp".into(), verifiable_credential_field);
        }

        verifiable_presentation
    }

    /// Add an issuer to the verifiable presentation.
    ///
    /// The issuer is the entity that issues the verifiable presentation.
    /// This is typically the holder of the verifiable credential.
    pub fn add_issuer(mut self, issuer: DIDURLBuf) -> Self {
        if let Some(obj) = self.0 .0.as_object_mut() {
            // The issuer is the holder of the verifiable credential (subject of the verifiable credential).
            obj.insert("iss".into(), Value::String(issuer.as_str().into()));
        };
        self
    }

    /// Add a subject to the verifiable presentation.
    ///
    /// The subject is the entity that is the subject of the verifiable presentation.
    /// This is typically the holder of the verifiable credential.
    pub fn add_subject(mut self, subject: DIDURLBuf) -> Self {
        if let Some(obj) = self.0 .0.as_object_mut() {
            // The subject is the entity that is the subject of the verifiable presentation.
            obj.insert("sub".into(), Value::String(subject.as_str().into()));
        };
        self
    }

    /// Add an audience to the verifiable presentation.
    /// The audience is the entity to which the verifiable presentation is addressed.
    /// This is typically the verifier of the verifiable presentation.
    pub fn add_audience(mut self, audience: DIDURLBuf) -> Self {
        if let Some(obj) = self.0 .0.as_object_mut() {
            // The audience is the entity to which the verifiable presentation is addressed.
            obj.insert("aud".into(), Value::String(audience.as_str().into()));
        };
        self
    }

    /// Set the issuance date of the verifiable presentation.
    pub fn set_issuance_date(mut self, issuance_date: i64) -> Self {
        if let Some(obj) = self.0 .0.as_object_mut() {
            obj.insert("iat".into(), Value::Number(issuance_date.into()));
        };
        self
    }

    /// Set the expiration date of the verifiable presentation.
    pub fn set_expiration_date(mut self, expiration_date: i64) -> Self {
        if let Some(obj) = self.0 .0.as_object_mut() {
            obj.insert("exp".into(), Value::Number(expiration_date.into()));
        };
        self
    }

    /// Set the nonce of the verifiable presentation.
    pub fn set_nonce(mut self, nonce: String) -> Self {
        if let Some(obj) = self.0 .0.as_object_mut() {
            obj.insert("nonce".into(), Value::String(nonce.into()));
        }
        self
    }

    pub fn build(self) -> VerifiablePresentation {
        self.0
    }
}
