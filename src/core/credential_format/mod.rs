use core::fmt;
use std::{borrow::Cow, collections::HashMap, str::FromStr};

use serde::{Deserialize, Serialize};

const FORMAT_JWT: &str = "jwt";
const FORMAT_JWT_VC: &str = "jwt_vc";
const FORMAT_JWT_VP: &str = "jwt_vp";
const FORMAT_JWT_VC_JSON: &str = "jwt_vc_json";
const FORMAT_JWT_VP_JSON: &str = "jwt_vp_json";
const FORMAT_LDP: &str = "ldp";
const FORMAT_LDP_VC: &str = "ldp_vc";
const FORMAT_LDP_VP: &str = "ldp_vp";
const FORMAT_AC_VC: &str = "ac_vc";
const FORMAT_AC_VP: &str = "ac_vp";
const FORMAT_MSO_MDOC: &str = "mso_mdoc";

/// A Json object of claim formats.
pub type ClaimFormatMap = HashMap<ClaimFormatDesignation, ClaimFormatPayload>;

/// The credential type that may be requested in a presentation request.
// NOTE: Credential types can be presented in a number of formats and therefore
// is an alias of a String is used. In the future, there may be a case to create
// a new type with associative methods, e.g., to parse various credential types, etc.
pub type CredentialType = String;

/// The Presentation Definition MAY include a format property. The value MUST be an object with one or
/// more properties matching the registered [ClaimFormatDesignation] (e.g., jwt, jwt_vc, jwt_vp, etc.).
/// The properties inform the Holder of the Claim format configurations the Verifier can process.
/// The value for each claim format property MUST be an object composed as follows:
///
/// The object MUST include a format-specific property (i.e., alg, proof_type) that expresses which
/// algorithms the Verifier supports for the format. Its value MUST be an array of one or more
/// format-specific algorithmic identifier references, as noted in the [ClaimFormatDesignation].
///
/// See [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition)
/// for an example schema.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimFormat {
    #[serde(rename = "jwt")]
    Jwt {
        /// The algorithm used to sign the JWT.
        alg: Vec<String>,
    },
    #[serde(rename = "jwt_vc")]
    JwtVc {
        /// The algorithm used to sign the JWT verifiable credential.
        alg: Vec<String>,
    },
    #[serde(rename = "jwt_vp")]
    JwtVp {
        /// The algorithm used to sign the JWT verifiable presentation.
        alg: Vec<String>,
    },
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson {
        /// Used in the OID4VP specification for wallet methods supported.
        alg_values_supported: Vec<String>,
    },
    #[serde(rename = "jwt_vp_json")]
    JwtVpJson {
        /// Used in the OID4VP specification for wallet methods supported.
        alg_values_supported: Vec<String>,
    },
    #[serde(rename = "ldp")]
    Ldp {
        /// The proof type used to sign the linked data proof.
        /// e.g., "JsonWebSignature2020", "Ed25519Signature2018", "EcdsaSecp256k1Signature2019", "RsaSignature2018"
        proof_type: Vec<String>,
    },
    #[serde(rename = "ldp_vc")]
    LdpVc {
        /// The proof type used to sign the linked data proof verifiable credential.
        proof_type: Vec<String>,
    },
    #[serde(rename = "ldp_vp")]
    LdpVp {
        /// The proof type used to sign the linked data proof verifiable presentation.
        proof_type: Vec<String>,
    },
    #[serde(rename = "ac_vc")]
    AcVc {
        /// The proof type used to sign the anoncreds verifiable credential.
        proof_type: Vec<String>,
    },
    #[serde(rename = "ac_vp")]
    AcVp {
        /// The proof type used to sign the anoncreds verifiable presentation.
        proof_type: Vec<String>,
    },
    #[serde(rename = "mso_mdoc")]
    MsoMDoc(serde_json::Value),
    /// Support for non-standard claim formats.
    // NOTE: a `format` property will be included within the serialized
    // type. This will help for identifying the claim format designation type.
    #[serde(untagged)]
    Other(serde_json::Value),
}

impl ClaimFormat {
    /// Returns the designated format of the claim.
    ///
    /// e.g., jwt, jwt_vc, jwt_vp, ldp, ldp_vc, ldp_vp, ac_vc, ac_vp, mso_mdoc
    pub fn designation(&self) -> ClaimFormatDesignation {
        match self {
            ClaimFormat::Jwt { .. } => ClaimFormatDesignation::Jwt,
            ClaimFormat::JwtVc { .. } => ClaimFormatDesignation::JwtVc,
            ClaimFormat::JwtVcJson { .. } => ClaimFormatDesignation::JwtVcJson,
            ClaimFormat::JwtVp { .. } => ClaimFormatDesignation::JwtVp,
            ClaimFormat::JwtVpJson { .. } => ClaimFormatDesignation::JwtVpJson,
            ClaimFormat::Ldp { .. } => ClaimFormatDesignation::Ldp,
            ClaimFormat::LdpVc { .. } => ClaimFormatDesignation::LdpVc,
            ClaimFormat::LdpVp { .. } => ClaimFormatDesignation::LdpVp,
            ClaimFormat::AcVc { .. } => ClaimFormatDesignation::AcVc,
            ClaimFormat::AcVp { .. } => ClaimFormatDesignation::AcVp,
            ClaimFormat::MsoMDoc(_) => ClaimFormatDesignation::MsoMDoc,
            ClaimFormat::Other(value) => {
                // Parse the format from the first key found in the value map.
                let format = value
                    .as_object()
                    .and_then(|map| map.keys().next())
                    .map(ToOwned::to_owned)
                    .unwrap_or("other".into());

                ClaimFormatDesignation::Other(format)
            }
        }
    }
}

/// Claim format payload
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimFormatPayload {
    #[serde(rename = "alg")]
    Alg(Vec<String>),
    /// This variant is primarily used for `jwt_vc_json` and `jwt_vp_json`
    /// claim presentation algorithm types supported by a wallet.
    #[serde(rename = "alg_values_supported")]
    AlgValuesSupported(Vec<String>),
    #[serde(rename = "proof_type")]
    ProofType(Vec<String>),
    #[serde(untagged)]
    Other(serde_json::Value),
}

impl ClaimFormatPayload {
    /// Adds an algorithm value to the list of supported algorithms.
    ///
    /// This method is a no-op if self is not of type `AlgValuesSupported` or `Alg`.
    pub fn add_alg(&mut self, alg: String) {
        if let Self::Alg(algs) | Self::AlgValuesSupported(algs) = self {
            algs.push(alg);
        }
    }

    /// Adds a proof type to the list of supported proof types.
    ///
    /// This method is a no-op if self is not of type `ProofType`.
    pub fn add_proof_type(&mut self, proof_type: String) {
        if let Self::ProofType(proof_types) = self {
            proof_types.push(proof_type);
        }
    }
}

/// The claim format designation type is used in the input description object to specify the format of the claim.
///
/// Registry of claim format type: https://identity.foundation/claim-format-registry/#registry
///
/// Documentation based on the [DIF Presentation Exchange Specification v2.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/#claim-format-designations)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClaimFormatDesignation {
    /// The format is a JSON Web Token (JWT) as defined by [RFC7519](https://identity.foundation/claim-format-registry/#ref:RFC7519)
    /// that will be submitted in the form of a JWT encoded string. Expression of
    /// supported algorithms in relation to this format MUST be conveyed using an `alg`
    /// property paired with values that are identifiers from the JSON Web Algorithms
    /// registry [RFC7518](https://identity.foundation/claim-format-registry/#ref:RFC7518).
    Jwt,

    /// These formats are JSON Web Tokens (JWTs) [RFC7519](https://identity.foundation/claim-format-registry/#ref:RFC7519)
    /// that will be submitted in the form of a JWT-encoded string, with a payload extractable from it defined according to the
    /// JSON Web Token (JWT) [section] of the W3C [VC-DATA-MODEL](https://identity.foundation/claim-format-registry/#term:vc-data-model)
    /// specification. Expression of supported algorithms in relation to these formats MUST be conveyed using an JWT alg
    /// property paired with values that are identifiers from the JSON Web Algorithms registry in
    /// [RFC7518](https://identity.foundation/claim-format-registry/#ref:RFC7518) Section 3.
    JwtVc,

    /// See [JwtVc](JwtVc) for more information.
    JwtVp,

    JwtVcJson,

    JwtVpJson,

    /// The format is a Linked-Data Proof that will be submitted as an object.
    /// Expression of supported algorithms in relation to these formats MUST be
    /// conveyed using a proof_type property with values that are identifiers from
    /// the Linked Data Cryptographic Suite Registry [LDP-Registry](https://identity.foundation/claim-format-registry/#term:ldp-registry).
    Ldp,

    /// Verifiable Credentials or Verifiable Presentations signed with Linked Data Proof formats.
    /// These are descriptions of formats normatively defined in the W3C Verifiable Credentials
    /// specification [VC-DATA-MODEL](https://identity.foundation/claim-format-registry/#term:vc-data-model),
    /// and will be submitted in the form of a JSON object. Expression of supported algorithms in relation to
    /// these formats MUST be conveyed using a proof_type property paired with values that are identifiers from the
    /// Linked Data Cryptographic Suite Registry (LDP-Registry).
    LdpVc,

    /// See [LdpVc](LdpVc) for more information.
    LdpVp,

    /// This format is for Verifiable Credentials using AnonCreds.
    /// AnonCreds is a VC format that adds important
    /// privacy-protecting ZKP (zero-knowledge proof) capabilities
    /// to the core VC assurances.
    AcVc,

    /// This format is for Verifiable Presentations using AnonCreds.
    /// AnonCreds is a VC format that adds important privacy-protecting ZKP
    /// (zero-knowledge proof) capabilities to the core VC assurances.
    AcVp,

    /// The format is defined by ISO/IEC 18013-5:2021 [ISO.18013-5](https://identity.foundation/claim-format-registry/#term:iso.18013-5)
    /// which defines a mobile driving license (mDL) Credential in the mobile document (mdoc) format.
    /// Although ISO/IEC 18013-5:2021 ISO.18013-5 is specific to mobile driving licenses (mDLs),
    /// the Credential format can be utilized with any type of Credential (or mdoc document types).
    MsoMDoc,

    /// Other claim format designations not covered by the above.
    ///
    /// The value of this variant is the name of the claim format designation.
    Other(String),
}

impl ClaimFormatDesignation {
    pub fn from_name(name: Cow<str>) -> Self {
        match name.as_ref() {
            FORMAT_JWT => Self::Jwt,
            FORMAT_JWT_VC => Self::JwtVc,
            FORMAT_JWT_VP => Self::JwtVp,
            FORMAT_JWT_VC_JSON => Self::JwtVcJson,
            FORMAT_JWT_VP_JSON => Self::JwtVpJson,
            FORMAT_LDP => Self::Ldp,
            FORMAT_LDP_VC => Self::LdpVc,
            FORMAT_LDP_VP => Self::LdpVp,
            FORMAT_AC_VC => Self::AcVc,
            FORMAT_AC_VP => Self::AcVp,
            FORMAT_MSO_MDOC => Self::MsoMDoc,
            _ => Self::Other(name.into_owned()),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Jwt => FORMAT_JWT,
            Self::JwtVc => FORMAT_JWT_VC,
            Self::JwtVp => FORMAT_JWT_VP,
            Self::JwtVcJson => FORMAT_JWT_VC_JSON,
            Self::JwtVpJson => FORMAT_JWT_VP_JSON,
            Self::Ldp => FORMAT_LDP,
            Self::LdpVc => FORMAT_LDP_VC,
            Self::LdpVp => FORMAT_LDP_VP,
            Self::AcVc => FORMAT_AC_VC,
            Self::AcVp => FORMAT_AC_VP,
            Self::MsoMDoc => FORMAT_MSO_MDOC,
            Self::Other(other) => other,
        }
    }

    fn into_name(self) -> Cow<'static, str> {
        match self {
            Self::Jwt => Cow::Borrowed(FORMAT_JWT),
            Self::JwtVc => Cow::Borrowed(FORMAT_JWT_VC),
            Self::JwtVp => Cow::Borrowed(FORMAT_JWT_VP),
            Self::JwtVcJson => Cow::Borrowed(FORMAT_JWT_VC_JSON),
            Self::JwtVpJson => Cow::Borrowed(FORMAT_JWT_VP_JSON),
            Self::Ldp => Cow::Borrowed(FORMAT_LDP),
            Self::LdpVc => Cow::Borrowed(FORMAT_LDP_VC),
            Self::LdpVp => Cow::Borrowed(FORMAT_LDP_VP),
            Self::AcVc => Cow::Borrowed(FORMAT_AC_VC),
            Self::AcVp => Cow::Borrowed(FORMAT_AC_VP),
            Self::MsoMDoc => Cow::Borrowed(FORMAT_MSO_MDOC),
            Self::Other(other) => Cow::Owned(other),
        }
    }
}

impl From<&str> for ClaimFormatDesignation {
    fn from(s: &str) -> Self {
        Self::from_name(Cow::Borrowed(s))
    }
}

impl From<String> for ClaimFormatDesignation {
    fn from(value: String) -> Self {
        Self::from_name(Cow::Owned(value))
    }
}

impl FromStr for ClaimFormatDesignation {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.into())
    }
}

impl From<ClaimFormatDesignation> for String {
    fn from(format: ClaimFormatDesignation) -> Self {
        format.into_name().into_owned()
    }
}

impl fmt::Display for ClaimFormatDesignation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name().fmt(f)
    }
}

impl Serialize for ClaimFormatDesignation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.name().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ClaimFormatDesignation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn test_credential_format_serialization() {
        let value = json!({
          "claim_formats_supported": {
            "jwt_vc": {
              "alg": ["ES256", "EdDSA"],
              "proof_type": ["JsonWebSignature2020"]
            },
            "ldp_vc": {
              "proof_type": ["Ed25519Signature2018", "EcdsaSecp256k1Signature2019"]
            },
            "sd_jwt_vc": {
              "alg": ["ES256", "ES384"],
              "kb_jwt_alg": ["ES256"]
            },
            "com.example.custom_vc": {
              "version": "1.0",
              "encryption": ["AES-GCM"],
              "signature": ["ED25519"]
            }
          }
        });

        let claim_format_map: ClaimFormatMap =
            serde_json::from_value(value["claim_formats_supported"].clone())
                .expect("Failed to parse claim format map");

        assert!(claim_format_map.contains_key(&ClaimFormatDesignation::JwtVc));
        assert!(claim_format_map.contains_key(&ClaimFormatDesignation::LdpVc));
        assert!(
            claim_format_map.contains_key(&ClaimFormatDesignation::Other("sd_jwt_vc".to_string()))
        );
        assert!(
            claim_format_map.contains_key(&ClaimFormatDesignation::Other(
                "com.example.custom_vc".to_string()
            ))
        );
    }
}
