use core::fmt;
use std::{borrow::Cow, collections::HashMap, str::FromStr};

use serde::{Deserialize, Serialize};

// Credential Format Identifiers
// See Appendix B: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B
const FORMAT_JWT_VC_JSON: &str = "jwt_vc_json";
const FORMAT_LDP_VC: &str = "ldp_vc";
const FORMAT_MSO_MDOC: &str = "mso_mdoc";
const FORMAT_DC_SD_JWT: &str = "dc+sd-jwt";

/// A Json object of claim formats.
pub type ClaimFormatMap = HashMap<ClaimFormatDesignation, ClaimFormatPayload>;

/// The credential type that may be requested in a presentation request.
// NOTE: Credential types can be presented in a number of formats and therefore
// is an alias of a String is used. In the future, there may be a case to create
// a new type with associative methods, e.g., to parse various credential types, etc.
pub type CredentialType = String;

/// Credential Format with associated metadata.
///
/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimFormat {
    /// W3C Verifiable Credential secured with JWT (OID4VP v1.0 Section B.1.3.1)
    ///
    /// Covers both credentials AND presentations per spec.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson {
        /// Algorithms supported for JWT-secured credentials/presentations.
        alg_values_supported: Vec<String>,
    },
    /// W3C Verifiable Credential secured with Data Integrity (OID4VP v1.0 Section B.1.3.2)
    ///
    /// Covers both credentials AND presentations per spec.
    #[serde(rename = "ldp_vc")]
    LdpVc {
        /// Proof types supported for Data Integrity credentials/presentations.
        proof_type: Vec<String>,
    },
    /// ISO/IEC 18013-5 mDOC (OID4VP v1.0 Section B.2)
    #[serde(rename = "mso_mdoc")]
    MsoMDoc(serde_json::Value),
    /// IETF SD-JWT VC (OID4VP v1.0 Section B.3)
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt(serde_json::Value),
    /// Support for non-standard claim formats.
    #[serde(untagged)]
    Other(serde_json::Value),
}

impl ClaimFormat {
    /// Returns the designated format of the claim.
    pub fn designation(&self) -> ClaimFormatDesignation {
        match self {
            ClaimFormat::JwtVcJson { .. } => ClaimFormatDesignation::JwtVcJson,
            ClaimFormat::LdpVc { .. } => ClaimFormatDesignation::LdpVc,
            ClaimFormat::MsoMDoc(_) => ClaimFormatDesignation::MsoMDoc,
            ClaimFormat::DcSdJwt(_) => ClaimFormatDesignation::DcSdJwt,
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

/// Claim format payload per OID4VP v1.0 Appendix B.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimFormatPayload {
    /// Algorithms supported for JWT-based credentials (jwt_vc_json, jwt_vp_json).
    /// Per OID4VP v1.0 Section B.1.3.1.3.
    #[serde(rename = "alg_values")]
    AlgValues(Vec<String>),
    /// Cryptographic suites supported for Data Integrity credentials (ldp_vc, ldp_vp).
    /// Per OID4VP v1.0 Section B.1.3.2.3.
    #[serde(rename = "proof_type_values")]
    ProofTypeValues(Vec<String>),
    /// Catch-all for other formats (mso_mdoc, dc+sd-jwt, etc.)
    /// which may have different or multiple metadata parameters.
    #[serde(untagged)]
    Other(serde_json::Value),
}

impl ClaimFormatPayload {
    /// Adds an algorithm value to the list of supported algorithms.
    ///
    /// This method is a no-op if self is not of type `AlgValues`.
    pub fn add_alg(&mut self, alg: String) {
        if let Self::AlgValues(algs) = self {
            algs.push(alg);
        }
    }

    /// Adds a proof type to the list of supported proof types.
    ///
    /// This method is a no-op if self is not of type `ProofTypeValues`.
    pub fn add_proof_type(&mut self, proof_type: String) {
        if let Self::ProofTypeValues(proof_types) = self {
            proof_types.push(proof_type);
        }
    }
}

/// Credential Format Identifiers.

/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClaimFormatDesignation {
    /// W3C Verifiable Credential secured with JWT (OID4VP v1.0 Section B.1.3.1)
    ///
    /// Per Section B.1.3.1.1:
    /// > "The Credential Format Identifier is `jwt_vc_json` to request a W3C Verifiable
    /// > Credential... or a Verifiable Presentation of such a Credential."
    JwtVcJson,

    /// W3C Verifiable Credential secured with Data Integrity (OID4VP v1.0 Section B.1.3.2)
    ///
    /// Per Section B.1.3.2.1:
    /// > "The Credential Format Identifier is `ldp_vc` to request a W3C Verifiable
    /// > Credential... or a Verifiable Presentation of such a Credential."
    LdpVc,

    /// ISO/IEC 18013-5 mDOC format (OID4VP v1.0 Section B.2)
    ///
    /// Used for mobile driving licenses (mDL) and other mobile documents.
    MsoMDoc,

    /// IETF SD-JWT VC format (OID4VP v1.0 Section B.3)
    ///
    /// The Credential Format Identifier is `dc+sd-jwt` per Section B.3.1.
    DcSdJwt,

    /// Other claim format designations not defined in OID4VP v1.0.
    ///
    /// The value of this variant is the name of the claim format designation.
    Other(String),
}

impl ClaimFormatDesignation {
    pub fn from_name(name: Cow<str>) -> Self {
        match name.as_ref() {
            FORMAT_JWT_VC_JSON => Self::JwtVcJson,
            FORMAT_LDP_VC => Self::LdpVc,
            FORMAT_MSO_MDOC => Self::MsoMDoc,
            FORMAT_DC_SD_JWT => Self::DcSdJwt,
            _ => Self::Other(name.into_owned()),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::JwtVcJson => FORMAT_JWT_VC_JSON,
            Self::LdpVc => FORMAT_LDP_VC,
            Self::MsoMDoc => FORMAT_MSO_MDOC,
            Self::DcSdJwt => FORMAT_DC_SD_JWT,
            Self::Other(other) => other,
        }
    }

    fn into_name(self) -> Cow<'static, str> {
        match self {
            Self::JwtVcJson => Cow::Borrowed(FORMAT_JWT_VC_JSON),
            Self::LdpVc => Cow::Borrowed(FORMAT_LDP_VC),
            Self::MsoMDoc => Cow::Borrowed(FORMAT_MSO_MDOC),
            Self::DcSdJwt => Cow::Borrowed(FORMAT_DC_SD_JWT),
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
        // OID4VP v1.0 compliant vp_formats_supported
        let value = json!({
          "vp_formats_supported": {
            "jwt_vc_json": {
              "alg_values": ["ES256", "EdDSA"]
            },
            "ldp_vc": {
              "proof_type_values": ["Ed25519Signature2018", "ecdsa-rdfc-2019"]
            },
            "mso_mdoc": {},
            "dc+sd-jwt": {
              "sd-jwt_alg_values": ["ES256"],
              "kb-jwt_alg_values": ["ES256"]
            }
          }
        });

        let claim_format_map: ClaimFormatMap =
            serde_json::from_value(value["vp_formats_supported"].clone())
                .expect("Failed to parse claim format map");

        assert!(claim_format_map.contains_key(&ClaimFormatDesignation::JwtVcJson));
        assert!(claim_format_map.contains_key(&ClaimFormatDesignation::LdpVc));
        assert!(claim_format_map.contains_key(&ClaimFormatDesignation::MsoMDoc));
        assert!(claim_format_map.contains_key(&ClaimFormatDesignation::DcSdJwt));
    }

    #[test]
    fn test_format_covers_both_credentials_and_presentations() {
        assert_eq!(ClaimFormatDesignation::JwtVcJson.name(), "jwt_vc_json");
        assert_eq!(ClaimFormatDesignation::LdpVc.name(), "ldp_vc");

        // Non-standard formats should be parsed as Other
        let jwt_vp_json: ClaimFormatDesignation = "jwt_vp_json".into();
        assert!(matches!(jwt_vp_json, ClaimFormatDesignation::Other(_)));

        let ldp_vp: ClaimFormatDesignation = "ldp_vp".into();
        assert!(matches!(ldp_vp, ClaimFormatDesignation::Other(_)));
    }
}
