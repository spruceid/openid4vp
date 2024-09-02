use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// TODO: Does the `isomdl` crate provide this constant value, or another crate?
const ORG_ISO_18013_5_1_MDL: &str = "org.iso.18013.5.1.mDL";

/// A Json object of claim formats.
pub type ClaimFormatMap = HashMap<ClaimFormatDesignation, ClaimFormatPayload>;

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
                // parse the format from the value
                let format = value
                    .get("format")
                    .and_then(|format| format.as_str())
                    // If a `format` property is not present, default to "unknown"
                    .unwrap_or("unknown");

                ClaimFormatDesignation::Other(format.to_string())
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
    Json(serde_json::Value),
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ClaimFormatDesignation {
    /// The format is a JSON Web Token (JWT) as defined by [RFC7519](https://identity.foundation/claim-format-registry/#ref:RFC7519)
    /// that will be submitted in the form of a JWT encoded string. Expression of
    /// supported algorithms in relation to this format MUST be conveyed using an `alg`
    /// property paired with values that are identifiers from the JSON Web Algorithms
    /// registry [RFC7518](https://identity.foundation/claim-format-registry/#ref:RFC7518).
    #[serde(rename = "jwt")]
    Jwt,
    /// These formats are JSON Web Tokens (JWTs) [RFC7519](https://identity.foundation/claim-format-registry/#ref:RFC7519)
    /// that will be submitted in the form of a JWT-encoded string, with a payload extractable from it defined according to the
    /// JSON Web Token (JWT) [section] of the W3C [VC-DATA-MODEL](https://identity.foundation/claim-format-registry/#term:vc-data-model)
    /// specification. Expression of supported algorithms in relation to these formats MUST be conveyed using an JWT alg
    /// property paired with values that are identifiers from the JSON Web Algorithms registry in
    /// [RFC7518](https://identity.foundation/claim-format-registry/#ref:RFC7518) Section 3.
    #[serde(rename = "jwt_vc")]
    JwtVc,
    /// See [JwtVc](JwtVc) for more information.
    #[serde(rename = "jwt_vp")]
    JwtVp,
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
    #[serde(rename = "jwt_vp_json")]
    JwtVpJson,
    /// The format is a Linked-Data Proof that will be submitted as an object.
    /// Expression of supported algorithms in relation to these formats MUST be
    /// conveyed using a proof_type property with values that are identifiers from
    /// the Linked Data Cryptographic Suite Registry [LDP-Registry](https://identity.foundation/claim-format-registry/#term:ldp-registry).
    #[serde(rename = "ldp")]
    Ldp,
    /// Verifiable Credentials or Verifiable Presentations signed with Linked Data Proof formats.
    /// These are descriptions of formats normatively defined in the W3C Verifiable Credentials
    /// specification [VC-DATA-MODEL](https://identity.foundation/claim-format-registry/#term:vc-data-model),
    /// and will be submitted in the form of a JSON object. Expression of supported algorithms in relation to
    /// these formats MUST be conveyed using a proof_type property paired with values that are identifiers from the
    /// Linked Data Cryptographic Suite Registry (LDP-Registry).
    #[serde(rename = "ldp_vc")]
    LdpVc,
    /// See [LdpVc](LdpVc) for more information.
    #[serde(rename = "ldp_vp")]
    LdpVp,
    /// This format is for Verifiable Credentials using AnonCreds.
    /// AnonCreds is a VC format that adds important
    /// privacy-protecting ZKP (zero-knowledge proof) capabilities
    /// to the core VC assurances.
    #[serde(rename = "ac_vc")]
    AcVc,
    /// This format is for Verifiable Presentations using AnonCreds.
    /// AnonCreds is a VC format that adds important privacy-protecting ZKP
    /// (zero-knowledge proof) capabilities to the core VC assurances.
    #[serde(rename = "ac_vp")]
    AcVp,
    /// The format is defined by ISO/IEC 18013-5:2021 [ISO.18013-5](https://identity.foundation/claim-format-registry/#term:iso.18013-5)
    /// which defines a mobile driving license (mDL) Credential in the mobile document (mdoc) format.
    /// Although ISO/IEC 18013-5:2021 ISO.18013-5 is specific to mobile driving licenses (mDLs),
    /// the Credential format can be utilized with any type of Credential (or mdoc document types).
    #[serde(rename = "mso_mdoc")]
    MsoMDoc,
    /// Other claim format designations not covered by the above.
    ///
    /// The value of this variant is the name of the claim format designation.
    Other(String),
}

impl From<&str> for ClaimFormatDesignation {
    fn from(s: &str) -> Self {
        match s {
            "jwt" => Self::Jwt,
            "jwt_vc" => Self::JwtVc,
            "jwt_vp" => Self::JwtVp,
            "jwt_vc_json" => Self::JwtVcJson,
            "jwt_vp_json" => Self::JwtVpJson,
            "ldp" => Self::Ldp,
            "ldp_vc" => Self::LdpVc,
            "ldp_vp" => Self::LdpVp,
            "ac_vc" => Self::AcVc,
            "ac_vp" => Self::AcVp,
            "mso_mdoc" => Self::MsoMDoc,
            s => Self::Other(s.to_string()),
        }
    }
}

impl From<ClaimFormatDesignation> for String {
    fn from(format: ClaimFormatDesignation) -> Self {
        match format {
            ClaimFormatDesignation::AcVc => "ac_vc".to_string(),
            ClaimFormatDesignation::AcVp => "ac_vp".to_string(),
            ClaimFormatDesignation::Jwt => "jwt".to_string(),
            ClaimFormatDesignation::JwtVc => "jwt_vc".to_string(),
            ClaimFormatDesignation::JwtVp => "jwt_vp".to_string(),
            ClaimFormatDesignation::JwtVcJson => "jwt_vc_json".to_string(),
            ClaimFormatDesignation::JwtVpJson => "jwt_vp_json".to_string(),
            ClaimFormatDesignation::Ldp => "ldp".to_string(),
            ClaimFormatDesignation::LdpVc => "ldp_vc".to_string(),
            ClaimFormatDesignation::LdpVp => "ldp_vp".to_string(),
            ClaimFormatDesignation::MsoMDoc => "mso_mdoc".to_string(),
            ClaimFormatDesignation::Other(s) => s,
        }
    }
}

impl std::fmt::Display for ClaimFormatDesignation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", String::from(self.clone()))
    }
}

/// Credential types that may be requested in a credential request.
///
/// Credential types can be presented in a number of formats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CredentialType {
    /// an ISO 18013-5:2021 mobile driving license (mDL) Credential
    #[serde(rename = "org.iso.18013.5.1.mDL")]
    Iso18013_5_1mDl,
    /// A vehicle title credential
    ///
    /// Given there is no universal standard for how to present a vehicle title credential,
    /// the inner String provides a dynamic way to represent a vehicle title credential.
    // TODO: is there a standard identifier for a vehicle title credential instead of `vehicle_title`?
    #[serde(rename = "vehicle_title")]
    VehicleTitle(String),
    // TODO: Add additional credential types here. Fallback to a string for any other credential type.
    /// Other credential types not covered by the above.
    Other(String),
}

impl From<&str> for CredentialType {
    fn from(s: &str) -> Self {
        match s {
            s if s.contains(ORG_ISO_18013_5_1_MDL) => Self::Iso18013_5_1mDl,
            s if s.contains("vehicle_title.") => Self::VehicleTitle(s.to_string()),
            s => Self::Other(s.to_string()),
        }
    }
}

impl From<&CredentialType> for String {
    fn from(cred_type: &CredentialType) -> Self {
        match cred_type {
            CredentialType::Iso18013_5_1mDl => ORG_ISO_18013_5_1_MDL.to_string(),
            CredentialType::VehicleTitle(title) => format!("vehicle_title.{title}"),
            CredentialType::Other(s) => s.to_owned(),
        }
    }
}

impl std::fmt::Display for &CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
