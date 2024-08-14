use std::collections::HashMap;

pub use crate::utils::NonEmptyVec;
use crate::{
    core::response::{AuthorizationResponse, UnencodedAuthorizationResponse},
    json_schema_validation::SchemaValidator,
};

use anyhow::{bail, Context, Result};
use did_method_key::DIDKey;
use serde::{Deserialize, Serialize};
use serde_json::Map;
use ssi_claims::{
    jwt::{AnyRegisteredClaim, Issuer, RegisteredClaim, VerifiablePresentation},
    CompactJWSString, VerificationParameters,
};
use ssi_dids::{
    ssi_json_ld::{
        object::value::FragmentRef,
        syntax::{from_value, Value},
    },
    VerificationMethodDIDResolver, DIDJWK,
};
use ssi_jwk::JWK;
use ssi_verification_methods::AnyJwkMethod;

/// A JSONPath is a string that represents a path to a specific value within a JSON object.
///
/// For syntax details, see [https://identity.foundation/presentation-exchange/spec/v2.0.0/#jsonpath-syntax-definition](https://identity.foundation/presentation-exchange/spec/v2.0.0/#jsonpath-syntax-definition)
pub type JsonPath = String;

/// The predicate Feature introduces properties enabling Verifier to request that Holder apply a predicate and return the result.
///
/// The predicate Feature extends the Input Descriptor Object `constraints.fields` object to add a predicate property.
///
/// The value of predicate **MUST** be one of the following strings: `required` or `preferred`.
///
/// If the predicate property is not present, a Conformant Consumer **MUST NOT** return derived predicate values.
///
/// See: [https://identity.foundation/presentation-exchange/#predicate-feature](https://identity.foundation/presentation-exchange/#predicate-feature)
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum Predicate {
    /// required - This indicates that the returned value **MUST** be the boolean result of
    /// applying the value of the filter property to the result of evaluating the path property.
    #[serde(rename = "required")]
    Required,
    /// preferred - This indicates that the returned value **SHOULD** be the boolean result of
    /// applying the value of the filter property to the result of evaluating the path property.
    #[serde(rename = "preferred")]
    Preferred,
}

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
#[serde(untagged)]
pub enum ClaimFormat {
    #[serde(rename = "jwt_vp")]
    JwtVp {
        // The algorithm used to sign the JWT verifiable presentation.
        alg: Vec<String>,
    },
    #[serde(rename = "jwt_vp_json")]
    JwtVpJson {
        // Used in the OID4VP specification for wallet methods supported.
        alg_values_supported: Vec<String>,
    },
    #[serde(rename = "jwt_vc")]
    JwtVc {
        // The algorithm used to sign the JWT verifiable credential.
        alg: Vec<String>,
    },
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson {
        // Used in the OID4VP specification for wallet methods supported.
        alg_values_supported: Vec<String>,
    },
    #[serde(rename = "jwt")]
    Jwt {
        // The algorithm used to sign the JWT.
        alg: Vec<String>,
    },
    #[serde(rename = "ldp_vp")]
    LdpVp {
        // The proof type used to sign the linked data proof verifiable presentation.
        proof_type: Vec<String>,
    },
    #[serde(rename = "ldp_vc")]
    LdpVc {
        // The proof type used to sign the linked data proof verifiable credential.
        proof_type: Vec<String>,
    },
    #[serde(rename = "ldp")]
    Ldp {
        // The proof type used to sign the linked data proof.
        // e.g., "JsonWebSignature2020", "Ed25519Signature2018", "EcdsaSecp256k1Signature2019", "RsaSignature2018"
        proof_type: Vec<String>,
    },
    #[serde(rename = "ac_vp")]
    AcVp {
        // The proof type used to sign the anoncreds verifiable presentation.
        proof_type: Vec<String>,
    },
    #[serde(rename = "ac_vc")]
    AcVc {
        // The proof type used to sign the anoncreds verifiable credential.
        proof_type: Vec<String>,
    },
    #[serde(rename = "mso_mdoc")]
    MsoMDoc(serde_json::Value),
    #[serde(untagged)]
    Other {
        name: String,
        value: serde_json::Value,
    },
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
            ClaimFormat::Other { name, .. } => ClaimFormatDesignation::Other(name.to_owned()),
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
    /// JwtVcJson is used by `vp_formats_supported` in the OID4VP metadata.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
    /// See [JwtVc](JwtVc) for more information.
    #[serde(rename = "jwt_vp")]
    JwtVp,
    /// JwtVpJson is used by `vp_formats_supported` in the OID4VP metadata.
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
    #[serde(untagged)]
    Other(String),
}

/// A presentation definition is a JSON object that describes the information a [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) requires of a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder).
///
/// > Presentation Definitions are objects that articulate what proofs a [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) requires.
/// These help the [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) to decide how or whether to interact with a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder).
///
/// Presentation Definitions are composed of inputs, which describe the forms and details of the
/// proofs they require, and optional sets of selection rules, to allow [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder)s flexibility
/// in cases where different types of proofs may satisfy an input requirement.
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition)
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentationDefinition {
    id: String,
    input_descriptors: Vec<InputDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<ClaimFormat>,
}

impl PresentationDefinition {
    /// The Presentation Definition MUST contain an id property. The value of this property MUST be a string.
    /// The string SHOULD provide a unique ID for the desired context.
    ///
    /// The Presentation Definition MUST contain an input_descriptors property. Its value MUST be an array of Input Descriptor Objects,
    /// the composition of which are found [InputDescriptor] type.
    ///
    pub fn new(id: String, input_descriptor: InputDescriptor) -> Self {
        Self {
            id,
            input_descriptors: vec![input_descriptor],
            ..Default::default()
        }
    }

    /// Return the id of the presentation definition.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Add a new input descriptor to the presentation definition.
    pub fn add_input_descriptors(mut self, input_descriptor: InputDescriptor) -> Self {
        self.input_descriptors.push(input_descriptor);
        self
    }

    /// Return the input descriptors of the presentation definition.
    pub fn input_descriptors(&self) -> &Vec<InputDescriptor> {
        &self.input_descriptors
    }

    /// Return a mutable reference to the input descriptors of the presentation definition.
    pub fn input_descriptors_mut(&mut self) -> &mut Vec<InputDescriptor> {
        &mut self.input_descriptors
    }

    /// Set the name of the presentation definition.
    ///
    /// The [PresentationDefinition] MAY contain a name property. If present, its value SHOULD be a
    /// human-friendly string intended to constitute a distinctive designation of the Presentation Definition.
    pub fn set_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Return the name of the presentation definition.
    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }

    /// Set the purpose of the presentation definition.
    ///
    /// The [PresentationDefinition] MAY contain a purpose property. If present, its value MUST be a string that
    /// describes the purpose for which the Presentation Definition's inputs are being used for.
    pub fn set_purpose(mut self, purpose: String) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// Return the purpose of the presentation definition.
    pub fn purpose(&self) -> Option<&String> {
        self.purpose.as_ref()
    }

    /// Attach a format to the presentation definition.
    ///
    /// The Presentation Definition MAY include a format property. If present,
    /// the value MUST be an object with one or more properties matching the
    /// registered Claim Format Designations (e.g., jwt, jwt_vc, jwt_vp, etc.).
    ///
    /// The properties inform the [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder) of the Claim format configurations the [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) can process.
    /// The value for each claim format property MUST be an object composed as follows:
    ///
    /// The object MUST include a format-specific property (i.e., alg, proof_type)
    /// that expresses which algorithms the [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) supports for the format.
    /// Its value MUST be an array of one or more format-specific algorithmic identifier references,
    /// as noted in the Claim Format Designations section.
    ///
    /// See: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition)
    pub fn set_format(mut self, format: ClaimFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Return the format of the presentation definition.
    pub fn format(&self) -> Option<&ClaimFormat> {
        self.format.as_ref()
    }

    /// Validate a presentation submission against the presentation definition.
    ///
    /// Checks the underlying presentation submission parsed from the authorization response,
    /// against the input descriptors of the presentation definition.
    pub async fn validate_authorization_response(
        &self,
        auth_response: &AuthorizationResponse,
    ) -> Result<()> {
        match auth_response {
            AuthorizationResponse::Jwt(jwt) => {
                bail!("Authorization Response Presentation Definition Validation Not Implemented.")
            }
            AuthorizationResponse::Unencoded(response) => {
                let presentation_submission = response.presentation_submission().parsed();

                let jwt = response.vp_token().0.clone();

                // TODO: Verify the JWT.
                // let jws = CompactJWSString::from_string(jwt.clone()).context("Invalid JWT.")?;
                // let resolver: VerificationMethodDIDResolver<DIDKey, AnyJwkMethod> =
                //     VerificationMethodDIDResolver::new(DIDKey);
                // let params = VerificationParameters::from_resolver(resolver);

                // if let Err(e) = jws.verify(params).await {
                //     bail!("JWT Verification Failed: {:?}", e)
                // }

                let verifiable_presentation: VerifiablePresentation =
                    ssi_claims::jwt::decode_unverified(&jwt)?;

                // let holder: Option<Issuer> =
                //     Issuer::extract(AnyRegisteredClaim::from(verifiable_presentation.clone()));

                // println!("Holder: {:?}", holder);

                // Ensure the definition id matches the submission's definition id.
                if presentation_submission.definition_id() != self.id() {
                    bail!("Presentation Definition ID does not match the Presentation Submission.")
                }

                let descriptor_map: HashMap<String, DescriptorMap> = presentation_submission
                    .descriptor_map()
                    .iter()
                    .map(|descriptor_map| (descriptor_map.id().to_owned(), descriptor_map.clone()))
                    .collect();

                for input_descriptor in self.input_descriptors().iter() {
                    match descriptor_map.get(input_descriptor.id()) {
                        None => {
                            // TODO: Determine whether input descriptor must have a corresponding descriptor map.
                            bail!("Input Descriptor ID not found in Descriptor Map.")
                        }
                        Some(descriptor) => {
                            input_descriptor
                                .validate_verifiable_presentation(
                                    &verifiable_presentation,
                                    descriptor,
                                )
                                .context("Input Descriptor Validation Failed.")?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Input Descriptors are objects used to describe the information a
/// [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) requires of a
/// [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder).
///
/// All Input Descriptors MUST be satisfied, unless otherwise specified by a
/// [Feature](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:feature).
///
/// See: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputDescriptor {
    id: String,
    constraints: Constraints,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<ClaimFormat>,
}

impl InputDescriptor {
    /// Create a new instance of the input descriptor with the given id and constraints.
    ///
    /// The Input Descriptor Object MUST contain an id property. The value of the id
    /// property MUST be a string that does not conflict with the id of another
    /// Input Descriptor Object in the same Presentation Definition.
    ///
    ///
    /// The Input Descriptor Object MUST contain a constraints property.
    ///
    /// See: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
    pub fn new(id: String, constraints: Constraints) -> Self {
        Self {
            id,
            constraints,
            ..Default::default()
        }
    }

    /// Return the id of the input descriptor.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Return the constraints of the input descriptor.
    pub fn constraints(&self) -> &Constraints {
        &self.constraints
    }

    /// Set the name of the input descriptor.
    pub fn set_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Return the name of the input descriptor.
    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }

    /// Set the purpose of the input descriptor.
    ///
    /// The purpose of the input descriptor is an optional field.
    ///
    /// If present, the purpose MUST be a string that describes the purpose for which the
    /// [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim)'s
    /// data is being requested.
    pub fn set_purpose(mut self, purpose: String) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// Return the purpose of the input descriptor.
    ///
    /// If present, the purpose MUST be a string that describes the purpose for which the
    /// [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim)'s
    /// data is being requested.
    pub fn purpose(&self) -> Option<&String> {
        self.purpose.as_ref()
    }

    /// Set the format of the input descriptor.
    ///
    /// The Input Descriptor Object MAY contain a format property. If present,
    /// its value MUST be an object with one or more properties matching the registered
    /// Claim Format Designations (e.g., jwt, jwt_vc, jwt_vp, etc.).
    ///
    /// This format property is identical in value signature to the top-level format object,
    /// but can be used to specifically constrain submission of a single input to a subset of formats or algorithms.
    pub fn set_format(mut self, format: ClaimFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Return the format of the input descriptor.
    ///
    /// The Input Descriptor Object MAY contain a format property. If present,
    /// its value MUST be an object with one or more properties matching the registered
    /// Claim Format Designations (e.g., jwt, jwt_vc, jwt_vp, etc.).
    ///
    /// This format property is identical in value signature to the top-level format object,
    /// but can be used to specifically constrain submission of a single input to a subset of formats or algorithms.
    pub fn format(&self) -> Option<&ClaimFormat> {
        self.format.as_ref()
    }

    /// Validate the input descriptor against the verifiable presentation and the descriptor map.
    pub fn validate_verifiable_presentation(
        &self,
        verifiable_presentation: &VerifiablePresentation,
        descriptor_map: &DescriptorMap,
    ) -> Result<()> {
        // The descriptor map must match the input descriptor.
        if descriptor_map.id() != self.id() {
            bail!("Input Descriptor ID does not match the Descriptor Map ID.")
        }

        let vp = &verifiable_presentation.0;

        let vp_json: serde_json::Value =
            from_value(vp.clone()).context("failed to parse value into json type")?;

        if let Some(ConstraintsLimitDisclosure::Required) = self.constraints().limit_disclosure() {
            if self.constraints().fields().is_none() {
                bail!("Required limit disclosure must have fields.")
            }
        };

        if let Some(field_constraints) = self.constraints().fields() {
            for constraint_field in field_constraints.iter() {
                // Check if the filter exists if the predicate is present
                // and set to required.
                if let Some(Predicate::Required) = constraint_field.predicate() {
                    if constraint_field.filter().is_none() {
                        bail!("Required predicate must have a filter.")
                    }
                }

                let mut selector = jsonpath_lib::selector(&vp_json);

                // The root element is relative to the descriptor map path returned.
                let Ok(root_element) = selector(descriptor_map.path()) else {
                    bail!("Failed to select root element from verifiable presentation.")
                };

                let root_element = root_element
                    .first()
                    .ok_or(anyhow::anyhow!("Root element not found."))?;

                println!("Root element: {:?}", root_element);

                let mut map_selector = jsonpath_lib::selector(root_element);

                for field_path in constraint_field.path().iter() {
                    println!("Field path: {:?}", field_path);

                    let field_elements = map_selector(field_path)
                        .context("Failed to select field elements from verifiable presentation.")?;

                    // Check if the field matches are empty.
                    if field_elements.is_empty() {
                        if let Some(ConstraintsLimitDisclosure::Required) =
                            self.constraints().limit_disclosure()
                        {
                            bail!("Field elements are empty while limit disclosure is required.")
                        }

                        // According the specification, found here:
                        // [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation)
                        // > If the result returned no JSONPath match, skip to the next path array element.
                        continue;
                    }

                    println!("Field elements: {:?}", field_elements);

                    if let Some(filter) = constraint_field.filter() {
                        // TODO: possible trace a warning if a field is not valid.
                        // TODO: Check the predicate feature value.
                        let validated_fields =
                            field_elements
                                .iter()
                                .find(|element| match filter.validate(element) {
                                    Err(e) => {
                                        println!("Field did not pass filter validation: {}", e);
                                        false
                                    }
                                    Ok(_) => true,
                                });

                        if validated_fields.is_none() {
                            if let Some(Predicate::Required) = constraint_field.predicate() {
                                bail!(
                                    "Field did not pass filter validation, required by predicate."
                                );
                            } else if constraint_field.is_required() {
                                bail!("Field did not pass filter validation, and is not an optional field.");
                            }
                        }
                    }

                    // TODO: Check limit disclosure of data requested. Do not provide more data
                    // than is necessary to satisfy the constraints.
                }
            }
        }

        Ok(())
    }
}

/// Constraints are objects used to describe the constraints that a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder) must satisfy to fulfill an Input Descriptor.
///
/// A constraint object MAY be empty, or it may include a `fields` and/or `limit_disclosure` property.
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Constraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<ConstraintsField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_disclosure: Option<ConstraintsLimitDisclosure>,
}

impl Constraints {
    /// Returns an empty Constraints object.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new field constraint to the constraints list.
    pub fn add_constraint(mut self, field: ConstraintsField) -> Self {
        self.fields.get_or_insert_with(Vec::new).push(field);
        self
    }

    /// Returns the fields of the constraints object.
    pub fn fields(&self) -> Option<&Vec<ConstraintsField>> {
        self.fields.as_ref()
    }

    /// Set the limit disclosure value.
    ///
    /// For all [Claims](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claims) submitted in relation to [InputDescriptor] Objects that include a `constraints`
    /// object with a `limit_disclosure` property set to the string value `required`,
    /// ensure that the data submitted is limited to the entries specified in the `fields` property of the `constraints` object.
    /// If the `fields` property IS NOT present, or contains zero field objects, the submission SHOULD NOT include any data from the Claim.
    ///
    /// For example, a [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) may simply want to know whether a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder) has a valid, signed [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim) of a particular type,
    /// without disclosing any of the data it contains.
    ///
    /// For more information: see [https://identity.foundation/presentation-exchange/spec/v2.0.0/#limited-disclosure-submissions](https://identity.foundation/presentation-exchange/spec/v2.0.0/#limited-disclosure-submissions)
    pub fn set_limit_disclosure(mut self, limit_disclosure: ConstraintsLimitDisclosure) -> Self {
        self.limit_disclosure = Some(limit_disclosure);
        self
    }

    /// Returns the limit disclosure value.
    pub fn limit_disclosure(&self) -> Option<&ConstraintsLimitDisclosure> {
        self.limit_disclosure.as_ref()
    }
}

/// ConstraintsField objects are used to describe the constraints that a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder) must satisfy to fulfill an Input Descriptor.
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintsField {
    path: NonEmptyVec<JsonPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    // TODO: JSONSchema validation at deserialization time
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<SchemaValidator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // Optional predicate value
    predicate: Option<Predicate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent_to_retain: Option<bool>,
}

pub type ConstraintsFields = Vec<ConstraintsField>;

impl From<NonEmptyVec<JsonPath>> for ConstraintsField {
    fn from(path: NonEmptyVec<JsonPath>) -> Self {
        Self {
            path,
            id: None,
            purpose: None,
            name: None,
            filter: None,
            predicate: None,
            optional: None,
            intent_to_retain: None,
        }
    }
}

impl ConstraintsField {
    /// Create a new instance of the constraints field with the given path.
    ///
    /// Constraint fields must have at least one JSONPath to the field for which the constraint is applied.
    ///
    /// Tip: Use the [ConstraintsField::From](ConstraintsField::From) trait to convert a [NonEmptyVec](NonEmptyVec) of
    /// [JsonPath](JsonPath) to a [ConstraintsField](ConstraintsField) if more than one path is known.
    pub fn new(path: JsonPath) -> ConstraintsField {
        ConstraintsField {
            path: NonEmptyVec::new(path),
            id: None,
            purpose: None,
            name: None,
            filter: None,
            predicate: None,
            optional: None,
            intent_to_retain: None,
        }
    }

    /// Add a new path to the constraints field.
    pub fn add_path(mut self, path: JsonPath) -> Self {
        self.path.push(path);
        self
    }

    /// Return the paths of the constraints field.
    ///
    /// `path` is a non empty list of [JsonPath](https://goessner.net/articles/JsonPath/) expressions.
    ///
    /// For syntax definition, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#jsonpath-syntax-definition](https://identity.foundation/presentation-exchange/spec/v2.0.0/#jsonpath-syntax-definition)
    pub fn path(&self) -> &NonEmptyVec<JsonPath> {
        &self.path
    }

    /// Set the id of the constraints field.
    ///
    /// The fields object MAY contain an id property. If present, its value MUST be a string that
    /// is unique from every other field object’s id property, including those contained in other
    /// Input Descriptor Objects.
    pub fn set_id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    /// Return the id of the constraints field.
    pub fn id(&self) -> Option<&String> {
        self.id.as_ref()
    }

    /// Set the purpose of the constraints field.
    ///
    /// If present, its value MUST be a string that describes the purpose for which the field is being requested.
    pub fn set_purpose(mut self, purpose: String) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// Return the purpose of the constraints field.
    pub fn purpose(&self) -> Option<&String> {
        self.purpose.as_ref()
    }

    /// Set the name of the constraints field.
    ///
    /// If present, its value MUST be a string, and SHOULD be a human-friendly
    /// name that describes what the target field represents.
    ///
    /// For example, the name of the constraint could be "over_18" if the field is a date of birth.
    pub fn set_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Return the name of the constraints field.
    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }

    /// Set the filter of the constraints field.
    ///
    /// If present its value MUST be a JSON Schema descriptor used to filter against
    /// the values returned from evaluation of the JSONPath string expressions in the path array.
    pub fn set_filter(mut self, filter: SchemaValidator) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Return the filter of the constraints field.
    pub fn filter(&self) -> Option<&SchemaValidator> {
        self.filter.as_ref()
    }

    /// Set the predicate of the constraints field.
    ///
    /// When using the [Predicate Feature](https://identity.foundation/presentation-exchange/#predicate-feature),
    /// the fields object **MAY** contain a predicate property. If the predicate property is present,
    /// the filter property **MUST** also be present.
    ///
    /// See: [https://identity.foundation/presentation-exchange/#predicate-feature](https://identity.foundation/presentation-exchange/#predicate-feature)
    pub fn set_predicate(mut self, predicate: Predicate) -> Self {
        self.predicate = Some(predicate);
        self
    }

    /// Return the predicate of the constraints field.
    ///
    /// When using the [Predicate Feature](https://identity.foundation/presentation-exchange/#predicate-feature),
    /// the fields object **MAY** contain a predicate property. If the predicate property is present,
    /// the filter property **MUST** also be present.
    ///
    /// See: [https://identity.foundation/presentation-exchange/#predicate-feature](https://identity.foundation/presentation-exchange/#predicate-feature)
    pub fn predicate(&self) -> Option<&Predicate> {
        self.predicate.as_ref()
    }

    /// Set the optional value of the constraints field.
    ///
    /// The value of this property MUST be a boolean, wherein true indicates the
    /// field is optional, and false or non-presence of the property indicates the
    /// field is required. Even when the optional property is present, the value
    /// located at the indicated path of the field MUST validate against the
    /// JSON Schema filter, if a filter is present.
    ///
    /// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
    pub fn set_optional(mut self, optional: bool) -> Self {
        self.optional = Some(optional);
        self
    }

    /// Return the optional value of the constraints field.
    pub fn is_optional(&self) -> bool {
        self.optional.unwrap_or(false)
    }

    /// Inverse alias for `!is_optional()`.
    pub fn is_required(&self) -> bool {
        !self.is_optional()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConstraintsLimitDisclosure {
    Required,
    Preferred,
}

/// Presentation Submissions are objects embedded within target
/// [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim) negotiation
/// formats that express how the inputs presented as proofs to a
/// [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) are
/// provided in accordance with the requirements specified in a [PresentationDefinition].
///
/// Embedded Presentation Submission objects MUST be located within target data format as
/// the value of a `presentation_submission` property.
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentationSubmission {
    id: uuid::Uuid,
    definition_id: String,
    descriptor_map: Vec<DescriptorMap>,
}

impl PresentationSubmission {
    /// The presentation submission MUST contain an id property. The value of this property MUST be a unique identifier, i.e. a UUID.
    ///
    /// The presentation submission object MUST contain a `definition_id` property.
    /// The value of this property MUST be the id value of a valid [PresentationDefinition::id()].
    ///
    /// The object MUST include a `descriptor_map` property. The value of this property MUST be an array of
    /// Input [DescriptorMap] Objects.
    pub fn new(id: uuid::Uuid, definition_id: String, descriptor_map: Vec<DescriptorMap>) -> Self {
        Self {
            id,
            definition_id,
            descriptor_map,
        }
    }

    /// Return the id of the presentation submission.
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    /// Return the definition id of the presentation submission.
    pub fn definition_id(&self) -> &String {
        &self.definition_id
    }

    /// Return the descriptor map of the presentation submission.
    pub fn descriptor_map(&self) -> &Vec<DescriptorMap> {
        &self.descriptor_map
    }

    /// Return a mutable reference to the descriptor map of the presentation submission.
    pub fn descriptor_map_mut(&mut self) -> &mut Vec<DescriptorMap> {
        &mut self.descriptor_map
    }
}

/// Descriptor Maps are objects used to describe the information a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder) provides to a [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier).
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DescriptorMap {
    id: String,
    format: ClaimFormatDesignation,
    path: JsonPath,
    path_nested: Option<Box<DescriptorMap>>,
}

impl DescriptorMap {
    /// The descriptor map MUST include an `id` property. The value of this property MUST be a string that matches the `id` property of the [InputDescriptor::id()] in the [PresentationDefinition] that this [PresentationSubmission] is related to.
    ///
    /// The descriptor map object MUST include a `format` property. The value of this property MUST be a string that matches one of the [ClaimFormatDesignation]. This denotes the data format of the [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim).
    ///
    /// The descriptor map object MUST include a `path` property. The value of this property MUST be a [JSONPath](https://goessner.net/articles/JsonPath/) string expression. The path property indicates the [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim) submitted in relation to the identified [InputDescriptor], when executed against the top-level of the object the [PresentationSubmission] is embedded within.
    ///
    /// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
    pub fn new(id: String, format: ClaimFormatDesignation, path: JsonPath) -> Self {
        Self {
            id,
            format,
            path,
            path_nested: None,
        }
    }

    /// Return the id of the descriptor map.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Return the format of the descriptor map.
    pub fn format(&self) -> &ClaimFormatDesignation {
        &self.format
    }

    /// Return the path of the descriptor map.
    pub fn path(&self) -> &JsonPath {
        &self.path
    }

    /// Set the nested path of the descriptor map.
    ///
    /// The format of a path_nested object mirrors that of a [DescriptorMap] property. The nesting may be any number of levels deep.
    /// The `id` property MUST be the same for each level of nesting.
    ///
    /// The path property inside each `path_nested` property provides a relative path within a given nested value.
    ///
    /// For more information on nested paths, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries](https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries)
    ///
    /// Errors:
    /// - The id of the nested path must be the same as the parent id.
    pub fn set_path_nested(mut self, path_nested: DescriptorMap) -> Result<Self> {
        // Check the id of the nested path is the same as the parent id.
        if path_nested.id() != self.id() {
            bail!("The id of the nested path must be the same as the parent id.")
        }

        self.path_nested = Some(Box::new(path_nested));

        Ok(self)
    }
}

#[derive(Deserialize)]
pub struct SubmissionRequirementBaseBase {
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum SubmissionRequirementBase {
    From {
        from: String, // TODO `group` string??
        #[serde(flatten)]
        submission_requirement_base: SubmissionRequirementBaseBase,
    },
    FromNested {
        from_nested: Vec<SubmissionRequirement>,
        #[serde(flatten)]
        submission_requirement_base: SubmissionRequirementBaseBase,
    },
}

#[derive(Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum SubmissionRequirement {
    All(SubmissionRequirementBase),
    Pick(SubmissionRequirementPick),
}

#[derive(Deserialize)]
pub struct SubmissionRequirementPick {
    #[serde(flatten)]
    pub submission_requirement: SubmissionRequirementBase,
    pub count: Option<u64>,
    pub min: Option<u64>,
    pub max: Option<u64>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        ffi::OsStr,
        fs::{self, File},
    };

    #[test]
    fn request_example() {
        let value = json!(
            {
                "id": "36682080-c2ed-4ba6-a4cd-37c86ef2da8c",
                "input_descriptors": [
                    {
                        "id": "d05a7f51-ac09-43af-8864-e00f0175f2c7",
                        "format": {
                            "ldp_vc": {
                                "proof_type": [
                                    "Ed25519Signature2018"
                                ]
                            }
                        },
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$.type"
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "pattern": "IDCardCredential"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        );
        let _: PresentationDefinition = serde_json::from_value(value).unwrap();
    }

    #[derive(Deserialize)]
    pub struct PresentationDefinitionTest {
        #[serde(alias = "presentation_definition")]
        _pd: PresentationDefinition,
    }

    #[test]
    fn presentation_definition_suite() {
        let paths =
            fs::read_dir("tests/presentation-exchange/test/presentation-definition").unwrap();
        for path in paths {
            let path = path.unwrap().path();
            if let Some(ext) = path.extension() {
                if ext != OsStr::new("json")
                    || ["VC_expiration_example.json", "VC_revocation_example.json"] // TODO bad format
                        .contains(&path.file_name().unwrap().to_str().unwrap())
                {
                    continue;
                }
            }
            print!("{} -> ", path.file_name().unwrap().to_str().unwrap());
            let file = File::open(path).unwrap();
            let jd = &mut serde_json::Deserializer::from_reader(file.try_clone().unwrap());
            let _: PresentationDefinitionTest = serde_path_to_error::deserialize(jd)
                .map_err(|e| e.path().to_string())
                .unwrap();
            println!("✅")
        }
    }

    #[derive(Deserialize)]
    pub struct PresentationSubmissionTest {
        #[serde(alias = "presentation_submission")]
        _ps: PresentationSubmission,
    }

    #[test]
    fn presentation_submission_suite() {
        let paths =
            fs::read_dir("tests/presentation-exchange/test/presentation-submission").unwrap();
        for path in paths {
            let path = path.unwrap().path();
            if let Some(ext) = path.extension() {
                if ext != OsStr::new("json")
                    || [
                        "appendix_DIDComm_example.json",
                        "appendix_CHAPI_example.json",
                    ]
                    .contains(&path.file_name().unwrap().to_str().unwrap())
                {
                    continue;
                }
            }
            print!("{} -> ", path.file_name().unwrap().to_str().unwrap());
            let file = File::open(path).unwrap();
            let jd = &mut serde_json::Deserializer::from_reader(file.try_clone().unwrap());
            let _: PresentationSubmissionTest = serde_path_to_error::deserialize(jd)
                .map_err(|e| e.path().to_string())
                .unwrap();
            println!("✅")
        }
    }

    #[derive(Deserialize)]
    pub struct SubmissionRequirementsTest {
        #[serde(alias = "submission_requirements")]
        _sr: Vec<SubmissionRequirement>,
    }

    #[test]
    fn submission_requirements_suite() {
        let paths =
            fs::read_dir("tests/presentation-exchange/test/submission-requirements").unwrap();
        for path in paths {
            let path = path.unwrap().path();
            if let Some(ext) = path.extension() {
                if ext != OsStr::new("json")
                    || ["schema.json"].contains(&path.file_name().unwrap().to_str().unwrap())
                {
                    continue;
                }
            }
            print!("{} -> ", path.file_name().unwrap().to_str().unwrap());
            let file = File::open(path).unwrap();
            let jd = &mut serde_json::Deserializer::from_reader(file.try_clone().unwrap());
            let _: SubmissionRequirementsTest = serde_path_to_error::deserialize(jd)
                .map_err(|e| e.path().to_string())
                .unwrap();
            println!("✅")
        }
    }
}
