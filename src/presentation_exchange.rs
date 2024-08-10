use crate::json_schema_validation::SchemaValidator;
pub use crate::utils::NonEmptyVec;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Map;

/// A JSONPath is a string that represents a path to a specific value within a JSON object.
///
/// For syntax details, see [https://identity.foundation/presentation-exchange/spec/v2.0.0/#jsonpath-syntax-definition](https://identity.foundation/presentation-exchange/spec/v2.0.0/#jsonpath-syntax-definition)
pub type JsonPath = String;

/// The claim format designation type is used in the input description object to specify the format of the claim.
///
/// Registry of claim format type: https://identity.foundation/claim-format-registry/#registry
///
/// Documentation based on the [DIF Presentation Exchange Specification v2.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/#claim-format-designations)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    id: uuid::Uuid, // TODO: The specification allows for non-uuid types, should we revert to using String type?
    input_descriptors: Vec<InputDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<serde_json::Value>,
}

impl PresentationDefinition {
    /// The Presentation Definition MUST contain an id property. The value of this property MUST be a string.
    /// The string SHOULD provide a unique ID for the desired context.
    ///
    /// The Presentation Definition MUST contain an input_descriptors property. Its value MUST be an array of Input Descriptor Objects,
    /// the composition of which are found [InputDescriptor] type.
    ///
    pub fn new(id: uuid::Uuid, input_descriptor: InputDescriptor) -> Self {
        Self {
            id,
            input_descriptors: vec![input_descriptor],
            ..Default::default()
        }
    }

    /// Return the id of the presentation definition.
    pub fn id(&self) -> &uuid::Uuid {
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
    pub fn set_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Return the name of the presentation definition.
    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }

    /// Set the purpose of the presentation definition.
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
    pub fn set_format(mut self, format: serde_json::Value) -> Self {
        self.format = Some(format);
        self
    }

    /// Return the format of the presentation definition.
    pub fn format(&self) -> Option<&serde_json::Value> {
        self.format.as_ref()
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
    id: uuid::Uuid,
    constraints: Constraints,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<serde_json::Value>, // TODO
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
    pub fn new(id: uuid::Uuid, constraints: Constraints) -> Self {
        Self {
            id,
            constraints,
            ..Default::default()
        }
    }

    /// Create a new instance of an input descriptor with a random UUID.
    ///
    /// The Input Descriptor Object MUST contain a constraints property.
    pub fn new_random(constraints: Constraints) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            constraints,
            ..Default::default()
        }
    }

    /// Return the id of the input descriptor.
    pub fn id(&self) -> &uuid::Uuid {
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
    pub fn set_format(mut self, format: serde_json::Value) -> Self {
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
    pub fn format(&self) -> Option<&serde_json::Value> {
        self.format.as_ref()
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
    // JSON Regex path -> check regex against JSON structure to check if there is a match;
    // TODO JsonPath validation at deserialization time
    // Regular expression includes the path -> whether or not the JSON object contains a property.
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
            optional: None,
            intent_to_retain: None,
        }
    }
}

impl ConstraintsField {
    /// Create a new instance of the constraints field with the given path.
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
    pub fn optional(&self) -> bool {
        self.optional.unwrap_or(false)
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
    definition_id: uuid::Uuid,
    descriptor_map: Vec<DescriptorMap>,
}

impl PresentationSubmission {
    /// The presentation submission MUST contain an id property. The value of this property MUST be a UUID.
    ///
    /// The presentation submission object MUST contain a `definition_id` property. The value of this property MUST be the id value of a valid [PresentationDefinition::id()].
    pub fn new(
        id: uuid::Uuid,
        definition_id: uuid::Uuid,
        descriptor_map: Vec<DescriptorMap>,
    ) -> Self {
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
    pub fn definition_id(&self) -> &uuid::Uuid {
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
    id: uuid::Uuid,
    format: ClaimFormatDesignation,
    path: JsonPath,
    path_nested: Option<Box<DescriptorMap>>,
}

impl DescriptorMap {
    /// The descriptor map MUST include an `id` property. The value of this property MUST be a string that matches the `id` property of the [InputDescriptor::id()] in the Presentation Definition that this [PresentationSubmission] is related to.
    ///
    /// The descriptor map object MUST include a `format` property. The value of this property MUST be a string that matches one of the [ClaimFormatDesignation]. This denotes the data format of the [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim).
    ///
    /// The descriptor map object MUST include a `path` property. The value of this property MUST be a [JSONPath](https://goessner.net/articles/JsonPath/) string expression. The path property indicates the [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim) submitted in relation to the identified [InputDescriptor], when executed against the top-level of the object the [PresentationSubmission] is embedded within.
    ///
    /// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
    pub fn new(id: uuid::Uuid, format: ClaimFormatDesignation, path: JsonPath) -> Self {
        Self {
            id,
            format,
            path,
            path_nested: None,
        }
    }

    /// Return the id of the descriptor map.
    pub fn id(&self) -> &uuid::Uuid {
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
