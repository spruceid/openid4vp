use super::credential_format::*;
use crate::utils::NonEmptyVec;

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use jsonschema::ValidationError;
use serde::{Deserialize, Serialize};
use serde_json_path::JsonPath;
use uuid::Uuid;

/// A GroupId represents a unique identifier for a group of Input Descriptors.
///
/// This type is also used by the submission requirements to group input descriptors.
pub type GroupId = String;

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
    pub id: String,

    #[serde(default)]
    pub constraints: Constraints,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    #[serde(default, skip_serializing_if = "ClaimFormatMap::is_empty")]
    pub format: ClaimFormatMap,

    #[serde(rename = "group", default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupId>,
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

    /// Set the name of the input descriptor.
    pub fn set_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
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

    /// Set the format of the input descriptor.
    ///
    /// The Input Descriptor Object MAY contain a format property. If present,
    /// its value MUST be an object with one or more properties matching the registered
    /// Claim Format Designations (e.g., jwt, jwt_vc, jwt_vp, etc.).
    ///
    /// This format property is identical in value signature to the top-level format object,
    /// but can be used to specifically constrain submission of a single input to a subset of formats or algorithms.
    pub fn set_format(mut self, format: ClaimFormatMap) -> Self {
        self.format = format;
        self
    }

    /// Return the format designations of the input descriptor as a hash set.
    pub fn format_designations(&self) -> HashSet<&ClaimFormatDesignation> {
        self.format.keys().collect()
    }

    /// Returns the requested fields of a given JSON-encoded credential
    /// that match the constraint fields of the input descriptors of the
    /// presentation definition.
    pub fn requested_fields<'a>(&self, value: &'a serde_json::Value) -> Vec<RequestedField<'a>> {
        self.constraints
            .fields
            .iter()
            .map(|field| field.requested_fields(self.id.clone(), value))
            .map(|mut requested_field| {
                // Set the purpose of the requested field to the input descriptor `purpose`,
                // if it is no value is set from the constraint field's `purpose`.
                if requested_field.purpose.is_none() {
                    requested_field.purpose = self.purpose.clone();
                }

                requested_field
            })
            .collect()
    }

    /// Return the credential types of the input descriptor, if any.
    pub fn credential_types_hint(&self) -> Vec<CredentialType> {
        self.constraints
            .fields()
            .iter()
            .flat_map(|field| field.credential_types_hint())
            .collect()
    }
}

/// A parsed object containing the credential type(s) and their
/// respective requested fields, parsed from the input descriptor contraints fields.
///
/// NOTE: This object is not part of the OID4VP specification, but is used to simplify the
/// extraction of the requested fields and credential types from the input descriptor.
///
/// If the credential types hint is non-empty, then the holder MUST select from the list of
/// credentials that satisfies the requested fields. Otherwise, if the list is empty, the holder
/// may choose to select any credential that satisfies the requested fields.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialTypesRequestedFields {
    input_descriptor_id: String,
    credential_type_hint: Vec<CredentialType>,
    requested_fields: Vec<String>,
}

impl CredentialTypesRequestedFields {
    /// Return the input descriptor ID.
    pub fn input_descriptor_id(&self) -> &str {
        &self.input_descriptor_id
    }

    /// Return the credential type hint(s).
    ///
    /// NOTE: If credential types hint is non-empty, then the holder MUST
    /// select from the list of credentials that satisfies the requested fields.
    ///
    /// Otherwise, if the list is empty, the holder may choose to select any
    /// credential that satisfies the requested fields.
    pub fn credential_type_hint(&self) -> &[CredentialType] {
        &self.credential_type_hint
    }

    /// Return the requested fields.
    pub fn requested_fields(&self) -> &[String] {
        &self.requested_fields
    }
}

/// Constraints are objects used to describe the constraints that a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder) must satisfy to fulfill an Input Descriptor.
///
/// A constraint object MAY be empty, or it may include a `fields` and/or `limit_disclosure` property.
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Constraints {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<ConstraintsField>,
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
        self.fields.push(field);
        self
    }

    /// Returns the fields of the constraints object.
    pub fn fields(&self) -> &Vec<ConstraintsField> {
        self.fields.as_ref()
    }

    /// Returns the fields of the constraints object as a mutable reference.
    pub fn fields_mut(&mut self) -> &mut Vec<ConstraintsField> {
        self.fields.as_mut()
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

    /// Returns if the constraints fields contain non-optional
    /// fields that must be satisfied.
    pub fn is_required(&self) -> bool {
        self.fields.iter().any(|field| field.is_required())
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn matches(&self, value: &serde_json::Value) -> bool {
        for field in &self.fields {
            if field.query(value).is_none() && field.is_required() {
                return false;
            }
        }

        true
    }
}

/// Pre-compiled JSON-Schema.
///
/// Stores both the raw JSON representation and compiled validator of a JSON
/// Schema. The schema is compiled on the fly upon deserialization.
#[derive(Debug, Clone)]
pub struct CompiledJsonSchema {
    raw: serde_json::Value,
    compiled: Arc<jsonschema::JSONSchema>,
}

impl CompiledJsonSchema {
    pub fn validator(&self) -> &Arc<jsonschema::JSONSchema> {
        &self.compiled
    }
}

impl AsRef<serde_json::Value> for CompiledJsonSchema {
    fn as_ref(&self) -> &serde_json::Value {
        &self.raw
    }
}

impl<'a> TryFrom<&'a serde_json::Value> for CompiledJsonSchema {
    type Error = ValidationError<'a>;

    fn try_from(value: &'a serde_json::Value) -> Result<Self, Self::Error> {
        let compiled = jsonschema::JSONSchema::compile(value)?;
        Ok(Self {
            raw: value.to_owned(),
            compiled: Arc::new(compiled),
        })
    }
}

// NOTE: implementing PartialEq directly due to JSONSchema not implementing PartialEq.
impl PartialEq for CompiledJsonSchema {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for CompiledJsonSchema {}

impl Serialize for CompiledJsonSchema {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CompiledJsonSchema {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
        D::Error: std::error::Error,
    {
        let raw = serde_json::Value::deserialize(deserializer)?;

        let compiled = jsonschema::JSONSchema::compile(&raw)
            .map(Arc::new)
            .map_err(|e| {
                serde::de::Error::custom(format!("Failed to compile JSON schema: {}", e))
            })?;

        Ok(CompiledJsonSchema { raw, compiled })
    }
}

/// ConstraintsField objects are used to describe the constraints that a
/// [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder)
/// must satisfy to fulfill an Input Descriptor.
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintsField {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    pub path: NonEmptyVec<JsonPath>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<CompiledJsonSchema>,

    /// Predicate.
    ///
    /// Defined by the [Predicate feature][1] of Presentation Exchange 2.0.
    ///
    /// [1]: <https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature>
    pub predicate: Option<Predicate>,

    /// Indicates if the Verifier intends to retain the Claim's data being
    /// requested.
    ///
    /// Defined by the [Retention Feature][1] of Presentation Exchange 2.0.
    ///
    /// [1]: <https://identity.foundation/presentation-exchange/spec/v2.0.0/#retention-feature>
    #[serde(default)]
    pub intent_to_retain: bool,
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
            intent_to_retain: false,
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
            ..Default::default()
        }
    }

    /// Add a new path to the constraints field.
    pub fn add_path(mut self, path: JsonPath) -> Self {
        self.path.push(path);
        self
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

    /// Set the purpose of the constraints field.
    ///
    /// If present, its value MUST be a string that describes the purpose for which the field is being requested.
    pub fn set_purpose(mut self, purpose: String) -> Self {
        self.purpose = Some(purpose);
        self
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

    /// Set the filter of the constraints field.
    ///
    /// If present its value MUST be a JSON Schema descriptor used to filter against
    /// the values returned from evaluation of the JSONPath string expressions in the path array.
    pub fn set_filter(mut self, filter: &serde_json::Value) -> Result<Self, ValidationError> {
        self.filter = Some(CompiledJsonSchema::try_from(filter)?);
        Ok(self)
    }

    /// Return the raw filter of the constraints field.
    pub fn filter(&self) -> Option<&serde_json::Value> {
        self.filter.as_ref().map(|f| f.as_ref())
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

    /// Field query.
    ///
    /// See: <https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation>
    pub fn query<'a>(&self, value: &'a serde_json::Value) -> Option<FieldQueryResult<'a>> {
        for path in &self.path {
            let candidates = path.query(value);
            if !candidates.is_empty() {
                for candidate in candidates {
                    if let Some(filter) = &self.filter {
                        if filter.validator().validate(candidate).is_err() {
                            continue; // next candidate
                        }
                    }

                    if let Some(_predicate) = &self.predicate {
                        return Some(FieldQueryResult::Predicate(true));
                    }

                    return Some(FieldQueryResult::Value(candidate));
                }
            }
        }

        None
    }

    /// Returns the requested fields given a JSON-encoded credential
    /// that is compared against the constraint fields of the input
    /// descriptor.
    ///
    /// This method returns constraint fields of the credential itself, as opposed
    /// to the what is defined in the presentation definition. This ensures the
    /// holder of the credential may verify what information is shared versus
    /// requested.
    pub fn requested_fields<'a>(
        &self,
        input_descriptor_id: String,
        value: &'a serde_json::Value,
    ) -> RequestedField<'a> {
        let raw_fields = self
            .path
            .iter()
            .flat_map(|path| path.query(value).all())
            .collect::<Vec<&'a serde_json::Value>>();

        RequestedField {
            id: uuid::Uuid::new_v4(),
            name: self.name.clone(),
            path: self.path.iter().map(|j| j.to_string()).collect(),
            required: self.is_required(),
            retained: self.intent_to_retain,
            purpose: self.purpose.clone(),
            input_descriptor_id,
            raw_fields,
        }
    }

    /// Returns the Credential Type(s) found in the constraints field.
    ///
    /// Note: This is a `hint` in that it is not guaranteed that the credential type
    /// can be parsed from the input descriptor.
    ///
    /// This will return an empty vector if the credential type cannot be parsed.
    ///
    /// Multiple credentials can be returned if the input descriptor contains a pattern
    /// filter that matches multiple credentials.
    pub fn credential_types_hint(&self) -> Vec<CredentialType> {
        let mut parsed_credentials = Vec::new();

        if self
            .path
            .as_ref()
            .iter()
            // Check if any of the paths contain a reference to type.
            // NOTE: It may not be guaranteed or normative that a `type` field to the path
            // for a verifiable credential is present.
            .any(|path| path.to_string().contains("type"))
        {
            // Check the filter field to determine the `const`
            // value for the credential type, e.g. `iso.org.18013.5.1.mDL`, etc.
            if let Some(credential) = self.filter.as_ref().and_then(|filter| {
                filter
                    .as_ref()
                    .get("const")
                    .and_then(serde_json::Value::as_str)
                    .map(CredentialType::from)
            }) {
                parsed_credentials.push(credential);
            }

            // The `type` field may be an array with a nested `const` value.
            if let Some(credential) = self.filter.as_ref().and_then(|filter| {
                filter
                    .as_ref()
                    .get("contains")
                    .and_then(|value| value.get("const"))
                    .and_then(serde_json::Value::as_str)
                    .map(CredentialType::from)
            }) {
                parsed_credentials.push(credential);
            }

            // The `type` field may be an array with a nested `enum` value.
            if let Some(credential) = self.filter.as_ref().and_then(|filter| {
                filter
                    .as_ref()
                    .get("contains")
                    .and_then(|value| value.get("enum"))
                    .and_then(serde_json::Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(CredentialType::from)
                            .collect::<Vec<String>>()
                    })
            }) {
                parsed_credentials.extend(credential);
            }

            // Check a pattern for the filter that may include multiple credentials
            // that may satisfy the constraints.
            if let Some(credentials) = self.filter.as_ref().and_then(|filter| {
                filter
                    .as_ref()
                    .get("pattern")
                    .and_then(serde_json::Value::as_str)
                    .map(|pattern| {
                        // Remove the start (^) and end ($) anchors
                        let trimmed = pattern.trim_start_matches('^').trim_end_matches('$');

                        // Remove the outer parentheses
                        let inner = trimmed.trim_start_matches('(').trim_end_matches(')');

                        // Split by the '|' character
                        inner
                            .split('|')
                            .map(|s| s.to_string())
                            .collect::<Vec<CredentialType>>()
                    })
            }) {
                // Found multiple credentials that may satisfy the constraints.
                parsed_credentials.extend(credentials);
            }
        }

        parsed_credentials
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConstraintsLimitDisclosure {
    Required,
    Preferred,
}

pub enum FieldQueryResult<'a> {
    Predicate(bool),
    Value(&'a serde_json::Value),
}

/// The [RequestedField] type is non-normative and is not part of the
/// core OID4VP specification. However, it is provided as a helper function
/// for returning requested fields parsed from a given credential that
/// correspond to the input descriptor constraint fields that are requested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedField<'a> {
    /// A unique ID for the requested field
    pub id: Uuid,
    /// The input descriptor ID the requested field belongs to.
    pub input_descriptor_id: String,
    // The name property is optional, since it is also
    // optional on the constraint field.
    pub name: Option<String>,
    pub path: Vec<String>,
    pub required: bool,
    pub retained: bool,
    pub purpose: Option<String>,
    // the `raw_field` represents the actual field(s)
    // being selected by the input descriptor JSON path
    // selector.
    pub raw_fields: Vec<&'a serde_json::Value>,
}
