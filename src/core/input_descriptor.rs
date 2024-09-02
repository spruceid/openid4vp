use std::collections::HashSet;

use super::{credential_format::*, presentation_submission::*};
use crate::utils::NonEmptyVec;

use anyhow::{bail, Context, Result};
use jsonschema::{JSONSchema, ValidationError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_claims::jwt::VerifiablePresentation;
use ssi_dids::ssi_json_ld::syntax::from_value;

/// A GroupId represents a unique identifier for a group of Input Descriptors.
///
/// This type is also used by the submission requirements to group input descriptors.
pub type GroupId = String;

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
    #[serde(default)]
    constraints: Constraints,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<ClaimFormatMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<Vec<GroupId>>,
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
    pub fn id(&self) -> &str {
        self.id.as_str()
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
    pub fn set_format(mut self, format: ClaimFormatMap) -> Self {
        self.format = Some(format);
        self
    }

    /// Return the format of the input descriptor.
    pub fn format(&self) -> Option<&ClaimFormatMap> {
        self.format.as_ref()
    }

    /// Return the format designations of the input descriptor as a hash set.
    pub fn format_designations(&self) -> Option<HashSet<&ClaimFormatDesignation>> {
        self.format.as_ref().map(|f| f.keys().collect())
    }

    /// Set the group of the constraints field.
    pub fn set_group(mut self, group: Vec<GroupId>) -> Self {
        self.group = Some(group);
        self
    }

    /// Return the group of the constraints field.
    pub fn groups(&self) -> Option<&Vec<GroupId>> {
        self.group.as_ref()
    }

    /// Return a mutable reference to the group of the constraints field.
    pub fn add_to_group(mut self, member: GroupId) -> Self {
        self.group.get_or_insert_with(Vec::new).push(member);

        self
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

        if let Some(ConstraintsLimitDisclosure::Required) = self.constraints.limit_disclosure {
            if self.constraints.fields().is_none() {
                bail!("Required limit disclosure must have fields.")
            }
        };

        if let Some(constraint_fields) = self.constraints.fields() {
            for constraint_field in constraint_fields.iter() {
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

                let mut map_selector = jsonpath_lib::selector(root_element);

                let validator = constraint_field.validator();

                let mut found_elements = false;

                for field_path in constraint_field.path.iter() {
                    let field_elements = map_selector(field_path)
                        .context("Failed to select field elements from verifiable presentation.")?;

                    // Check if the field matches are empty.
                    if field_elements.is_empty() {
                        // According the specification, found here:
                        // [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation)
                        // > If the result returned no JSONPath match, skip to the next path array element.
                        continue;
                    }

                    found_elements = true;

                    // If a filter is available with a valid schema, handle the field validation.
                    if let Some(Ok(schema_validator)) = validator.as_ref() {
                        let validated_fields = field_elements.iter().find(|element| {
                            match schema_validator.validate(element) {
                                Err(errors) => {
                                    for error in errors {
                                        tracing::debug!(
                                            "Field did not pass filter validation: {error}",
                                        );
                                    }
                                    false
                                }
                                Ok(_) => true,
                            }
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
                }

                // If no elements are found, and limit disclosure is required, return an error.
                if !found_elements {
                    if let Some(ConstraintsLimitDisclosure::Required) =
                        self.constraints.limit_disclosure
                    {
                        bail!("Field elements are empty while limit disclosure is required.")
                    }
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

    /// Returns if the constraints fields contain non-optional
    /// fields that must be satisfied.
    pub fn is_required(&self) -> bool {
        self.fields()
            .map(|fields| fields.iter().any(|field| field.is_required()))
            .unwrap_or(false)
    }

    /// Intent to retain.
    ///
    /// Returns whether any of the contraint fields have an intent
    /// to retain the data by the verifier.
    pub fn intend_to_retain(&self) -> bool {
        self.fields()
            .map(|fields| fields.iter().any(|field| field.intent_to_retain()))
            .unwrap_or(false)
    }
}

/// ConstraintsField objects are used to describe the constraints that a
/// [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder)
/// must satisfy to fulfill an Input Descriptor.
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
    // Optional predicate value
    predicate: Option<Predicate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<serde_json::Value>,
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
    pub fn set_filter(mut self, filter: serde_json::Value) -> Self {
        self.filter = Some(filter);
        self
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

    /// Return the raw filter of the constraints field.
    pub fn filter(&self) -> Option<&serde_json::Value> {
        self.filter.as_ref()
    }

    /// Return a JSON schema validator using the internal filter.
    ///
    /// If no filter is provided on the constraint field, this
    /// will return None.
    ///
    /// # Errors
    ///
    /// If the filter is invalid, this will return an error.
    pub fn validator(&self) -> Option<Result<JSONSchema, ValidationError>> {
        self.filter.as_ref().map(JSONSchema::compile)
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

    /// Set the intent to retain the constraints field.
    ///
    /// This value indicates the verifier's intent to retain the
    /// field in the presentation, storing the value in the verifier's system.
    pub fn set_retained(mut self, intent_to_retain: bool) -> Self {
        self.intent_to_retain = Some(intent_to_retain);
        self
    }

    /// Return the intent to retain the constraints field.
    pub fn intent_to_retain(&self) -> bool {
        self.intent_to_retain.unwrap_or(false)
    }

    /// Return the humanly-readable requested fields of the constraints field.
    ///
    /// This will convert camelCase to space-separated words with capitalized first letter.
    ///
    /// For example, if the path is `["dateOfBirth"]`, this will return `["Date of Birth"]`.
    ///
    /// This will also stripe the periods from the JSON path and return the last word in the path.
    ///
    /// e.g., `["$.verifiableCredential.credentialSubject.dateOfBirth"]` will return `["Date of Birth"]`.
    /// e.g., `["$.verifiableCredential.credentialSubject.familyName"]` will return `["Family Name"]`.
    ///
    pub fn requested_fields(&self) -> Vec<String> {
        self.path()
            .iter()
            // NOTE: It may not be a given that the last path is the field name.
            // TODO: Cannot use the field path as a unique property, it may be associated to different
            // credential types.
            // NOTE: Include the namespace for uniqueness of the requested field type.
            .filter_map(|path| path.split(&['-', '.', ':', '@'][..]).last())
            .map(|path| {
                path.chars()
                    .fold(String::new(), |mut acc, c| {
                        // Convert camelCase to space-separated words with capitalized first letter.
                        if c.is_uppercase() {
                            acc.push(' ');
                        }

                        // Check if the field is snake_case and convert to
                        // space-separated words with capitalized first letter.
                        if c == '_' {
                            acc.push(' ');
                            return acc;
                        }

                        acc.push(c);
                        acc
                    })
                    // Split the path based on empty spaces and uppercase the first letter of each word.
                    .split(' ')
                    .fold(String::new(), |desc, word| {
                        let word =
                            word.chars()
                                .enumerate()
                                .fold(String::new(), |mut acc, (i, c)| {
                                    // Capitalize the first letter of the word.
                                    if i == 0 {
                                        if let Some(c) = c.to_uppercase().next() {
                                            acc.push(c);
                                            return acc;
                                        }
                                    }
                                    acc.push(c);
                                    acc
                                });

                        format!("{desc} {}", word.trim_end())
                    })
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    /// Return the Credential Type of the constraints field
    pub fn credential_type(&self) -> Option<CredentialType> {
        // NOTE: There may be other ways to search for a valid the credential type
        // that meets the input descriptor constraints.
        //
        // A more exhaustive search may require parsing each credential to
        // check if it contains a certain field, e.g. `firstName`, `familyName`, etc.,
        // and see if it will satisfy the constraints.
        //
        // For now, we explicity check the type of the credential if it is present
        // in the credential `type` field.

        if self
            .path
            .as_ref()
            .iter()
            // Check if any of the paths contain a reference to type.
            // NOTE: I am not sure if this is normative to add a `type` field to the path
            // for a verifiable credential.
            .any(|path| path.contains(&"type".to_string()))
        {
            // Check the filter field to determine the `const`
            // value for the credential type, e.g. `iso.org.18013.5.1.mDL`, etc.
            if let Some(credential) = self.filter.as_ref().and_then(|filter| {
                filter
                    .get("const")
                    .and_then(Value::as_str)
                    .map(CredentialType::from)
            }) {
                return Some(credential);
            }

            // The `type` field may be an array with a nested const value.
            if let Some(credential) = self.filter.as_ref().and_then(|filter| {
                filter
                    .get("contains")
                    .and_then(|value| value.get("const"))
                    .and_then(Value::as_str)
                    .map(CredentialType::from)
            }) {
                return Some(credential);
            }
        }

        None
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConstraintsLimitDisclosure {
    Required,
    Preferred,
}
