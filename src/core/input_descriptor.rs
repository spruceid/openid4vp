use super::{credential_format::*, presentation_submission::*};
use crate::utils::NonEmptyVec;

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use jsonpath_lib::JsonPathError;
use jsonschema::{JSONSchema, ValidationError};
use serde::{Deserialize, Serialize};
use ssi::claims::jwt::VerifiablePresentation;
use ssi::dids::ssi_json_ld::syntax::from_value;
use uuid::Uuid;

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
    #[serde(default, skip_serializing_if = "ClaimFormatMap::is_empty")]
    format: ClaimFormatMap,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    group: Vec<GroupId>,
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
        self.format = format;
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
    pub fn format(&self) -> &ClaimFormatMap {
        &self.format
    }

    /// Return the format designations of the input descriptor as a hash set.
    pub fn format_designations(&self) -> HashSet<&ClaimFormatDesignation> {
        self.format.keys().collect()
    }

    /// Set the group of the constraints field.
    pub fn set_group(mut self, group: Vec<GroupId>) -> Self {
        self.group = group;
        self
    }

    /// Return the group of the constraints field.
    pub fn groups(&self) -> &Vec<GroupId> {
        self.group.as_ref()
    }

    /// Return a mutable reference to the group of the constraints field.
    pub fn add_to_group(mut self, member: GroupId) -> Self {
        self.group.push(member);

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
            if self.constraints.fields().is_empty() {
                bail!("Required limit disclosure must have fields.")
            }
        };

        for constraint_field in self.constraints.fields.iter() {
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
                if let Some(schema_validator) = validator.as_ref() {
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
                            bail!("Field did not pass filter validation, required by predicate.");
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

        Ok(())
    }

    /// Returns the requested fields of a given JSON-encoded credential
    /// that match the constraint fields of the input descriptors of the
    /// presentation definition.
    pub fn requested_fields<'a>(
        &self,
        mut selector: impl FnMut(&str) -> Result<Vec<&'a serde_json::Value>, JsonPathError>,
    ) -> Vec<RequestedField> {
        self.constraints()
            .fields()
            .iter()
            .map(|field| field.requested_fields(&mut selector))
            .collect()
    }

    /// Return the credential types of the input descriptor, if any.
    pub fn credential_types_hint(&self) -> Vec<CredentialType> {
        self.constraints()
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
}

/// This type is non-normative and used to simplify the construction
/// of constraint field validators at deserialization and construction,
/// thereby reducing runtime error checking requirements.
///
/// Only the inner raw JSON value is serialized and deserialized.
#[derive(Debug, Clone)]
pub struct ConstraintsFieldValidator {
    raw: serde_json::Value,
    compiled: Arc<JSONSchema>,
}

impl ConstraintsFieldValidator {
    pub fn validator(&self) -> &Arc<JSONSchema> {
        &self.compiled
    }
}

impl AsRef<serde_json::Value> for ConstraintsFieldValidator {
    fn as_ref(&self) -> &serde_json::Value {
        &self.raw
    }
}

impl<'a> TryFrom<&'a serde_json::Value> for ConstraintsFieldValidator {
    type Error = ValidationError<'a>;

    fn try_from(value: &'a serde_json::Value) -> Result<Self, Self::Error> {
        let compiled = JSONSchema::compile(value)?;
        Ok(Self {
            raw: value.to_owned(),
            compiled: Arc::new(compiled),
        })
    }
}

// NOTE: implementing PartialEq directly due to JSONSchema not implementing PartialEq.
impl PartialEq for ConstraintsFieldValidator {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for ConstraintsFieldValidator {}

impl Serialize for ConstraintsFieldValidator {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConstraintsFieldValidator {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
        D::Error: std::error::Error,
    {
        let raw = serde_json::Value::deserialize(deserializer)?;

        let compiled = JSONSchema::compile(&raw).map(Arc::new).map_err(|e| {
            serde::de::Error::custom(format!("Failed to compile JSON schema: {}", e))
        })?;

        Ok(ConstraintsFieldValidator { raw, compiled })
    }
}

/// ConstraintsField objects are used to describe the constraints that a
/// [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder)
/// must satisfy to fulfill an Input Descriptor.
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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
    filter: Option<ConstraintsFieldValidator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,
    #[serde(default)]
    intent_to_retain: bool,
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
    pub fn set_filter(mut self, filter: &serde_json::Value) -> Result<Self, ValidationError> {
        self.filter = Some(ConstraintsFieldValidator::try_from(filter)?);
        Ok(self)
    }

    /// Return the raw filter of the constraints field.
    pub fn filter(&self) -> Option<&serde_json::Value> {
        self.filter.as_ref().map(|f| f.as_ref())
    }

    /// Return the validator for the constraints field.
    pub fn validator(&self) -> Option<&Arc<JSONSchema>> {
        self.filter.as_ref().map(|f| f.validator())
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

    /// Set the intent to retain the constraints field.
    ///
    /// This value indicates the verifier's intent to retain the
    /// field in the presentation, storing the value in the verifier's system.
    pub fn set_retained(mut self, intent_to_retain: bool) -> Self {
        self.intent_to_retain = intent_to_retain;
        self
    }

    /// Return the intent to retain the constraints field.
    pub fn intent_to_retain(&self) -> bool {
        self.intent_to_retain
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
        mut selector: impl FnMut(&str) -> Result<Vec<&'a serde_json::Value>, JsonPathError>,
    ) -> RequestedField {
        let raw_values = self
            .path()
            .iter()
            .filter_map(|path| selector(path).ok())
            .flatten()
            .map(ToOwned::to_owned)
            // NOTE: It is likely that only one of the paths will
            // match the selector. Therefore, we're selecting only
            // the first match that exists, if any.
            //
            // It may also be possible that multiple paths match,
            // in which case there may be multiple raw fields
            // that can be requested.
            //
            // As a result, it may be more acceptable to use `collect()` instead
            // of `first()` to return all the possible requested fields.
            .collect::<Vec<serde_json::Value>>()
            .pop();

        let purpose = self.purpose().map(ToOwned::to_owned);

        let name = self
            .name()
            .map(ToOwned::to_owned)
            // TODO: Add an "unknown field" if the name is not provided.
            // Consider skipping or erroring on unknown fields.
            .unwrap_or_default();

        let required = self.is_required();
        let retained = self.intent_to_retain();

        RequestedField::new(
            name,
            required,
            retained,
            purpose,
            self.id().map(ToOwned::to_owned),
            raw_values,
        )
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
        // NOTE: There may be other ways to search for a valid the credential type
        // that meets the input descriptor constraints.
        //
        // A more exhaustive search may require parsing each credential to
        // check if it contains a certain field, e.g. `firstName`, `familyName`, etc.,
        // and see if it will satisfy the constraints.
        //
        // For now, we explicity check the type of the credential if it is present
        // in the credential `type` field.

        let mut parsed_credentials = Vec::new();

        if self
            .path
            .as_ref()
            .iter()
            // Check if any of the paths contain a reference to type.
            // NOTE: It may not be guaranteed or normative that a `type` field to the path
            // for a verifiable credential is present.
            .any(|path| path.contains(&"type".to_string()))
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

/// The [RequestedField] type is non-normative and is not part of the
/// core OID4VP specification. However, it is provided as a helper function
/// for returning requested fields parsed from a given credential that
/// correspond to the input descriptor constraint fields that are requested.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedField {
    /// A unique ID for the requested field
    pub id: Uuid,
    pub name: String,
    pub required: bool,
    pub retained: bool,
    pub purpose: Option<String>,
    pub constraint_field_id: Option<String>,
    // the `raw_field` represents the actual field
    // being selected by the input descriptor JSON path
    // selector.
    pub raw_fields: Option<serde_json::Value>,
}

impl RequestedField {
    /// Construct a new requested field given the required parameters. This method is exposed as
    /// public, however, it is likely that the `from_definition` method will be used to construct
    /// requested fields from a presentation definition.
    ///
    /// See [RequestedField::from_definition] to return a vector of requested fields
    /// according to a presentation definition.
    pub fn new(
        name: String,
        required: bool,
        retained: bool,
        purpose: Option<String>,
        constraint_field_id: Option<String>,
        raw_fields: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            required,
            retained,
            purpose,
            constraint_field_id,
            raw_fields,
        }
    }

    /// Return the unique ID for the request field.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Return the constraint field id this requested field belongs to,
    /// if it exists.
    pub fn constraint_field_id(&self) -> Option<String> {
        self.constraint_field_id.clone()
    }

    /// Return the raw values of the credential matching the
    /// constraint fields filter.
    pub fn raw_fields(&self) -> Option<&serde_json::Value> {
        self.raw_fields.as_ref()
    }
}
