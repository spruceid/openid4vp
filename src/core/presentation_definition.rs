use super::credential_format::*;
use super::input_descriptor::*;
use super::presentation_submission::*;

use std::collections::HashMap;
use std::collections::HashSet;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Map;

/// A presentation definition is a JSON object that describes the information a [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) requires of a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder).
///
/// > Presentation Definitions are objects that articulate what proofs a [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) requires.
/// > These help the [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier) to decide how or whether to interact with a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder).
///
/// Presentation Definitions are composed of inputs, which describe the forms and details of the
/// proofs they require, and optional sets of selection rules, to allow [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder)s flexibility
/// in cases where different types of proofs may satisfy an input requirement.
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition)
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentationDefinition {
    id: String,
    input_descriptors: Vec<InputDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    submission_requirements: Option<Vec<SubmissionRequirement>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    #[serde(default, skip_serializing_if = "ClaimFormatMap::is_empty")]
    format: ClaimFormatMap,
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
    pub fn add_input_descriptor(mut self, input_descriptor: InputDescriptor) -> Self {
        self.input_descriptors.push(input_descriptor);

        self
    }

    /// Return the input descriptors of the presentation definition.
    pub fn input_descriptors(&self) -> &Vec<InputDescriptor> {
        &self.input_descriptors
    }

    /// Return the input descriptors as a mapping of the input descriptor id to the input descriptor.
    pub fn input_descriptors_map(&self) -> HashMap<&str, &InputDescriptor> {
        self.input_descriptors
            .iter()
            .map(|input_descriptor| (input_descriptor.id.as_str(), input_descriptor))
            .collect()
    }

    /// Return a mutable reference to the input descriptors of the presentation definition.
    pub fn input_descriptors_mut(&mut self) -> &mut Vec<InputDescriptor> {
        &mut self.input_descriptors
    }

    /// Set the submission requirements of the presentation definition.
    pub fn set_submission_requirements(
        mut self,
        submission_requirements: Vec<SubmissionRequirement>,
    ) -> Self {
        self.submission_requirements = Some(submission_requirements);
        self
    }

    /// Return the submission requirements of the presentation definition.
    pub fn submission_requirements(&self) -> Option<&Vec<SubmissionRequirement>> {
        self.submission_requirements.as_ref()
    }

    /// Return a mutable reference to the submission requirements of the presentation definition.
    pub fn submission_requirements_mut(&mut self) -> Option<&mut Vec<SubmissionRequirement>> {
        self.submission_requirements.as_mut()
    }

    /// Add a new submission requirement to the presentation definition.
    pub fn add_submission_requirement(
        mut self,
        submission_requirement: SubmissionRequirement,
    ) -> Self {
        self.submission_requirements
            .get_or_insert_with(Vec::new)
            .push(submission_requirement);
        self
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
    pub fn set_format(mut self, format: ClaimFormatMap) -> Self {
        self.format = format;
        self
    }

    /// Add a new format to the presentation definition.
    pub fn add_format(mut self, key: ClaimFormatDesignation, value: ClaimFormatPayload) -> Self {
        self.format.insert(key, value);
        self
    }

    /// Return the format of the presentation definition.
    pub fn format(&self) -> &ClaimFormatMap {
        &self.format
    }

    /// Check whether a format exists for the presentation definition or
    /// any of the input descriptors.
    pub fn contains_format(&self, format: impl Into<ClaimFormatDesignation>) -> bool {
        let format = format.into();

        // Check input descriptors.
        for descriptor in self.input_descriptors().iter() {
            if descriptor.format.contains_key(&format) {
                // return early if the format is included in an
                // input descriptor.
                return true;
            }
        }

        // Lastly, check the presentation definition itself for the
        // format.
        self.format().contains_key(&format)
    }

    /// Returns the requested fields of a given JSON-encoded credential
    /// that match the constraint fields of the input descriptors of the
    /// presentation definition.
    pub fn requested_fields<'a>(
        &self,
        credential: &'a serde_json::Value,
    ) -> Vec<RequestedField<'a>> {
        self.input_descriptors
            .iter()
            .flat_map(|descriptor| descriptor.requested_fields(credential))
            .collect()
    }

    /// Return the credential types requested in the presentation definition,
    /// if any.
    pub fn credential_types_hint(&self) -> Vec<CredentialType> {
        self.input_descriptors
            .iter()
            .flat_map(|descriptor| descriptor.credential_types_hint())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SubmissionRequirementObject {
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, serde_json::Value>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SubmissionRequirementBase {
    From {
        from: GroupId,
        #[serde(flatten)]
        submission_requirement_base: SubmissionRequirementObject,
    },
    FromNested {
        from_nested: Vec<SubmissionRequirement>,
        #[serde(flatten)]
        submission_requirement_base: SubmissionRequirementObject,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum SubmissionRequirement {
    All(SubmissionRequirementBase),
    Pick(SubmissionRequirementPick),
}

impl SubmissionRequirement {
    // Internal method to group the submission requirement,
    // based on the `from` or recurse the `from_nested` field.
    fn validate_group<T>(
        group: &GroupId,
        definition: &PresentationDefinition,
        inputs: &MatchingInputs<T>,
        pick: Option<&SubmissionRequirementPick>,
    ) -> Result<(), SubmissionValidationError> {
        // Group all the input descriptors according to the matching groups of this submission requirement.
        let grouped_input_descriptors = definition
            .input_descriptors
            .iter()
            .filter_map(|input_descriptor| {
                if input_descriptor.groups.contains(group) {
                    Some(input_descriptor.id.as_str())
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();

        match pick {
            Some(pick) => {
                // Filter for the descriptor maps that match the grouped input descriptors.
                let group_count = inputs
                    .inputs
                    .iter()
                    .filter(|input| grouped_input_descriptors.contains(input.descriptor_id))
                    .count();

                if let Some(min_count) = pick.min {
                    if group_count < min_count {
                        return Err(SubmissionValidationError::SelectionTooSmall {
                            group: group.clone(),
                            min: min_count,
                            found: group_count,
                        });
                    }
                }

                if let Some(max_count) = pick.max {
                    if group_count > max_count {
                        return Err(SubmissionValidationError::SelectionTooLarge {
                            group: group.clone(),
                            max: max_count,
                            found: group_count,
                        });
                    }
                }

                if let Some(count) = pick.count {
                    if group_count != count {
                        return Err(SubmissionValidationError::SelectionSizeMismatch {
                            group: group.clone(),
                            expected: count,
                            found: group_count,
                        });
                    }
                }
            }
            None => {
                for id in grouped_input_descriptors {
                    if !inputs.by_descriptor.contains_key(id) {
                        return Err(SubmissionValidationError::MissingRequiredInput(
                            id.to_owned(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate a submission requirement against a input descriptors and descriptor maps.
    pub fn validate<T>(
        &self,
        definition: &PresentationDefinition,
        inputs: &MatchingInputs<T>,
    ) -> Result<(), SubmissionValidationError> {
        // Validate the submission requirement against the grouped descriptor maps.
        match self {
            SubmissionRequirement::All(base) => match base {
                SubmissionRequirementBase::From { from, .. } => {
                    return Self::validate_group(from, definition, inputs, None);
                }
                SubmissionRequirementBase::FromNested { from_nested, .. } => {
                    for requirement in from_nested {
                        requirement.validate(definition, inputs)?;
                    }
                }
            },
            SubmissionRequirement::Pick(pick) => match &pick.submission_requirement {
                SubmissionRequirementBase::From { from, .. } => {
                    return Self::validate_group(from, definition, inputs, Some(pick));
                }
                SubmissionRequirementBase::FromNested { from_nested, .. } => {
                    for requirement in from_nested {
                        requirement.validate(definition, inputs)?;
                    }
                }
            },
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SubmissionRequirementPick {
    #[serde(flatten)]
    pub submission_requirement: SubmissionRequirementBase,
    pub count: Option<usize>,
    pub min: Option<usize>,
    pub max: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;

    #[test]
    fn test_input_descriptor_multi_credential_types_pattern() -> Result<()> {
        let definition: PresentationDefinition = serde_json::from_str(include_str!(
            "../../tests/presentation-definition/multi-credential-pattern.json"
        ))?;

        let credentials = definition.credential_types_hint();

        assert!(credentials.contains(&"PassportCredential".into()));
        assert!(credentials.contains(&"DriversLicenseCredential".into()));
        assert!(credentials.contains(&"NationalIDCredential".into()));

        Ok(())
    }

    #[test]
    fn test_input_descriptor_multi_credential_types_array() -> Result<()> {
        let definition: PresentationDefinition = serde_json::from_str(include_str!(
            "../../tests/presentation-definition/multi-credential-array.json"
        ))?;

        let credentials = definition.credential_types_hint();

        assert!(credentials.contains(&"IdentityCredential".into()));
        assert!(credentials.contains(&"EducationalCredential".into()));

        Ok(())
    }
}
