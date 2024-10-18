use super::credential_format::*;
use super::input_descriptor::*;
use super::presentation_submission::*;

use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Map;
use ssi::claims::jwt::VerifiablePresentation;

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
    pub fn input_descriptors_map(&self) -> HashMap<String, &InputDescriptor> {
        self.input_descriptors
            .iter()
            .map(|input_descriptor| (input_descriptor.id().to_string(), input_descriptor))
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

    /// Validate submission requirements provided an input descriptor and descriptor map.
    pub fn validate_submission_requirements(&self, descriptor_map: &[DescriptorMap]) -> Result<()> {
        match self.submission_requirements.as_ref() {
            None => Ok(()),
            Some(requirements) => {
                for requirement in requirements {
                    requirement.validate(self.input_descriptors(), descriptor_map)?;
                }
                Ok(())
            }
        }
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
            if descriptor.format().contains_key(&format) {
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
    pub fn requested_fields(&self, credential: &serde_json::Value) -> Vec<RequestedField> {
        let mut selector = jsonpath_lib::selector(credential);

        self.input_descriptors
            .iter()
            .flat_map(|descriptor| descriptor.requested_fields(&mut selector))
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

    /// Validate a presentation submission against the presentation definition.
    ///
    /// This descriptor map is a map of descriptor objects, keyed by their id.
    ///
    /// For convenience, use [PresentationSubmission::descriptor_map_by_id] to generate this map.
    ///
    /// Internally, this method will call [PresentationDefinition::validate_submission_requirements].
    pub fn validate_presentation(
        &self,
        verifiable_presentation: VerifiablePresentation,
        descriptor_map: &[DescriptorMap],
    ) -> Result<()> {
        // Validate the submission requirements. This will
        // no-op if there are no submission requirements.
        self.validate_submission_requirements(descriptor_map)?;

        let input_descript_map = self.input_descriptors_map();

        // Validate the submission requirements

        for descriptor in descriptor_map.iter() {
            match input_descript_map.get(descriptor.id()) {
                None => {
                    bail!(
                        "Descriptor map ID, {}, does not match a valid input descriptor.",
                        descriptor.id()
                    )
                }
                Some(input_descriptor) => {
                    input_descriptor
                        .validate_verifiable_presentation(&verifiable_presentation, descriptor)?;
                }
            }
        }

        Ok(())
    }

    /// Validate a JSON-encoded credential against the presentation definition.
    ///
    /// NOTE: this method accepts a generic serde_json::Value argument and checks whether
    /// the JSON value conforms to the presentation definition's input descriptor constraint
    /// fields.
    ///
    /// If the credential satisifies the presentation definition, this method will return true.
    pub fn check_credential_validation(&self, credential: &serde_json::Value) -> bool {
        let mut selector = jsonpath_lib::selector(credential);

        self.input_descriptors()
            .iter()
            .flat_map(|descriptor| descriptor.constraints().fields())
            // skip optional fields
            .filter(|field| field.is_required())
            .all(|field| {
                match field.validator() {
                    Some(validator) => {
                        let is_valid = field
                            .path()
                            .iter()
                            // NOTE: Errors are ignored to allow other paths to
                            // be checked. Interested in whether there is at least
                            // one valid path.
                            //
                            // An empty iterator will return false on an any() call.
                            .filter_map(|path| selector(path).ok())
                            .flatten()
                            // NOTE: This is currently assuming that if any of the paths are a match
                            // to the credential, then the validation is, at least partially, successful,
                            // and the credential may satisfy the presentation definition.
                            .any(|value| validator.validate(value).is_ok());

                        is_valid
                    }
                    // Allow for fields without validators to pass through.
                    _ => true,
                }
            })
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
    fn validate_group(
        group: &GroupId,
        input_descriptors: &[InputDescriptor],
        decriptor_map: &[DescriptorMap],
        options: Option<&SubmissionRequirementPick>,
    ) -> Result<()> {
        // Group all the input descriptors according to the matching groups of this submission requirement.
        let grouped_input_descriptors = input_descriptors
            .iter()
            .filter(|input_descriptor| input_descriptor.groups().contains(group))
            .collect::<Vec<&InputDescriptor>>();

        // Filter for the descriptor maps that match the grouped input descriptors.
        let group_count = decriptor_map
            .iter()
            .filter(|descriptor| {
                grouped_input_descriptors
                    .iter()
                    .any(|input_descriptor| input_descriptor.id() == descriptor.id())
            })
            .count();

        if let Some(opts) = options {
            if let Some(min_count) = opts.min {
                if group_count < min_count {
                    bail!("Submission Requirement validation failed. Descriptor Map count {group_count} is less than the minimum count: {min_count}.");
                }
            }

            if let Some(max_count) = opts.max {
                if group_count > max_count {
                    bail!("Submission Requirement validation failed. Descriptor Map count {group_count} is greater than the maximum count: {max_count}.");
                }
            }

            if let Some(count) = opts.count {
                if group_count != count {
                    bail!("Submission Requirement group, {group}, validation failed. Descriptor Map count {group_count} is not equal to the count: {count}.");
                }
            }
        } else {
            // If the descriptor maps are less than the grouped input descriptors,
            // then the submission requirement is not satisfied.
            if group_count < grouped_input_descriptors.len() {
                bail!("Submission Requirement group, {group}, validation failed. Descriptor Map count {group_count} is not equal to the count of grouped input descriptors: {}.", grouped_input_descriptors.len());
            }
        }

        Ok(())
    }

    /// Validate a submission requirement against a input descriptors and descriptor maps.
    pub fn validate(
        &self,
        input_descriptors: &[InputDescriptor],
        decriptor_map: &[DescriptorMap],
    ) -> Result<()> {
        // Validate the submission requirement against the grouped descriptor maps.
        match self {
            SubmissionRequirement::All(base) => match base {
                SubmissionRequirementBase::From { from, .. } => {
                    return Self::validate_group(from, input_descriptors, decriptor_map, None);
                }
                SubmissionRequirementBase::FromNested { from_nested, .. } => {
                    for requirement in from_nested {
                        requirement.validate(input_descriptors, decriptor_map)?;
                    }
                }
            },
            SubmissionRequirement::Pick(pick) => match &pick.submission_requirement {
                SubmissionRequirementBase::From { from, .. } => {
                    return Self::validate_group(
                        from,
                        input_descriptors,
                        decriptor_map,
                        Some(pick),
                    );
                }
                SubmissionRequirementBase::FromNested { from_nested, .. } => {
                    for requirement in from_nested {
                        requirement.validate(input_descriptors, decriptor_map)?;
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
