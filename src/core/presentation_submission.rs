use std::{borrow::Cow, collections::HashMap};

use super::{
    credential_format::*, input_descriptor::*, object::TypedParameter,
    presentation_definition::PresentationDefinition,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use serde_json_path::JsonPath;

/// A DescriptorMapId is a unique identifier for a DescriptorMap.
pub type DescriptorMapId = String;

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
    definition_id: DescriptorMapId,
    descriptor_map: Vec<DescriptorMap>,
}

impl TypedParameter for PresentationSubmission {
    const KEY: &'static str = "presentation_submission";
}

impl PresentationSubmission {
    /// The presentation submission MUST contain an id property. The value of this property MUST be a unique identifier, i.e. a UUID.
    ///
    /// The presentation submission object MUST contain a `definition_id` property.
    /// The value of this property MUST be the id value of a valid [PresentationDefinition::id()].
    ///
    /// The object MUST include a `descriptor_map` property. The value of this property MUST be an array of
    /// Input [DescriptorMap] Objects.
    pub fn new(
        id: uuid::Uuid,
        definition_id: DescriptorMapId,
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

    /// Returns the descriptor map as a mapping of descriptor map id to descriptor map.
    ///
    /// The descriptor map id is expected to match the id of the input descriptor.
    /// This mapping is helpful for checking if an input descriptor has an associated descriptor map,
    /// using this mapping from the presentation submission.
    pub fn descriptor_map_by_id(
        &self,
    ) -> std::collections::HashMap<DescriptorMapId, &DescriptorMap> {
        self.descriptor_map
            .iter()
            .map(|descriptor_map| (descriptor_map.id.clone(), descriptor_map))
            .collect()
    }

    /// Find all the submission inputs in `value` matching the input descriptors
    /// specified in the presentation `definition`.
    pub fn find_inputs<T>(
        &self,
        definition: &PresentationDefinition,
        value: &serde_json::Value,
        decoder: &impl ClaimsDecoder<T>,
    ) -> Result<MatchingInputs<T>, SubmissionError> {
        let mut inputs = Vec::new();
        for d in &self.descriptor_map {
            d.find_inputs(definition, value, decoder, &mut inputs)?;
        }

        let mut by_descriptor: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, input) in inputs.iter().enumerate() {
            by_descriptor
                .entry(input.descriptor_id)
                .or_default()
                .push(i);
        }

        Ok(MatchingInputs {
            inputs,
            by_descriptor,
        })
    }

    /// Find all the submission inputs in `value` matching the input descriptor
    /// specified in the presentation `definition`, and validate them.
    pub fn find_and_validate_inputs<T>(
        &self,
        definition: &PresentationDefinition,
        value: &serde_json::Value,
        decoder: &impl ClaimsDecoder<T>,
    ) -> Result<MatchingInputs<T>, SubmissionError> {
        let matches = self.find_inputs(definition, value, decoder)?;
        matches.validate(definition)?;
        Ok(matches)
    }
}

/// Submission inputs matching the presentation definition.
pub struct MatchingInputs<'a, T> {
    /// List of inputs.
    pub inputs: Vec<DecodedInput<'a, T>>,

    /// Inputs grouped by input descriptor id.
    pub by_descriptor: HashMap<&'a str, Vec<usize>>,
}

impl<T> MatchingInputs<'_, T> {
    /// Validate the inputs against the presentation definition requirements.
    pub fn validate(
        &self,
        definition: &PresentationDefinition,
    ) -> Result<(), SubmissionValidationError> {
        match definition.submission_requirements() {
            Some(requirements) => {
                for r in requirements {
                    r.validate(definition, self)?
                }
            }
            None => {
                // By default each input descriptor must have at least one
                // associated input.
                for d in definition.input_descriptors() {
                    if self
                        .by_descriptor
                        .get(d.id.as_str())
                        .is_none_or(|i| i.is_empty())
                    {
                        return Err(SubmissionValidationError::MissingRequiredInput(
                            d.id.clone(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

impl TryFrom<Json> for PresentationSubmission {
    type Error = anyhow::Error;

    fn try_from(raw: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(raw.clone()).map_err(Into::into)
    }
}

impl From<PresentationSubmission> for Json {
    fn from(value: PresentationSubmission) -> Self {
        serde_json::to_value(value)
            // SAFETY: by definition, a presentation submission has a valid
            //         JSON representation.
            .unwrap()
    }
}

/// Descriptor Maps are objects used to describe the information a [Holder](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder) provides to a [Verifier](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier).
///
/// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DescriptorMap {
    pub id: DescriptorMapId,
    pub format: ClaimFormatDesignation,
    pub path: JsonPath,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_nested: Option<Box<DescriptorMap>>,
}

impl DescriptorMap {
    /// The descriptor map MUST include an `id` property. The value of this property MUST be a string that matches the `id` property of the [InputDescriptor::id()] in the [PresentationDefinition] that this [PresentationSubmission] is related to.
    ///
    /// The descriptor map object MUST include a `format` property. The value of this property MUST be a string that matches one of the [ClaimFormatDesignation]. This denotes the data format of the [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim).
    ///
    /// The descriptor map object MUST include a `path` property. The value of this property MUST be a [JSONPath](https://goessner.net/articles/JsonPath/) string expression. The path property indicates the [Claim](https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim) submitted in relation to the identified [InputDescriptor], when executed against the top-level of the object the [PresentationSubmission] is embedded within.
    ///
    /// For more information, see: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
    pub fn new(
        id: impl Into<DescriptorMapId>,
        format: impl Into<ClaimFormatDesignation>,
        path: JsonPath,
    ) -> Self {
        Self {
            id: id.into(),
            format: format.into(),
            path,
            path_nested: None,
        }
    }

    /// Set the nested path of the descriptor map.
    ///
    /// The format of a path_nested object mirrors that of a [DescriptorMap] property. The nesting may be any number of levels deep.
    /// The `id` property MUST be the same for each level of nesting.
    ///
    /// > The path property inside each `path_nested` property provides a relative path within a given nested value.
    ///
    /// See: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries](https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries)
    pub fn set_path_nested(mut self, mut path_nested: DescriptorMap) -> Self {
        // Ensure the nested path has the same id as the parent.
        path_nested.id.clone_from(&self.id);

        self.path_nested = Some(Box::new(path_nested));

        self
    }

    /// Find all the submission inputs in `value` matching the input descriptors
    /// specified in the presentation `definition`.
    ///
    /// Inputs are added to the list of decoded `inputs` provided in argument.
    /// Returns an array of indices referencing the inputs added into `inputs`
    /// by this descriptor map directly. Some more inputs may be added
    /// indirectly from nested descriptor maps. The index of nested inputs will
    /// be stored in the `nested` field of the parent `DecodedInput`.
    ///
    /// See: <https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries>
    pub fn find_inputs<'a, T>(
        &'a self,
        definition: &PresentationDefinition,
        value: &serde_json::Value,
        decoder: &impl ClaimsDecoder<T>,
        inputs: &mut Vec<DecodedInput<'a, T>>,
    ) -> Result<Vec<usize>, SubmissionError> {
        let input_descriptors = definition.input_descriptors_map();
        self.find_inputs_with(definition, &input_descriptors, value, decoder, inputs)
    }

    /// Find all the submission inputs in `value` matching the input descriptors
    /// specified in the presentation `definition`.
    ///
    /// This is the same as `find_inputs` but takes the presentation
    /// definition's input descriptor map as parameter.
    ///
    /// See: <https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries>
    fn find_inputs_with<'a, T>(
        &'a self,
        def: &PresentationDefinition,
        input_descriptors: &HashMap<&str, &InputDescriptor>,
        value: &serde_json::Value,
        decoder: &impl ClaimsDecoder<T>,
        inputs: &mut Vec<DecodedInput<'a, T>>,
    ) -> Result<Vec<usize>, SubmissionError> {
        let mut result = Vec::new();

        let input_desc = input_descriptors
            .get(self.id.as_str())
            .ok_or_else(|| SubmissionError::UndefinedInputDescriptor(self.id.clone()))?;

        // Find the appropriate format constraints, if any.
        let format_constraint = match input_desc.format.get(&self.format) {
            Some(format_constraint) => Some(format_constraint),
            None => {
                if input_desc.format.is_empty() {
                    match def.format().get(&self.format) {
                        Some(f) => Some(f),
                        None => {
                            if def.format().is_empty() {
                                None
                            } else {
                                return Err(SubmissionError::FormatMismatch(self.format.clone()));
                            }
                        }
                    }
                } else {
                    return Err(SubmissionError::FormatMismatch(self.format.clone()));
                }
            }
        };

        for encoded_item in self.path.query(value) {
            let (decoded_item, decoded_json) =
                decoder.decode(encoded_item, &self.format, format_constraint)?;

            if !input_desc.constraints.is_empty() {
                let decoded_json = decoded_json
                    .as_deref()
                    .ok_or_else(|| SubmissionError::NestingUnsupported(self.format.clone()))?;

                if !input_desc.constraints.matches(decoded_json) {
                    continue;
                }
            }

            let nested = match &self.path_nested {
                Some(nested_descriptor) => {
                    let decoded_json = decoded_json
                        .as_deref()
                        .ok_or_else(|| SubmissionError::NestingUnsupported(self.format.clone()))?;

                    let nested = nested_descriptor.find_inputs_with(
                        def,
                        input_descriptors,
                        decoded_json,
                        decoder,
                        inputs,
                    )?;

                    if nested.is_empty() {
                        continue;
                    }

                    nested
                }
                None => Vec::new(),
            };

            let nested = group_by_input_descriptor(inputs, nested);

            let i = inputs.len();
            inputs.push(DecodedInput {
                descriptor_id: &self.id,
                format: &self.format,
                value: decoded_item,
                nested,
            });
            result.push(i);
        }

        Ok(result)
    }
}

/// Presentation submission error.
#[derive(Debug, thiserror::Error)]
pub enum SubmissionError {
    /// Claim decoding failed.
    #[error("claim decoding failed: {0}")]
    Decoding(#[from] ClaimDecodingError),

    /// Nesting is not supported for a given claim format.
    #[error("nesting is not supported for claim format {0}")]
    NestingUnsupported(ClaimFormatDesignation),

    /// Submission contains inputs that are not defined in the presentation
    /// definition.
    #[error("undefined input descriptor: {0}")]
    UndefinedInputDescriptor(String),

    /// Input format does not match the format expected by the presentation
    /// definition.
    #[error("format mismatch: unexpected format {0}")]
    FormatMismatch(ClaimFormatDesignation),

    /// Input validation failed.
    #[error("presentation submission validation failed: {0}")]
    Validation(#[from] SubmissionValidationError),
}

/// Presentation submission inputs validation error.
#[derive(Debug, thiserror::Error)]
pub enum SubmissionValidationError {
    /// Missing an input required by the presentation definition.
    #[error("missing required input `{0}`")]
    MissingRequiredInput(String),

    /// Input group selection is too small.
    #[error("not enough inputs for group `{group}` (expected at least {min}, found {found})")]
    SelectionTooSmall {
        group: GroupId,
        min: usize,
        found: usize,
    },

    /// Input group selection is too large.
    #[error("too many inputs for group `{group}` (expected at most {max}, found {found})")]
    SelectionTooLarge {
        group: GroupId,
        max: usize,
        found: usize,
    },

    /// Input group selection is of the wrong size.
    #[error("invalid number of inputs for group `{group}` (expected {expected}, found {found})")]
    SelectionSizeMismatch {
        group: GroupId,
        expected: usize,
        found: usize,
    },
}

/// OID4VP claims decoder.
///
/// When extracting a presentation submission's inputs, inputs must be decoded
/// in order to be validated and for nested descriptor to be processed.
/// Since different applications can support different claim formats, this trait
/// abstracts the decoding capabilities of the application.
pub trait ClaimsDecoder<T> {
    /// Decodes a JSON value according to the given format.
    ///
    /// Optional format constraints can be provided.
    ///
    /// Returns the decoded claim, and a JSON representation of the decoded
    /// claims (if any). The JSON representation is used for nested descriptor
    /// map to be processed.
    fn decode<'a>(
        &self,
        value: &'a serde_json::Value,
        format: &ClaimFormatDesignation,
        format_constraint: Option<&ClaimFormatPayload>,
    ) -> Result<(T, Option<Cow<'a, serde_json::Value>>), ClaimDecodingError>;
}

pub struct NoClaimsDecoder;

impl ClaimsDecoder<()> for NoClaimsDecoder {
    fn decode<'a>(
        &self,
        value: &'a serde_json::Value,
        _format: &ClaimFormatDesignation,
        _format_constraint: Option<&ClaimFormatPayload>,
    ) -> Result<((), Option<Cow<'a, serde_json::Value>>), ClaimDecodingError> {
        Ok(((), Some(Cow::Borrowed(value))))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimDecodingError {
    #[error("unknown claim format: {0}")]
    UnknownFormat(ClaimFormatDesignation),

    #[error("invalid claim: {0}")]
    Invalid(String),
}

impl ClaimDecodingError {
    pub fn invalid(e: impl ToString) -> Self {
        Self::Invalid(e.to_string())
    }
}

/// Groups a set of input indexes by input descriptor id.
fn group_by_input_descriptor<'a, T>(
    claims: &[DecodedInput<'a, T>],
    indexes: Vec<usize>,
) -> HashMap<&'a str, Vec<usize>> {
    let mut map: HashMap<&'a str, Vec<usize>> = HashMap::new();

    for i in indexes {
        let d = claims[i].descriptor_id;
        map.entry(d).or_default().push(i);
    }

    map
}

/// Decoded submission input.
pub struct DecodedInput<'a, T> {
    /// Input descriptor id.
    pub descriptor_id: &'a str,

    /// Claim format.
    pub format: &'a ClaimFormatDesignation,

    /// Decoded value.
    pub value: T,

    /// Nested inputs.
    ///
    /// This maps each descriptor id to a list of indexes referencing inputs
    /// that are found nested in this input.
    ///
    /// For instance, if this input is a Verifiable Presentation, and the
    /// presentation definition also specifies an input descriptor `credential`
    /// for a Verifiable Credential, then this map will include an entry
    /// `("credential", vec![n])` where `n` is the index of the decoded
    /// Verifiable Credential input.
    pub nested: HashMap<&'a str, Vec<usize>>,
}
