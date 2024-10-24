use super::{credential_format::*, input_descriptor::*, object::TypedParameter};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

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
    id: DescriptorMapId,
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

    /// Return the id of the descriptor map.
    pub fn id(&self) -> &DescriptorMapId {
        &self.id
    }

    /// Return the format of the descriptor map.
    ///
    /// The value of this property MUST be a string that matches one of the
    /// [ClaimFormatDesignation]. This denotes the data format of the Claim.
    ///
    /// See: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
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
    /// > The path property inside each `path_nested` property provides a relative path within a given nested value.
    ///
    /// See: [https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries](https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries)
    pub fn set_path_nested(mut self, mut path_nested: DescriptorMap) -> Self {
        // Ensure the nested path has the same id as the parent.
        path_nested.id.clone_from(self.id());

        self.path_nested = Some(Box::new(path_nested));

        self
    }
}
