use crate::utils::NonEmptyVec;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// TODO does openidconnect have a Request type?
#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseRequest {
    id_token: serde_json::Value, // IdTokenSIOP, // CoreIdTokenClaims,
    vp_token: VpToken,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdlVpToken {
    pub presentation_submission: PresentationSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpTokenIdToken {
    pub presentation_submission: PresentationSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpToken {
    pub presentation_definition: PresentationDefinition,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestObject {
    pub presentation_definition: PresentationDefinition,
    pub presentation_definition_uri: Option<String>,
    pub client_id_scheme: Option<String>,
    pub client_metadata: Option<Value>,
    pub client_metadata_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentationDefinition {
    pub id: String, // Uuid,
    pub input_descriptors: Vec<InputDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<serde_json::Value>, // TODO
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputDescriptor {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<serde_json::Value>, // TODO
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>, // TODO shouldn't be optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>, // TODO shouldn't exist anymore
}

// TODO must have at least one
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Constraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<ConstraintsField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_disclosure: Option<ConstraintsLimitDisclosure>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintsField {
    pub path: NonEmptyVec<String>, // TODO JsonPath validation at deserialization time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>, // TODO JSONSchema validation at deserialization time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

pub type ConstraintsFields = Vec<ConstraintsField>;

impl ConstraintsField {
    pub fn new(
        path: NonEmptyVec<String>,
        id: Option<String>,
        purpose: Option<String>,
        name: Option<String>,
        filter: Option<serde_json::Value>,
        optional: Option<bool>,
        intent_to_retain: Option<bool>,
    ) -> ConstraintsField {
        ConstraintsField {
            path,
            id,
            purpose,
            name,
            filter,
            optional,
            intent_to_retain,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConstraintsLimitDisclosure {
    Required,
    Preferred,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMap>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DescriptorMap {
    pub id: String,
    pub format: String, // TODO should be enum of supported formats
    pub path: String,
    pub path_nested: Option<Box<DescriptorMap>>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmissionRequirementBaseBase {
    _name: Option<String>,
    _purpose: Option<String>,
    #[serde(flatten)]
    _property_set: Option<Map<String, serde_json::Value>>,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum SubmissionRequirement {
    All(SubmissionRequirementBase),
    Pick(SubmissionRequirementPick),
}

#[derive(Serialize, Deserialize)]
pub struct SubmissionRequirementPick {
    #[serde(flatten)]
    _submission_requirement: SubmissionRequirementBase,
    _count: Option<u64>,
    _min: Option<u64>,
    _max: Option<u64>,
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
        let value = json!({
                "id_token": {
                    "email": null
                },
                "vp_token": {
                    "presentation_definition": {
                        "id": "vp token example",
                        "input_descriptors": [
                            {
                                "id": "id card credential",
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
                }
            }
        );
        let _: ResponseRequest = serde_path_to_error::deserialize(value)
            .map_err(|e| e.path().to_string())
            .unwrap();
        // assert_eq!(serde_json::to_value(res).unwrap(), value);
    }

    #[derive(Serialize, Deserialize)]
    pub struct PresentationDefinitionTest {
        presentation_definition: PresentationDefinition,
    }

    #[test]
    fn presentation_definition_suite() {
        let paths =
            fs::read_dir("test/presentation-exchange/test/presentation-definition").unwrap();
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

    // TODO use VP type?
    #[derive(Serialize, Deserialize)]
    pub struct PresentationSubmissionTest {
        presentation_submission: PresentationSubmission,
    }

    #[test]
    fn presentation_submission_suite() {
        let paths =
            fs::read_dir("test/presentation-exchange/test/presentation-submission").unwrap();
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

    #[derive(Serialize, Deserialize)]
    pub struct SubmissionRequirementsTest {
        submission_requirements: Vec<SubmissionRequirement>,
    }

    #[test]
    fn submission_requirements_suite() {
        let paths =
            fs::read_dir("test/presentation-exchange/test/submission-requirements").unwrap();
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
