use serde::Deserialize;

// use crate::core::response::AuthorizationResponse;
// pub use crate::utils::NonEmptyVec;

// use anyhow::{bail, Context, Result};
// use jsonschema::{JSONSchema, ValidationError};

// use serde_json::Map;
// use ssi_claims::jwt::VerifiablePresentation;
// use ssi_dids::ssi_json_ld::syntax::from_value;

use crate::core::{presentation_definition::PresentationDefinition, presentation_submission::*};

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
    let paths = fs::read_dir("tests/presentation-exchange/test/presentation-definition").unwrap();
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
        println!("{} -> ", path.file_name().unwrap().to_str().unwrap());
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
    let paths = fs::read_dir("tests/presentation-exchange/test/presentation-submission").unwrap();
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
        println!("{} -> ", path.file_name().unwrap().to_str().unwrap());
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
    let paths = fs::read_dir("tests/presentation-exchange/test/submission-requirements").unwrap();
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
