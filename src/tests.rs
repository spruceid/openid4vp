use crate::core::{
    presentation_definition::{PresentationDefinition, SubmissionRequirement},
    presentation_submission::*,
};

use std::{
    ffi::OsStr,
    fs::{self, File},
};

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use serde_json::Value;
use ssi_claims::jwt::VerifiablePresentation;

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

#[test]
fn test_input_descriptor_validation() -> Result<()> {
    // Include the `input_descriptors_example.json` file in the `examples` directory.
    let input_descriptors = include_str!(
        "../tests/presentation-exchange/test/presentation-definition/input_descriptors_example.json"
    );

    println!("Input Descriptors: {:?}", input_descriptors);
    let mut value: Value = serde_json::from_str(input_descriptors)?;

    let presentation_definition: PresentationDefinition = value
        .as_object_mut()
        .map(|obj| {
            obj.remove("presentation_definition")
                .map(|v| serde_json::from_value(v))
        })
        .flatten()
        .expect("failed to parse presentation definition")?;

    println!("Presentation Definition: {:?}", presentation_definition);

    let presentation_submission = include_str!(
        "../tests/presentation-exchange/test/presentation-submission/appendix_VP_example.json"
    );

    println!("Presentation Submission: {:?}", presentation_submission);

    let value: Value = serde_json::from_str(presentation_submission)?;

    let presentation_submission: PresentationSubmission = value
        .as_object()
        .map(|obj| {
            obj.get("presentation_submission")
                .map(|v| serde_json::from_value(v.clone()))
        })
        .flatten()
        .expect("failed to parse presentation submission")?;

    println!("Presentation Submission: {:?}", presentation_submission);

    let descriptor_map = presentation_submission.descriptor_map_by_id();

    let verifiable_presentation: VerifiablePresentation = serde_json::from_value(value)?;

    println!("Verifiable Presentation: {verifiable_presentation:?}");

    presentation_definition
        .validate_definition_map(verifiable_presentation, &descriptor_map)
        .expect("Failed to validate definition map");

    Ok(())
}
