use crate::utils::Error;

use crate::{
    presentation_exchange::{
        Constraints, ConstraintsField, ConstraintsLimitDisclosure, InputDescriptor,
        PresentationDefinition,
    },
    utils::NonEmptyVec,
};
use serde_json::json;

pub enum CredentialFormat {
    MDOC,
    VC,
}

//TODO: Make a presentation definition builder
// input are the fields that should be challenged for and the format of the presentation definition. Does an automatic filter on the doctype and namespace

fn mdl_presentation_definition(
    requested_fields: Vec<&str>,
) -> Result<PresentationDefinition, Error> {
    //let mut input_descriptor = InputDescriptor {};
    let fmt = "mdoc.";

    let format = json!({
    "mso_mdoc": {
        "alg": [
            "EdDSA",
            "ES256"
        ]
    }});

    let doc_type_filter = json!({
        "type": "string",
        "const": "org.iso.18013.5.1"
    });

    let namespace_filter = json!({
        "type": "string",
        "const": "org.iso.18013.5.1.mDL"
    });

    let mut fields: Vec<ConstraintsField> = vec![];

    fields.push(ConstraintsField {
        path: NonEmptyVec::new(format!("{}{}", fmt, "doc_type")),
        id: None,
        purpose: None,
        name: None,
        filter: Some(doc_type_filter),
        optional: None,
        intent_to_retain: None,
    });

    fields.push(ConstraintsField {
        path: NonEmptyVec::new(format!("{}{}", fmt, "namespace")),
        id: None,
        purpose: None,
        name: None,
        filter: Some(namespace_filter),
        optional: None,
        intent_to_retain: None,
    });

    requested_fields.iter().for_each(|&f| {
        fields.push(ConstraintsField::new(
            NonEmptyVec::new(format!("{}{}", fmt, f)),
            None,
            None,
            None,
            None,
            None,
            Some(false),
        ))
    });

    let constraints = Constraints {
        limit_disclosure: Some(ConstraintsLimitDisclosure::Required),
        fields: Some(fields),
    };

    let input_descriptor = InputDescriptor {
        id: "mDL".to_string(),
        name: None,
        purpose: None,
        format: Some(format),
        constraints: Some(constraints),
        schema: None,
    };

    Ok(PresentationDefinition {
        id: "OID4VP Demo Req".to_string(),
        input_descriptors: vec![input_descriptor],
        name: None,
        purpose: None,
        format: None,
    })
}
