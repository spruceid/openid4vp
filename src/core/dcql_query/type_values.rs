use serde_json::{Map, Value as Json};
use ssi::json_ld::{ContextLoader, Expand, IriBuf};

use super::{DcqlCredentialQuery, DcqlQuery};

pub const TYPE_VALUES: &str = "type_values";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypeValuesError {
    #[error("`type_values` must be a non-empty array of non-empty arrays of strings")]
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypeExpansionError {
    #[error("the credential is not a JSON object")]
    NotAnObject,
    #[error("failed to expand the credential: {0}")]
    Expansion(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialTypes {
    NotApplicable,
    W3c {
        expanded: Option<Vec<String>>,
        literal: Vec<String>,
    },
}

impl CredentialTypes {
    pub async fn from_w3c_vc(vc: &Json, loader: &ContextLoader) -> Self {
        Self::W3c {
            expanded: expand_types(vc, loader)
                .await
                .inspect_err(|e| tracing::warn!("failed to expand credential types: {e}"))
                .ok(),
            literal: literal_types(vc),
        }
    }

    pub fn has(&self, required: &str) -> bool {
        match self {
            Self::NotApplicable => false,
            Self::W3c { expanded, literal } => expanded
                .iter()
                .flatten()
                .chain(literal)
                .any(|ty| ty == required),
        }
    }
}

impl DcqlQuery {
    pub fn requests_type_values(&self) -> bool {
        self.credentials()
            .iter()
            .any(|query| query.meta().contains_key(TYPE_VALUES))
    }
}

impl DcqlCredentialQuery {
    pub fn type_values(&self) -> Option<Result<Vec<Vec<&str>>, TypeValuesError>> {
        self.meta()
            .get(TYPE_VALUES)
            .map(|value| parse_type_values(value).ok_or(TypeValuesError::Malformed))
    }

    pub fn satisfies_type_values(&self, types: &CredentialTypes) -> bool {
        let Some(alternatives) = self.type_values() else {
            return true;
        };

        if *types == CredentialTypes::NotApplicable {
            return true;
        }

        let Ok(alternatives) = alternatives else {
            tracing::warn!(
                "credential query {:?} has a malformed `type_values`",
                self.id()
            );
            return false;
        };

        alternatives
            .iter()
            .any(|required| required.iter().all(|t| types.has(t)))
    }
}

fn parse_type_values(value: &Json) -> Option<Vec<Vec<&str>>> {
    value
        .as_array()
        .filter(|alternatives| !alternatives.is_empty())?
        .iter()
        .map(|alternative| {
            alternative
                .as_array()
                .filter(|types| !types.is_empty())?
                .iter()
                .map(Json::as_str)
                .collect::<Option<Vec<_>>>()
        })
        .collect()
}

pub fn literal_types(vc: &Json) -> Vec<String> {
    ["type", "@type"]
        .iter()
        .filter_map(|key| vc.get(key))
        .flat_map(|value| match value {
            Json::Array(values) => values.iter().filter_map(Json::as_str).collect(),
            value => value.as_str().into_iter().collect::<Vec<_>>(),
        })
        .map(ToOwned::to_owned)
        .collect()
}

pub async fn expand_types(
    vc: &Json,
    loader: &ContextLoader,
) -> Result<Vec<String>, TypeExpansionError> {
    let root = vc.as_object().ok_or(TypeExpansionError::NotAnObject)?;

    let mut document = Map::new();
    for key in ["@context", "type", "@type"] {
        if let Some(value) = root.get(key) {
            document.insert(key.to_owned(), value.clone());
        }
    }

    let document = json_syntax::Value::from_serde_json(Json::Object(document));
    let expanded = Expand::<IriBuf>::expand(&document, loader)
        .await
        .map_err(|e| TypeExpansionError::Expansion(e.to_string()))?;

    Ok(expanded
        .iter()
        .find_map(|object| object.as_node())
        .map(|node| node.types().iter().map(|t| t.as_str().to_owned()).collect())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VC_V1: &str = "https://www.w3.org/2018/credentials/v1";
    const VC_V1_EXAMPLES: &str = "https://www.w3.org/2018/credentials/examples/v1";
    const VC_V2: &str = "https://www.w3.org/ns/credentials/v2";
    const VC: &str = "https://www.w3.org/2018/credentials#VerifiableCredential";

    fn query(meta: Json) -> DcqlCredentialQuery {
        serde_json::from_value(json!({ "id": "q", "format": "ldp_vc", "meta": meta })).unwrap()
    }

    fn spec_query() -> DcqlCredentialQuery {
        query(json!({
            "type_values": [
                [
                    VC,
                    "https://example.org/examples#AlumniCredential",
                    "https://example.org/examples#BachelorDegree"
                ],
                [VC, "https://example.org/examples#UniversityDegreeCredential"],
                ["IdentityCredential"]
            ]
        }))
    }

    async fn types(vc: Json) -> CredentialTypes {
        CredentialTypes::from_w3c_vc(&vc, &ContextLoader::default()).await
    }

    fn expanded_only(types: CredentialTypes) -> CredentialTypes {
        match types {
            CredentialTypes::W3c { expanded, .. } => CredentialTypes::W3c {
                expanded,
                literal: vec![],
            },
            types => types,
        }
    }

    #[tokio::test]
    async fn matches_the_spec_examples() {
        let query = spec_query();

        for ty in [
            json!(["VerifiableCredential", "UniversityDegreeCredential"]),
            json!(["VerifiableCredential", "BachelorDegree", "AlumniCredential"]),
        ] {
            let vc = json!({ "@context": [VC_V1, VC_V1_EXAMPLES], "type": ty });
            assert!(query.satisfies_type_values(&expanded_only(types(vc).await)));
        }

        let vc =
            json!({ "@context": [VC_V1], "type": ["VerifiableCredential", "IdentityCredential"] });
        assert!(query.satisfies_type_values(&expanded_only(types(vc).await)));
    }

    #[tokio::test]
    async fn every_type_of_an_alternative_must_be_present() {
        let vc = json!({
            "@context": [VC_V1, VC_V1_EXAMPLES],
            "type": ["VerifiableCredential", "AlumniCredential"]
        });
        assert!(!spec_query().satisfies_type_values(&types(vc).await));
    }

    #[tokio::test]
    async fn matches_terms_as_written() {
        let vc = json!({
            "@context": [VC_V1, VC_V1_EXAMPLES],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        });
        let types = types(vc).await;

        let terms = query(json!({
            "type_values": [["VerifiableCredential", "UniversityDegreeCredential"]]
        }));
        assert!(terms.satisfies_type_values(&types));
        assert!(!terms.satisfies_type_values(&expanded_only(types.clone())));

        let mixed = query(json!({ "type_values": [[VC, "UniversityDegreeCredential"]] }));
        assert!(mixed.satisfies_type_values(&types));
    }

    #[tokio::test]
    async fn expands_undefined_types_with_the_vocab() {
        let vc = json!({
            "@context": [VC_V2, { "@vocab": "https://example.org/vocab#" }],
            "type": ["VerifiableCredential", "IDCredential"]
        });
        let types = expanded_only(types(vc).await);

        let expanded = query(json!({
            "type_values": [[VC, "https://example.org/vocab#IDCredential"]]
        }));
        assert!(expanded.satisfies_type_values(&types));

        let relative = query(json!({ "type_values": [["IDCredential"]] }));
        assert!(!relative.satisfies_type_values(&types));
    }

    #[tokio::test]
    async fn unknown_context_matches_terms_only() {
        let vc = json!({
            "@context": [VC_V1, "https://example.com/unknown/v1"],
            "type": ["VerifiableCredential", "ExampleCredential"]
        });
        assert!(expand_types(&vc, &ContextLoader::default()).await.is_err());
        let types = types(vc).await;

        let terms = query(json!({ "type_values": [["ExampleCredential"]] }));
        assert!(terms.satisfies_type_values(&types));

        let expanded = query(json!({ "type_values": [[VC]] }));
        assert!(!expanded.satisfies_type_values(&types));
    }

    #[tokio::test]
    async fn non_object_credential_fails_expansion() {
        assert_eq!(
            expand_types(&json!(["VerifiableCredential"]), &ContextLoader::default()).await,
            Err(TypeExpansionError::NotAnObject)
        );
    }

    #[test]
    fn reads_a_single_type() {
        assert_eq!(
            literal_types(&json!({ "type": "VerifiableCredential" })),
            ["VerifiableCredential"]
        );
        assert_eq!(
            literal_types(&json!({ "@type": ["A"], "type": "B" })),
            ["B", "A"]
        );
    }

    #[test]
    fn absent_type_values_places_no_constraint() {
        for types in [
            CredentialTypes::NotApplicable,
            CredentialTypes::W3c {
                expanded: None,
                literal: vec![],
            },
        ] {
            assert!(query(json!({})).satisfies_type_values(&types));
        }
    }

    #[test]
    fn does_not_apply_to_other_formats() {
        let query = query(json!({ "type_values": [[VC]] }));
        assert!(query.satisfies_type_values(&CredentialTypes::NotApplicable));
    }

    #[test]
    fn malformed_type_values_matches_nothing() {
        let types = CredentialTypes::W3c {
            expanded: Some(vec![VC.to_owned()]),
            literal: vec!["VerifiableCredential".to_owned()],
        };
        for malformed in [
            json!([]),
            json!([[]]),
            json!([VC]),
            json!([[VC, 1]]),
            json!(VC),
        ] {
            let query = query(json!({ "type_values": malformed }));
            assert_eq!(
                query.type_values(),
                Some(Err(TypeValuesError::Malformed)),
                "{malformed}"
            );
            assert!(!query.satisfies_type_values(&types), "{malformed}");
        }
    }

    #[test]
    fn detects_type_values_in_any_query() {
        let without: DcqlQuery = serde_json::from_value(json!({
            "credentials": [{ "id": "a", "format": "ldp_vc", "meta": {} }]
        }))
        .unwrap();
        assert!(!without.requests_type_values());

        let with: DcqlQuery = serde_json::from_value(json!({
            "credentials": [
                { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["x"] } },
                { "id": "b", "format": "ldp_vc", "meta": { "type_values": [[VC]] } }
            ]
        }))
        .unwrap();
        assert!(with.requests_type_values());
    }
}
