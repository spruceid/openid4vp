use std::collections::BTreeMap;

use base64::Engine;
use ciborium::Value as Cbor;
use openid4vp::core::{
    credential_format::ClaimFormatDesignation,
    dcql_query::{mdoc_path, CredentialTypes, DcqlCredentialQuery, DcqlQuery, SelectionError},
};
use serde_json::{json, Value as Json};
use ssi::json_ld::ContextLoader;

enum Stored {
    Json {
        format: ClaimFormatDesignation,
        w3c: bool,
        claims: Json,
    },
    Mdoc {
        doctype: String,
        namespaces: BTreeMap<String, BTreeMap<String, Cbor>>,
    },
}

struct Credential {
    id: &'static str,
    stored: Stored,
    types: CredentialTypes,
}

impl Credential {
    async fn json(id: &'static str, format: ClaimFormatDesignation, claims: Json) -> Self {
        let w3c = !matches!(format, ClaimFormatDesignation::DcSdJwt);
        let types = if w3c {
            CredentialTypes::from_w3c_vc(&claims, &ContextLoader::default()).await
        } else {
            CredentialTypes::NotApplicable
        };
        Self {
            id,
            stored: Stored::Json {
                format,
                w3c,
                claims,
            },
            types,
        }
    }

    fn mdoc(id: &'static str, doctype: &str, elements: &[(&str, &str, Cbor)]) -> Self {
        let mut namespaces: BTreeMap<String, BTreeMap<String, Cbor>> = BTreeMap::new();
        for (namespace, element, value) in elements {
            namespaces
                .entry(namespace.to_string())
                .or_default()
                .insert(element.to_string(), value.clone());
        }
        Self {
            id,
            stored: Stored::Mdoc {
                doctype: doctype.to_owned(),
                namespaces,
            },
            types: CredentialTypes::NotApplicable,
        }
    }

    fn satisfies(&self, query: &DcqlCredentialQuery) -> bool {
        let meta = query.meta();
        let format_and_meta = match &self.stored {
            Stored::Json {
                format,
                w3c,
                claims,
            } => {
                format == query.format()
                    && (*w3c
                        || meta
                            .get("vct_values")
                            .and_then(Json::as_array)
                            .is_none_or(|vcts| vcts.contains(&claims["vct"])))
            }
            Stored::Mdoc { doctype, .. } => {
                *query.format() == ClaimFormatDesignation::MsoMDoc
                    && meta.get("doctype_value").and_then(Json::as_str) == Some(doctype)
            }
        };

        format_and_meta
            && query.satisfies_type_values(&self.types)
            && match &self.stored {
                Stored::Json { claims, .. } => query.satisfies_json_claims(claims),
                Stored::Mdoc { namespaces, .. } => query.satisfies_claims(|claim| {
                    mdoc_path(claim.path())
                        .ok()
                        .and_then(|(namespace, element)| namespaces.get(namespace)?.get(element))
                        .is_some_and(|value| claim.matches_values(|v| v.matches_cbor(value)))
                }),
            }
    }
}

fn matches(dcql: &DcqlQuery, wallet: &[Credential]) -> BTreeMap<String, Vec<&'static str>> {
    dcql.credentials()
        .iter()
        .map(|query| {
            let ids = wallet
                .iter()
                .filter(|credential| credential.satisfies(query))
                .map(|credential| credential.id)
                .collect();
            (query.id().to_owned(), ids)
        })
        .collect()
}

fn fixture_jwt_vc() -> Json {
    let jwt = include_str!("examples/vc.jwt").trim();
    let payload = jwt.split('.').nth(1).unwrap();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice::<Json>(&payload).unwrap()["vc"].clone()
}

async fn wallet() -> Vec<Credential> {
    vec![
        Credential::json("jwt_fixture", ClaimFormatDesignation::JwtVcJson, fixture_jwt_vc()).await,
        Credential::json(
            "degree",
            ClaimFormatDesignation::LdpVc,
            json!({
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "credentialSubject": {
                    "degree": { "type": "BachelorDegree", "name": "Bachelor of Science and Arts" }
                }
            }),
        )
        .await,
        Credential::json(
            "registration",
            ClaimFormatDesignation::LdpVc,
            json!({
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    { "@vocab": "https://dmv.example/vocab#" }
                ],
                "type": ["VerifiableCredential", "VehicleRegistrationCredential"],
                "credentialSubject": { "licensePlateIdentifier": "2GKK061", "doors": 4 }
            }),
        )
        .await,
        Credential::json(
            "insurance",
            ClaimFormatDesignation::LdpVc,
            json!({
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    { "@vocab": "https://dmv.example/vocab#" }
                ],
                "type": ["VerifiableCredential", "VehicleInsuranceCredential"],
                "credentialSubject": { "policyNumber": "P-1" }
            }),
        )
        .await,
        Credential::json(
            "pid",
            ClaimFormatDesignation::DcSdJwt,
            json!({
                "vct": "https://credentials.example.com/identity_credential",
                "given_name": "Arthur",
                "family_name": "Dent",
                "address": { "street_address": "42 Market Street", "locality": "Milliways", "postal_code": "90210" },
                "nationalities": ["British", "Betelgeusian"]
            }),
        )
        .await,
        Credential::mdoc(
            "mdl",
            "org.iso.18013.5.1.mDL",
            &[
                ("org.iso.18013.5.1", "given_name", Cbor::Text("Arthur".into())),
                ("org.iso.18013.5.1", "family_name", Cbor::Text("Dent".into())),
                ("org.iso.18013.5.1", "age_over_21", Cbor::Bool(true)),
                ("org.iso.18013.5.1.aamva", "DHS_compliance", Cbor::Text("F".into())),
            ],
        ),
    ]
}

fn dcql(value: Json) -> DcqlQuery {
    serde_json::from_value(value).unwrap()
}

fn expected(entries: &[(&str, &[&'static str])]) -> BTreeMap<String, Vec<&'static str>> {
    entries
        .iter()
        .map(|(id, ids)| (id.to_string(), ids.to_vec()))
        .collect()
}

#[tokio::test]
async fn format_alone_matches_every_credential_of_the_format() {
    let wallet = wallet().await;
    let query = dcql(json!({
        "credentials": [{ "id": "any_ldp", "format": "ldp_vc", "meta": {} }]
    }));
    assert_eq!(
        matches(&query, &wallet),
        expected(&[("any_ldp", &["degree", "registration", "insurance"])])
    );
}

#[tokio::test]
async fn type_values_pick_the_credential_type() {
    let wallet = wallet().await;
    let query = dcql(json!({
        "credentials": [
            {
                "id": "degree",
                "format": "ldp_vc",
                "meta": { "type_values": [[
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                    "https://example.org/examples#UniversityDegreeCredential"
                ]] }
            },
            {
                "id": "registration",
                "format": "ldp_vc",
                "meta": { "type_values": [["https://dmv.example/vocab#VehicleRegistrationCredential"]] }
            },
            {
                "id": "fixture",
                "format": "jwt_vc_json",
                "meta": { "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]] }
            },
            {
                "id": "nothing",
                "format": "ldp_vc",
                "meta": { "type_values": [["https://dmv.example/vocab#BoatRegistrationCredential"]] }
            }
        ]
    }));
    assert_eq!(
        matches(&query, &wallet),
        expected(&[
            ("degree", &["degree"]),
            ("registration", &["registration"]),
            ("fixture", &["jwt_fixture"]),
            ("nothing", &[]),
        ])
    );
}

#[tokio::test]
async fn claim_values_pick_the_credential() {
    let wallet = wallet().await;
    let query = dcql(json!({
        "credentials": [
            {
                "id": "vehicle_registration",
                "format": "ldp_vc",
                "meta": {},
                "claims": [{ "path": ["type", null], "values": ["VehicleRegistrationCredential"] }]
            },
            {
                "id": "four_doors",
                "format": "ldp_vc",
                "meta": {},
                "claims": [{ "path": ["credentialSubject", "doors"], "values": [4] }]
            },
            {
                "id": "beverly_hills",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
                "claims": [{ "path": ["address", "postal_code"], "values": ["90210", "90211"] }]
            },
            {
                "id": "elsewhere",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
                "claims": [{ "path": ["address", "postal_code"], "values": ["10001"] }]
            }
        ]
    }));
    assert_eq!(
        matches(&query, &wallet),
        expected(&[
            ("vehicle_registration", &["registration"]),
            ("four_doors", &["registration"]),
            ("beverly_hills", &["pid"]),
            ("elsewhere", &[]),
        ])
    );
}

#[tokio::test]
async fn requested_claims_must_exist() {
    let wallet = wallet().await;
    let query = dcql(json!({
        "credentials": [
            {
                "id": "with_nationality",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
                "claims": [{ "path": ["given_name"] }, { "path": ["nationalities", 1] }]
            },
            {
                "id": "with_birthdate",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
                "claims": [{ "path": ["given_name"] }, { "path": ["birthdate"] }]
            },
            {
                "id": "with_subject_id",
                "format": "jwt_vc_json",
                "meta": {},
                "claims": [{ "path": ["credentialSubject", "id"] }]
            },
            {
                "id": "with_degree",
                "format": "jwt_vc_json",
                "meta": {},
                "claims": [{ "path": ["credentialSubject", "degree"] }]
            }
        ]
    }));
    assert_eq!(
        matches(&query, &wallet),
        expected(&[
            ("with_nationality", &["pid"]),
            ("with_birthdate", &[]),
            ("with_subject_id", &["jwt_fixture"]),
            ("with_degree", &[]),
        ])
    );
}

#[tokio::test]
async fn claim_sets_need_one_complete_option() {
    let wallet = wallet().await;
    let query = dcql(json!({
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
                "claims": [
                    { "id": "a", "path": ["last_name"] },
                    { "id": "b", "path": ["postal_code"] },
                    { "id": "c", "path": ["locality"] },
                    { "id": "d", "path": ["family_name"] },
                    { "id": "e", "path": ["address", "postal_code"] }
                ],
                "claim_sets": [["a", "c", "d"], ["a", "b"], ["d", "e"]]
            },
            {
                "id": "no_option",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
                "claims": [
                    { "id": "a", "path": ["last_name"] },
                    { "id": "b", "path": ["postal_code"] }
                ],
                "claim_sets": [["a"], ["b"]]
            }
        ]
    }));
    assert_eq!(
        matches(&query, &wallet),
        expected(&[("pid", &["pid"]), ("no_option", &[])])
    );
}

#[tokio::test]
async fn mdoc_claims_match_namespace_element_and_value() {
    let wallet = wallet().await;
    let mdl = |id: &str, claims: Json| {
        json!({
            "id": id,
            "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
            "claims": claims
        })
    };
    let query = dcql(json!({
        "credentials": [
            mdl("names", json!([
                { "path": ["org.iso.18013.5.1", "given_name"] },
                { "path": ["org.iso.18013.5.1", "family_name"] }
            ])),
            mdl("over_21", json!([{ "path": ["org.iso.18013.5.1", "age_over_21"], "values": [true] }])),
            mdl("real_id", json!([{ "path": ["org.iso.18013.5.1.aamva", "DHS_compliance"], "values": ["F"] }])),
            mdl("not_real_id", json!([{ "path": ["org.iso.18013.5.1.aamva", "DHS_compliance"], "values": ["N"] }])),
            mdl("wrong_namespace", json!([{ "path": ["org.iso.18013.5.1.aamva", "given_name"] }])),
            mdl("too_long", json!([{ "path": ["org.iso.18013.5.1", "given_name", "x"] }]))
        ]
    }));
    assert_eq!(
        matches(&query, &wallet),
        expected(&[
            ("names", &["mdl"]),
            ("over_21", &["mdl"]),
            ("real_id", &["mdl"]),
            ("not_real_id", &[]),
            ("wrong_namespace", &[]),
            ("too_long", &[]),
        ])
    );
}

#[tokio::test]
async fn selecting_every_match_respects_multiple() {
    let wallet = wallet().await;
    let query = |multiple: bool| {
        dcql(json!({
            "credentials": [
                {
                    "id": "vehicles",
                    "format": "ldp_vc",
                    "meta": {},
                    "multiple": multiple,
                    "claims": [{ "path": ["credentialSubject"] }]
                },
                { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
            ]
        }))
    };

    let selected = |query: &DcqlQuery| {
        matches(query, &wallet)
            .into_iter()
            .flat_map(|(id, ids)| std::iter::repeat_n(id, ids.len()))
            .collect::<Vec<_>>()
    };

    let single = query(false);
    let ids = selected(&single);
    assert_eq!(
        single.check_multiple(ids.iter().map(String::as_str)),
        Err(SelectionError::MultipleNotAllowed {
            id: "vehicles".into(),
            count: 3
        })
    );

    let many = query(true);
    let ids = selected(&many);
    assert_eq!(many.check_multiple(ids.iter().map(String::as_str)), Ok(()));
}
