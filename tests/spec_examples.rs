use openid4vp::core::{
    authorization_request::{
        parameters::{ClientMetadata, ExpectedOrigins, ResponseMode},
        AuthorizationRequestObject,
    },
    credential_format::{ClaimFormatDesignation, ClaimFormatPayload},
    dcql_query::{
        DcqlCredentialClaimsQueryPath, DcqlCredentialClaimsQueryValue, DcqlQuery,
        TrustedAuthoritiesQuery, TrustedAuthorityType,
    },
    metadata::parameters::verifier::VpFormats,
    object::UntypedObject,
    response::{parameters::VpToken, AuthorizationResponse},
};
use serde_json::{json, Value as Json};

fn dcql_section_7_4() -> Json {
    json!({
      "credentials": [
        {
          "id": "my_credential",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": [ "https://credentials.example.com/identity_credential" ]
          },
          "claims": [
              {"path": ["last_name"]},
              {"path": ["first_name"]},
              {"path": ["address", "street_address"]}
          ]
        }
      ]
    })
}

fn dcql_appendix_b_1_3_jwt_vc_json() -> Json {
    json!({
      "credentials": [
        {
          "id": "example_jwt_vc",
          "format": "jwt_vc_json",
          "meta": {
            "type_values": [["IDCredential"]]
          },
          "claims": [
            {"path": ["credentialSubject", "family_name"]},
            {"path": ["credentialSubject", "given_name"]}
          ]
        }
      ]
    })
}

fn dcql_appendix_b_1_3_ldp_vc() -> Json {
    json!({
      "credentials": [
        {
          "id": "example_ldp_vc",
          "format": "ldp_vc",
          "meta": {
            "type_values": [["IDCredential"]]
          },
          "claims": [
            {"path": ["credentialSubject", "family_name"]},
            {"path": ["credentialSubject", "given_name"]},
            {"path": ["credentialSubject", "birthdate"]},
            {"path": ["credentialSubject", "address", "street_address"]},
            {"path": ["credentialSubject", "address", "locality"]},
            {"path": ["credentialSubject", "address", "postal_code"]},
            {"path": ["credentialSubject", "address", "country"]}
          ]
        }
      ]
    })
}

fn dcql_appendix_d_mdoc() -> Json {
    json!({
      "credentials": [
        {
          "id": "my_credential",
          "format": "mso_mdoc",
          "meta": {
            "doctype_value": "org.iso.7367.1.mVRC"
          },
          "claims": [
            {"path": ["org.iso.7367.1", "vehicle_holder"]},
            {"path": ["org.iso.18013.5.1", "first_name"]}
          ]
        }
      ]
    })
}

fn dcql_appendix_d_sd_jwt_and_mdoc() -> Json {
    json!({
      "credentials": [
        {
          "id": "pid",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["https://credentials.example.com/identity_credential"]
          },
          "claims": [
            {"path": ["given_name"]},
            {"path": ["family_name"]},
            {"path": ["address", "street_address"]}
          ]
        },
        {
          "id": "mdl",
          "format": "mso_mdoc",
          "meta": {
            "doctype_value": "org.iso.7367.1.mVRC"
          },
          "claims": [
            {"path": ["org.iso.7367.1", "vehicle_holder"]},
            {"path": ["org.iso.18013.5.1", "first_name"]}
          ]
        }
      ]
    })
}

fn dcql_appendix_d_pid_credential_sets() -> Json {
    json!({
      "credentials": [
        {
          "id": "pid",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["https://credentials.example.com/identity_credential"]
          },
          "claims": [
            {"path": ["given_name"]},
            {"path": ["family_name"]},
            {"path": ["address", "street_address"]}
          ]
        },
        {
          "id": "other_pid",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["https://othercredentials.example/pid"]
          },
          "claims": [
            {"path": ["given_name"]},
            {"path": ["family_name"]},
            {"path": ["address", "street_address"]}
          ]
        },
        {
          "id": "pid_reduced_cred_1",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
          },
          "claims": [
            {"path": ["family_name"]},
            {"path": ["given_name"]}
          ]
        },
        {
          "id": "pid_reduced_cred_2",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["https://cred.example/residence_credential"]
          },
          "claims": [
            {"path": ["postal_code"]},
            {"path": ["locality"]},
            {"path": ["region"]}
          ]
        },
        {
          "id": "nice_to_have",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["https://company.example/company_rewards"]
          },
          "claims": [
            {"path": ["rewards_number"]}
          ]
        }
      ],
      "credential_sets": [
        {
          "options": [
            [ "pid" ],
            [ "other_pid" ],
            [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
          ]
        },
        {
          "required": false,
          "options": [
            [ "nice_to_have" ]
          ]
        }
      ]
    })
}

fn dcql_appendix_d_mdl_or_photo_id_credential_sets() -> Json {
    json!({
      "credentials": [
        {
          "id": "mdl-id",
          "format": "mso_mdoc",
          "meta": {
            "doctype_value": "org.iso.18013.5.1.mDL"
          },
          "claims": [
            {
              "id": "given_name",
              "path": ["org.iso.18013.5.1", "given_name"]
            },
            {
              "id": "family_name",
              "path": ["org.iso.18013.5.1", "family_name"]
            },
            {
              "id": "portrait",
              "path": ["org.iso.18013.5.1", "portrait"]
            }
          ]
        },
        {
          "id": "mdl-address",
          "format": "mso_mdoc",
          "meta": {
            "doctype_value": "org.iso.18013.5.1.mDL"
          },
          "claims": [
            {
              "id": "resident_address",
              "path": ["org.iso.18013.5.1", "resident_address"]
            },
            {
              "id": "resident_country",
              "path": ["org.iso.18013.5.1", "resident_country"]
            }
          ]
        },
        {
          "id": "photo_card-id",
          "format": "mso_mdoc",
          "meta": {
            "doctype_value": "org.iso.23220.photoid.1"
          },
          "claims": [
            {
              "id": "given_name",
              "path": ["org.iso.18013.5.1", "given_name"]
            },
            {
              "id": "family_name",
              "path": ["org.iso.18013.5.1", "family_name"]
            },
            {
              "id": "portrait",
              "path": ["org.iso.18013.5.1", "portrait"]
            }
          ]
        },
        {
          "id": "photo_card-address",
          "format": "mso_mdoc",
          "meta": {
            "doctype_value": "org.iso.23220.photoid.1"
          },
          "claims": [
            {
              "id": "resident_address",
              "path": ["org.iso.18013.5.1", "resident_address"]
            },
            {
              "id": "resident_country",
              "path": ["org.iso.18013.5.1", "resident_country"]
            }
          ]
        }
      ],
      "credential_sets": [
        {
          "options": [
            [ "mdl-id" ],
            [ "photo_card-id" ]
          ]
        },
        {
          "required": false,
          "options": [
            [ "mdl-address" ],
            [ "photo_card-address" ]
          ]
        }
      ]
    })
}

fn dcql_appendix_d_claim_sets() -> Json {
    json!({
      "credentials": [
        {
          "id": "pid",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": [ "https://credentials.example.com/identity_credential" ]
          },
          "claims": [
            {"id": "a", "path": ["last_name"]},
            {"id": "b", "path": ["postal_code"]},
            {"id": "c", "path": ["locality"]},
            {"id": "d", "path": ["region"]},
            {"id": "e", "path": ["date_of_birth"]}
          ],
          "claim_sets": [
            ["a", "c", "d", "e"],
            ["a", "b", "e"]
          ]
        }
      ]
    })
}

fn dcql_appendix_d_values() -> Json {
    json!({
      "credentials": [
        {
          "id": "my_credential",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": [ "https://credentials.example.com/identity_credential" ]
          },
          "claims": [
              {
                "path": ["last_name"],
                "values": ["Doe"]
              },
              {"path": ["first_name"]},
              {"path": ["address", "street_address"]},
              {
                "path": ["postal_code"],
                "values": ["90210", "90211"]
              }
          ]
        }
      ]
    })
}

fn all_dcql_examples() -> Vec<(&'static str, Json)> {
    vec![
        ("7.4", dcql_section_7_4()),
        ("B.1.3 jwt_vc_json", dcql_appendix_b_1_3_jwt_vc_json()),
        ("B.1.3 ldp_vc", dcql_appendix_b_1_3_ldp_vc()),
        ("D mdoc", dcql_appendix_d_mdoc()),
        ("D sd-jwt and mdoc", dcql_appendix_d_sd_jwt_and_mdoc()),
        (
            "D pid credential_sets",
            dcql_appendix_d_pid_credential_sets(),
        ),
        (
            "D mdl or photo id credential_sets",
            dcql_appendix_d_mdl_or_photo_id_credential_sets(),
        ),
        ("D claim_sets", dcql_appendix_d_claim_sets()),
        ("D values", dcql_appendix_d_values()),
    ]
}

fn parse_dcql(json: Json) -> DcqlQuery {
    serde_json::from_value(json).unwrap()
}

#[test]
fn dcql_examples_round_trip() {
    for (section, example) in all_dcql_examples() {
        let dcql = parse_dcql(example.clone());
        assert_eq!(
            serde_json::to_value(&dcql).unwrap(),
            example,
            "section {section}"
        );
    }
}

#[test]
fn dcql_examples_pass_validation() {
    for (section, example) in all_dcql_examples() {
        assert_eq!(parse_dcql(example).validate(), Ok(()), "section {section}");
    }
}

#[test]
fn dcql_example_formats_parse_to_known_designations() {
    let formats = |json: Json| -> Vec<ClaimFormatDesignation> {
        parse_dcql(json)
            .credentials()
            .iter()
            .map(|c| c.format().clone())
            .collect()
    };
    assert_eq!(
        formats(dcql_section_7_4()),
        [ClaimFormatDesignation::DcSdJwt]
    );
    assert_eq!(
        formats(dcql_appendix_b_1_3_jwt_vc_json()),
        [ClaimFormatDesignation::JwtVcJson]
    );
    assert_eq!(
        formats(dcql_appendix_b_1_3_ldp_vc()),
        [ClaimFormatDesignation::LdpVc]
    );
    assert_eq!(
        formats(dcql_appendix_d_mdoc()),
        [ClaimFormatDesignation::MsoMDoc]
    );
}

#[test]
fn dcql_example_pid_credential_sets_has_one_required_and_one_optional_set() {
    let dcql = parse_dcql(dcql_appendix_d_pid_credential_sets());
    let sets = dcql.credential_sets().unwrap();
    assert_eq!(sets.len(), 2);

    assert!(sets[0].is_required());
    assert_eq!(
        sets[0].options().as_ref(),
        [
            vec!["pid".to_string()],
            vec!["other_pid".to_string()],
            vec![
                "pid_reduced_cred_1".to_string(),
                "pid_reduced_cred_2".to_string()
            ],
        ]
    );

    assert!(!sets[1].is_required());
    assert_eq!(
        sets[1].options().as_ref(),
        [vec!["nice_to_have".to_string()]]
    );
}

#[test]
fn dcql_example_mdl_or_photo_id_reuses_claim_ids_across_credentials() {
    let dcql = parse_dcql(dcql_appendix_d_mdl_or_photo_id_credential_sets());
    let claim_ids = |credential: usize| -> Vec<String> {
        dcql.credentials()[credential]
            .claims()
            .unwrap()
            .iter()
            .map(|claim| claim.id().unwrap().clone())
            .collect()
    };
    assert_eq!(claim_ids(0), claim_ids(2));
    assert_eq!(dcql.validate(), Ok(()));
}

#[test]
fn dcql_example_claim_sets_keep_verifier_preference_order() {
    let dcql = parse_dcql(dcql_appendix_d_claim_sets());
    assert_eq!(
        dcql.credentials()[0].claim_sets().unwrap().as_ref(),
        [vec!["a", "c", "d", "e"], vec!["a", "b", "e"],]
    );
}

#[test]
fn dcql_example_values_parse_as_strings() {
    let dcql = parse_dcql(dcql_appendix_d_values());
    let claims = dcql.credentials()[0].claims().unwrap();
    assert_eq!(
        claims[0].values().unwrap().as_ref(),
        [DcqlCredentialClaimsQueryValue::String("Doe".into())]
    );
    assert!(claims[1].values().is_none());
    assert_eq!(
        claims[3].values().unwrap().as_ref(),
        [
            DcqlCredentialClaimsQueryValue::String("90210".into()),
            DcqlCredentialClaimsQueryValue::String("90211".into()),
        ]
    );
}

#[test]
fn dcql_example_mdoc_paths_split_into_namespace_and_element() {
    let dcql = parse_dcql(dcql_appendix_d_mdoc());
    let claims = dcql.credentials()[0].claims().unwrap();
    assert_eq!(claims[0].namespace(), Some("org.iso.7367.1"));
    assert_eq!(claims[0].element_identifier(), Some("vehicle_holder"));
    assert_eq!(claims[1].namespace(), Some("org.iso.18013.5.1"));
    assert_eq!(claims[1].element_identifier(), Some("first_name"));
}

#[test]
fn claims_path_pointer_examples_parse() {
    let paths: Vec<Vec<DcqlCredentialClaimsQueryPath>> = serde_json::from_value(json!([
        ["name"],
        ["address"],
        ["address", "street_address"],
        ["degrees", null, "type"],
        ["nationalities", 1]
    ]))
    .unwrap();
    assert_eq!(
        paths[3],
        [
            DcqlCredentialClaimsQueryPath::String("degrees".into()),
            DcqlCredentialClaimsQueryPath::Null,
            DcqlCredentialClaimsQueryPath::String("type".into()),
        ]
    );
    assert_eq!(
        paths[4],
        [
            DcqlCredentialClaimsQueryPath::String("nationalities".into()),
            DcqlCredentialClaimsQueryPath::Integer(1),
        ]
    );
}

#[test]
fn trusted_authorities_examples_parse() {
    let examples = [
        (
            json!({ "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] }),
            TrustedAuthorityType::Aki,
        ),
        (
            json!({ "type": "etsi_tl", "values": ["https://lotl.example.com"] }),
            TrustedAuthorityType::EtsiTl,
        ),
        (
            json!({ "type": "openid_federation", "values": ["https://trustanchor.example.com"] }),
            TrustedAuthorityType::OpenidFederation,
        ),
    ];
    for (example, expected) in examples {
        let query: TrustedAuthoritiesQuery = serde_json::from_value(example.clone()).unwrap();
        assert_eq!(query.authority_type(), &expected);
        assert_eq!(serde_json::to_value(&query).unwrap(), example);
    }
}

fn request_object(json: Json) -> AuthorizationRequestObject {
    serde_json::from_value::<UntypedObject>(json)
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn request_uri_response_example_parses() {
    let request = request_object(json!({
      "client_id": "x509_san_dns:client.example.org",
      "response_uri": "https://client.example.org/post",
      "response_type": "vp_token",
      "response_mode": "direct_post",
      "dcql_query": dcql_section_7_4(),
      "nonce": "n-0S6_WzA2Mj",
      "wallet_nonce": "qPmxiNFCR3QTm19POc8u",
      "state" : "eyJhb...6-sVA"
    }));

    assert_eq!(request.client_id_scheme().unwrap().0, "x509_san_dns");
    assert_eq!(request.response_mode(), &ResponseMode::DirectPost);
    assert_eq!(
        request.return_uri().as_str(),
        "https://client.example.org/post"
    );
    assert_eq!(request.nonce().as_str(), "n-0S6_WzA2Mj");
    assert_eq!(request.state().unwrap().unwrap().0, "eyJhb...6-sVA");
    assert_eq!(
        request.dcql_query().unwrap().unwrap(),
        parse_dcql(dcql_section_7_4())
    );
}

#[test]
fn direct_post_request_example_parses() {
    let request = request_object(json!({
      "client_id": "redirect_uri:https://client.example.org/post",
      "response_uri": "https://client.example.org/post",
      "response_type": "vp_token",
      "response_mode": "direct_post",
      "dcql_query": dcql_section_7_4(),
      "nonce": "n-0S6_WzA2Mj",
      "state": "eyJhb...6-sVA"
    }));

    assert_eq!(request.client_id_scheme().unwrap().0, "redirect_uri");
    assert_eq!(request.response_mode(), &ResponseMode::DirectPost);
    assert_eq!(
        request.return_uri().as_str(),
        "https://client.example.org/post"
    );
}

#[test]
fn dc_api_signed_request_payload_example_parses() {
    let request = request_object(json!({
      "expected_origins": [
        "https://origin1.example.com",
        "https://origin2.example.com"
      ],
      "client_id": "x509_san_dns:rp.example.com",
      "client_metadata": {
        "jwks": {
          "keys": [
            {
              "kty": "EC",
              "crv": "P-256",
              "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "use": "enc",
              "kid": "1"
            }
          ]
        }
      },
      "response_type": "vp_token",
      "response_mode": "dc_api",
      "nonce": "n-0S6_WzA2Mj",
      "dcql_query": dcql_section_7_4()
    }));

    assert_eq!(request.response_mode(), &ResponseMode::DcApi);
    assert_eq!(
        request.get::<ExpectedOrigins>().unwrap().unwrap().0,
        [
            "https://origin1.example.com".to_string(),
            "https://origin2.example.com".to_string(),
        ]
    );
    let ClientMetadata(metadata) = request.client_metadata().unwrap();
    let metadata: Json = metadata.into();
    assert_eq!(metadata["jwks"]["keys"][0]["kid"], "1");
}

fn vp_formats(json: Json) -> VpFormats {
    serde_json::from_value::<UntypedObject>(json)
        .unwrap()
        .get::<VpFormats>()
        .unwrap()
        .unwrap()
}

#[test]
fn jwt_vc_json_metadata_example_parses_alg_values() {
    let formats = vp_formats(json!({
      "vp_formats_supported": {
        "jwt_vc_json": {
          "alg_values": ["ES256", "ES384"]
        }
      }
    }));
    assert_eq!(
        formats.0.get(&ClaimFormatDesignation::JwtVcJson),
        Some(&ClaimFormatPayload::AlgValues(vec![
            "ES256".into(),
            "ES384".into()
        ]))
    );
    assert!(formats.supports_security_method(&ClaimFormatDesignation::JwtVcJson, &"ES256".into()));
}

#[test]
fn ldp_vc_metadata_example_supports_listed_proof_types_and_cryptosuites() {
    let formats = vp_formats(json!({
      "vp_formats_supported": {
        "ldp_vc": {
          "proof_type_values": [
            "DataIntegrityProof",
            "Ed25519Signature2020"
          ],
          "cryptosuite_values": [
            "ecdsa-rdfc-2019",
            "ecdsa-sd-2023",
            "ecdsa-jcs-2019",
            "bbs-2023"
          ]
        }
      }
    }));
    let supports = |method: &str| {
        formats.supports_security_method(&ClaimFormatDesignation::LdpVc, &method.to_string())
    };
    assert!(supports("DataIntegrityProof"));
    assert!(supports("Ed25519Signature2020"));
    assert!(supports("ecdsa-rdfc-2019"));
    assert!(supports("bbs-2023"));
    assert!(!supports("eddsa-rdfc-2022"));
    assert!(
        !formats.supports_security_method(&ClaimFormatDesignation::JwtVcJson, &"ES256".to_string())
    );
}

#[test]
fn mso_mdoc_and_sd_jwt_metadata_examples_parse() {
    let formats = vp_formats(json!({
      "vp_formats_supported": {
        "mso_mdoc": {
          "issuerauth_alg_values": [-9, -50],
          "deviceauth_alg_values": [-9, -50]
        },
        "dc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "ES384"],
          "kb-jwt_alg_values": ["ES256", "ES384"]
        }
      }
    }));
    assert_eq!(
        formats.0.get(&ClaimFormatDesignation::MsoMDoc),
        Some(&ClaimFormatPayload::Other(json!({
          "issuerauth_alg_values": [-9, -50],
          "deviceauth_alg_values": [-9, -50]
        })))
    );
    assert_eq!(
        formats.0.get(&ClaimFormatDesignation::DcSdJwt),
        Some(&ClaimFormatPayload::Other(json!({
          "sd-jwt_alg_values": ["ES256", "ES384"],
          "kb-jwt_alg_values": ["ES256", "ES384"]
        })))
    );
}

#[test]
fn vp_token_examples_parse() {
    let single: VpToken = serde_json::from_value(json!({
      "my_credential": ["eyJhbGci...QMA"]
    }))
    .unwrap();
    assert_eq!(single.get("my_credential").unwrap().len(), 1);

    let multiple: VpToken = serde_json::from_value(json!({
      "my_credential": ["eyJhbGci...QMA", "eyJhbGci...QMA"]
    }))
    .unwrap();
    assert_eq!(multiple.get("my_credential").unwrap().len(), 2);
}

#[test]
fn direct_post_response_example_parses() {
    let body = serde_urlencoded::to_string([
        ("vp_token", r#"{"example_jwt_vc":["eY...QMA"]}"#),
        ("state", "eyJhb...6-sVA"),
    ])
    .unwrap();

    let AuthorizationResponse::Unencoded(response) =
        AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes()).unwrap()
    else {
        panic!("expected an unencoded response");
    };
    assert_eq!(response.vp_token().get("example_jwt_vc").unwrap().len(), 1);
    assert_eq!(
        response.state().map(|state| state.0.as_str()),
        Some("eyJhb...6-sVA")
    );
}

const SPEC_ENCRYPTED_RESPONSE: &str = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImtpZCI6ImFjIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6Im5ubVZwbTNWM2piaGNhZlFhUkJrU1ZOSGx3Wkh3dC05ck9wSnVmeVlJdWsiLCJ5IjoicjRmakRxd0p5czlxVU9QLV9iM21SNVNaRy0tQ3dPMm1pYzVWU05UWU45ZyIsImNydiI6IlAtMjU2In19..uAYcHRUSSn2X0WPX.yVzlGSYG4qbg0bq18JcUiDRw56yVnbKR8E7S7YlEtzT00RqE3Pw5oTpUG3hdLN4taHZ9gC1kwak8JOnJgQ.1wR024_3-qtAlx1oFIUpQQ";

#[test]
fn direct_post_jwt_response_example_parses() {
    let body = serde_urlencoded::to_string([("response", SPEC_ENCRYPTED_RESPONSE)]).unwrap();

    let AuthorizationResponse::Jwt(response) =
        AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes()).unwrap()
    else {
        panic!("expected a JWT response");
    };
    assert_eq!(response.response, SPEC_ENCRYPTED_RESPONSE);
}
