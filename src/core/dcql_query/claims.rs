use serde_json::Value as Json;

use super::{
    DcqlCredentialClaimsQuery, DcqlCredentialClaimsQueryPath as PathComponent,
    DcqlCredentialClaimsQueryValue, DcqlCredentialQuery,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsPathError {
    #[error("path component {0} selects a key of a non-object")]
    NotAnObject(usize),
    #[error("path component {0} selects from a non-array")]
    NotAnArray(usize),
    #[error("the path selects no claim")]
    NoClaim,
    #[error("no selected claim matches the requested values")]
    ValueMismatch,
    #[error("an mdoc path must be exactly a namespace and a data element identifier")]
    InvalidMdocPath,
}

pub fn select_json<'a>(
    credential: &'a Json,
    path: &[PathComponent],
) -> Result<Vec<&'a Json>, ClaimsPathError> {
    let mut selected = vec![credential];

    for (i, component) in path.iter().enumerate() {
        let mut next = Vec::new();
        for element in selected {
            match component {
                PathComponent::String(key) => {
                    let object = element.as_object().ok_or(ClaimsPathError::NotAnObject(i))?;
                    next.extend(object.get(key));
                }
                PathComponent::Null => {
                    let array = element.as_array().ok_or(ClaimsPathError::NotAnArray(i))?;
                    next.extend(array);
                }
                PathComponent::Integer(index) => {
                    let array = element.as_array().ok_or(ClaimsPathError::NotAnArray(i))?;
                    next.extend(array.get(*index));
                }
            }
        }
        selected = next;
    }

    if selected.is_empty() {
        return Err(ClaimsPathError::NoClaim);
    }

    Ok(selected)
}

pub fn mdoc_path(path: &[PathComponent]) -> Result<(&str, &str), ClaimsPathError> {
    match path {
        [PathComponent::String(namespace), PathComponent::String(element)] => {
            Ok((namespace, element))
        }
        _ => Err(ClaimsPathError::InvalidMdocPath),
    }
}

impl DcqlCredentialClaimsQueryValue {
    pub fn matches_json(&self, claim: &Json) -> bool {
        match self {
            Self::String(expected) => claim.as_str() == Some(expected.as_str()),
            Self::Integer(expected) => claim.as_i64() == Some(*expected as i64),
            Self::Boolean(expected) => claim.as_bool() == Some(*expected),
        }
    }

    pub fn matches_cbor(&self, mut claim: &ciborium::Value) -> bool {
        while let Some((_, inner)) = claim.as_tag() {
            claim = inner;
        }
        match self {
            Self::String(expected) => claim.as_text() == Some(expected.as_str()),
            Self::Integer(expected) => claim
                .as_integer()
                .is_some_and(|n| i128::from(n) == *expected as i128),
            Self::Boolean(expected) => claim.as_bool() == Some(*expected),
        }
    }
}

impl DcqlCredentialClaimsQuery {
    pub fn matches_values(
        &self,
        matches: impl FnMut(&DcqlCredentialClaimsQueryValue) -> bool,
    ) -> bool {
        match self.values() {
            None => true,
            Some(values) => values.iter().any(matches),
        }
    }

    pub fn is_satisfied_by_json(&self, credential: &Json) -> Result<(), ClaimsPathError> {
        let selected = select_json(credential, self.path())?;
        let any_match = selected
            .iter()
            .any(|claim| self.matches_values(|value| value.matches_json(claim)));
        if any_match {
            Ok(())
        } else {
            Err(ClaimsPathError::ValueMismatch)
        }
    }
}

impl DcqlCredentialQuery {
    pub fn select_claims(
        &self,
        has_claim: impl Fn(&DcqlCredentialClaimsQuery) -> bool,
    ) -> Option<Vec<&DcqlCredentialClaimsQuery>> {
        let Some(claims) = self.claims() else {
            if self.claim_sets().is_some() {
                tracing::warn!(
                    "credential query {:?} has `claim_sets` but no `claims`",
                    self.id()
                );
                return None;
            }
            return Some(Vec::new());
        };

        let Some(claim_sets) = self.claim_sets() else {
            return claims
                .iter()
                .all(&has_claim)
                .then(|| claims.iter().collect());
        };

        claim_sets.iter().find_map(|option| {
            option
                .iter()
                .map(|id| {
                    let claim = claims.iter().find(|claim| claim.id() == Some(id));
                    if claim.is_none() {
                        tracing::warn!(
                            "credential query {:?}: `claim_sets` references undefined claim {id:?}",
                            self.id()
                        );
                    }
                    claim.filter(|claim| has_claim(claim))
                })
                .collect()
        })
    }

    pub fn satisfies_claims(&self, has_claim: impl Fn(&DcqlCredentialClaimsQuery) -> bool) -> bool {
        self.select_claims(has_claim).is_some()
    }

    pub fn satisfies_json_claims(&self, credential: &Json) -> bool {
        self.select_json_claims(credential).is_some()
    }

    pub fn select_json_claims(&self, credential: &Json) -> Option<Vec<&DcqlCredentialClaimsQuery>> {
        self.select_claims(|claim| {
            claim
                .is_satisfied_by_json(credential)
                .inspect_err(|e| {
                    tracing::debug!(
                        "credential query {:?}: claim {:?} not satisfied: {e}",
                        self.id(),
                        claim.path()
                    )
                })
                .is_ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn path(value: Json) -> Vec<PathComponent> {
        serde_json::from_value(value).unwrap()
    }

    fn arthur() -> Json {
        json!({
            "name": "Arthur Dent",
            "address": {
                "street_address": "42 Market Street",
                "locality": "Milliways",
                "postal_code": "12345"
            },
            "degrees": [
                { "type": "Bachelor of Science", "university": "University of Betelgeuse" },
                { "type": "Master of Science", "university": "University of Betelgeuse" }
            ],
            "nationalities": ["British", "Betelgeusian"]
        })
    }

    fn query(extra: Json) -> DcqlCredentialQuery {
        let mut query = json!({ "id": "q", "format": "ldp_vc", "meta": {} });
        query
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(query).unwrap()
    }

    fn arthur_presence(query: &DcqlCredentialQuery) -> bool {
        let credential = arthur();
        query.satisfies_claims(|claim| select_json(&credential, claim.path()).is_ok())
    }

    #[test]
    fn selects_the_spec_examples() {
        let credential = arthur();
        let select = |p: Json| select_json(&credential, &path(p)).unwrap();

        assert_eq!(select(json!(["name"])), [&json!("Arthur Dent")]);
        assert_eq!(select(json!(["address"])), [&credential["address"]]);
        assert_eq!(
            select(json!(["address", "street_address"])),
            [&json!("42 Market Street")]
        );
        assert_eq!(
            select(json!(["degrees", null, "type"])),
            [&json!("Bachelor of Science"), &json!("Master of Science")]
        );
        assert_eq!(
            select(json!(["nationalities", 1])),
            [&json!("Betelgeusian")]
        );
    }

    #[test]
    fn missing_claims_select_nothing() {
        let credential = arthur();
        for missing in [
            json!(["birthdate"]),
            json!(["address", "country"]),
            json!(["nationalities", 2]),
            json!(["degrees", null, "grade"]),
        ] {
            assert_eq!(
                select_json(&credential, &path(missing.clone())),
                Err(ClaimsPathError::NoClaim),
                "{missing}"
            );
        }
    }

    #[test]
    fn drops_only_the_elements_lacking_the_key() {
        let credential = json!({ "degrees": [{ "type": "BSc" }, { "university": "Betelgeuse" }] });
        assert_eq!(
            select_json(&credential, &path(json!(["degrees", null, "type"]))),
            Ok(vec![&json!("BSc")])
        );
    }

    #[test]
    fn null_on_an_empty_array_selects_nothing() {
        let credential = json!({ "nationalities": [] });
        assert_eq!(
            select_json(&credential, &path(json!(["nationalities", null]))),
            Err(ClaimsPathError::NoClaim)
        );
    }

    #[test]
    fn type_mismatches_are_errors() {
        let credential = arthur();
        let select = |p: Json| select_json(&credential, &path(p));

        assert_eq!(
            select(json!(["name", "first"])),
            Err(ClaimsPathError::NotAnObject(1))
        );
        assert_eq!(
            select(json!(["address", null])),
            Err(ClaimsPathError::NotAnArray(1))
        );
        assert_eq!(
            select(json!(["address", 0])),
            Err(ClaimsPathError::NotAnArray(1))
        );
        assert_eq!(
            select(json!(["degrees", "type"])),
            Err(ClaimsPathError::NotAnObject(1))
        );
    }

    #[test]
    fn jsonpath_style_component_is_a_literal_key() {
        let credential = json!({ "type": ["VerifiableCredential"] });
        assert_eq!(
            select_json(&credential, &path(json!(["$.type"]))),
            Err(ClaimsPathError::NoClaim)
        );
    }

    #[test]
    fn mdoc_paths_are_a_namespace_and_an_element() {
        assert_eq!(
            mdoc_path(&path(json!(["org.iso.18013.5.1", "given_name"]))),
            Ok(("org.iso.18013.5.1", "given_name"))
        );
        for invalid in [
            json!(["org.iso.18013.5.1"]),
            json!(["org.iso.18013.5.1", "given_name", "x"]),
            json!(["org.iso.18013.5.1", 0]),
            json!([null, "given_name"]),
        ] {
            assert_eq!(
                mdoc_path(&path(invalid.clone())),
                Err(ClaimsPathError::InvalidMdocPath),
                "{invalid}"
            );
        }
    }

    #[test]
    fn json_values_match_type_and_value_exactly() {
        let s = DcqlCredentialClaimsQueryValue::String("4".into());
        let i = DcqlCredentialClaimsQueryValue::Integer(4);
        let b = DcqlCredentialClaimsQueryValue::Boolean(true);

        assert!(s.matches_json(&json!("4")));
        assert!(!s.matches_json(&json!(4)));
        assert!(i.matches_json(&json!(4)));
        assert!(!i.matches_json(&json!("4")));
        assert!(!i.matches_json(&json!(4.5)));
        assert!(!i.matches_json(&json!(5)));
        assert!(b.matches_json(&json!(true)));
        assert!(!b.matches_json(&json!("true")));
        assert!(!b.matches_json(&json!(1)));

        let negative = DcqlCredentialClaimsQueryValue::Integer(-1);
        assert!(negative.matches_json(&json!(-1)));
        assert!(!DcqlCredentialClaimsQueryValue::Integer(-1).matches_json(&json!(u64::MAX)));
    }

    #[test]
    fn cbor_values_match_type_and_value_exactly() {
        use ciborium::Value as Cbor;

        let s = DcqlCredentialClaimsQueryValue::String("US".into());
        let i = DcqlCredentialClaimsQueryValue::Integer(21);
        let b = DcqlCredentialClaimsQueryValue::Boolean(true);

        assert!(s.matches_cbor(&Cbor::Text("US".into())));
        assert!(!s.matches_cbor(&Cbor::Bytes(b"US".to_vec())));
        assert!(i.matches_cbor(&Cbor::Integer(21.into())));
        assert!(!i.matches_cbor(&Cbor::Float(21.0)));
        assert!(b.matches_cbor(&Cbor::Bool(true)));
        assert!(!b.matches_cbor(&Cbor::Integer(1.into())));
    }

    #[test]
    fn no_claims_requests_nothing() {
        assert!(arthur_presence(&query(json!({}))));
        assert!(query(json!({})).satisfies_json_claims(&json!({})));
    }

    #[test]
    fn every_claim_is_required_without_claim_sets() {
        assert!(arthur_presence(&query(json!({
            "claims": [{ "path": ["name"] }, { "path": ["address", "locality"] }]
        }))));
        assert!(!arthur_presence(&query(json!({
            "claims": [{ "path": ["name"] }, { "path": ["birthdate"] }]
        }))));
    }

    #[test]
    fn one_claim_set_option_is_enough() {
        let claims = json!([
            { "id": "a", "path": ["name"] },
            { "id": "b", "path": ["birthdate"] },
            { "id": "c", "path": ["address", "postal_code"] }
        ]);

        assert!(arthur_presence(&query(json!({
            "claims": claims,
            "claim_sets": [["a", "b"], ["a", "c"]]
        }))));
        assert!(!arthur_presence(&query(json!({
            "claims": claims,
            "claim_sets": [["a", "b"], ["b", "c"]]
        }))));
    }

    #[test]
    fn claim_sets_naming_an_unknown_claim_cannot_be_satisfied() {
        assert!(!arthur_presence(&query(json!({
            "claims": [{ "id": "a", "path": ["name"] }],
            "claim_sets": [["a", "z"]]
        }))));
    }

    #[test]
    fn claim_sets_without_claims_cannot_be_satisfied() {
        assert!(!arthur_presence(&query(json!({ "claim_sets": [["a"]] }))));
    }

    fn registration() -> Json {
        json!({
            "type": ["VerifiableCredential", "VehicleRegistrationCredential"],
            "credentialSubject": { "licensePlateIdentifier": "2GKK061", "doors": 4, "active": true }
        })
    }

    fn insurance() -> Json {
        json!({ "type": ["VerifiableCredential", "VehicleInsuranceCredential"] })
    }

    #[test]
    fn values_filter_by_any_selected_claim() {
        let q = query(json!({
            "claims": [{ "path": ["type", null], "values": ["VehicleRegistrationCredential"] }]
        }));
        assert!(q.satisfies_json_claims(&registration()));
        assert!(!q.satisfies_json_claims(&insurance()));
    }

    #[test]
    fn values_with_an_index_select_one_element() {
        let q = query(json!({
            "claims": [{ "path": ["type", 1], "values": ["VehicleRegistrationCredential"] }]
        }));
        assert!(q.satisfies_json_claims(&registration()));
        assert!(!q.satisfies_json_claims(&insurance()));
    }

    #[test]
    fn integer_and_boolean_values_match() {
        let q = query(json!({
            "claims": [
                { "path": ["credentialSubject", "doors"], "values": [2, 4] },
                { "path": ["credentialSubject", "active"], "values": [true] }
            ]
        }));
        assert!(q.satisfies_json_claims(&registration()));

        let wrong = query(json!({
            "claims": [{ "path": ["credentialSubject", "doors"], "values": ["4"] }]
        }));
        assert!(!wrong.satisfies_json_claims(&registration()));
    }

    #[test]
    fn a_missing_claim_fails_even_without_values() {
        let q = query(json!({ "claims": [{ "path": ["credentialSubject", "missing"] }] }));
        assert!(!q.satisfies_json_claims(&registration()));
    }

    #[test]
    fn values_on_a_non_array_null_fail() {
        let q = query(json!({
            "claims": [{ "path": ["credentialSubject", null], "values": ["x"] }]
        }));
        assert!(!q.satisfies_json_claims(&registration()));
    }

    #[test]
    fn claim_sets_apply_values_per_option() {
        let q = query(json!({
            "claims": [
                { "id": "reg", "path": ["type", null], "values": ["VehicleRegistrationCredential"] },
                { "id": "ins", "path": ["type", null], "values": ["VehicleInsuranceCredential"] }
            ],
            "claim_sets": [["reg"], ["ins"]]
        }));
        assert!(q.satisfies_json_claims(&registration()));
        assert!(q.satisfies_json_claims(&insurance()));
        assert!(!q.satisfies_json_claims(&json!({ "type": ["VerifiableCredential"] })));
    }

    #[test]
    fn cbor_values_match_through_tags() {
        use ciborium::Value as Cbor;

        let birth_date = Cbor::Tag(1004, Box::new(Cbor::Text("1990-01-01".into())));
        let issued_at = Cbor::Tag(0, Box::new(Cbor::Text("2024-01-01T00:00:00Z".into())));

        assert!(
            DcqlCredentialClaimsQueryValue::String("1990-01-01".into()).matches_cbor(&birth_date)
        );
        assert!(
            DcqlCredentialClaimsQueryValue::String("2024-01-01T00:00:00Z".into())
                .matches_cbor(&issued_at)
        );
        assert!(
            !DcqlCredentialClaimsQueryValue::String("1990-01-02".into()).matches_cbor(&birth_date)
        );
    }

    #[test]
    fn value_mismatch_is_distinct_from_a_missing_claim() {
        let q: DcqlCredentialClaimsQuery =
            serde_json::from_value(json!({ "path": ["name"], "values": ["Ford Prefect"] }))
                .unwrap();
        assert_eq!(
            q.is_satisfied_by_json(&arthur()),
            Err(ClaimsPathError::ValueMismatch)
        );
    }

    #[test]
    fn selects_the_first_satisfiable_claim_set_option() {
        let q = query(json!({
            "claims": [
                { "id": "a", "path": ["name"] },
                { "id": "b", "path": ["birthdate"] },
                { "id": "c", "path": ["address", "postal_code"] },
                { "id": "d", "path": ["address", "locality"] }
            ],
            "claim_sets": [["a", "b"], ["c", "a"], ["d"]]
        }));
        let ids = q
            .select_json_claims(&arthur())
            .unwrap()
            .into_iter()
            .map(|claim| claim.id().unwrap().as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["c", "a"]);
    }

    #[test]
    fn selects_every_claim_without_claim_sets() {
        let q = query(json!({
            "claims": [{ "path": ["name"] }, { "path": ["address", "locality"] }]
        }));
        assert_eq!(q.select_json_claims(&arthur()).unwrap().len(), 2);
        assert_eq!(query(json!({})).select_json_claims(&arthur()), Some(vec![]));
    }
}
