use std::collections::HashMap;

use super::{DcqlCredentialQuery, DcqlQuery};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    #[error("credential query {0} is not in the DCQL query")]
    UnknownCredentialQuery(String),
    #[error(
        "{count} credentials selected for credential query {id}, which does not allow `multiple`"
    )]
    MultipleNotAllowed { id: String, count: usize },
}

impl DcqlQuery {
    pub fn credential_query(&self, id: &str) -> Option<&DcqlCredentialQuery> {
        self.credentials().iter().find(|query| query.id() == id)
    }

    pub fn requires_holder_binding(&self, credential_query_id: &str) -> bool {
        self.credential_query(credential_query_id)
            .is_none_or(DcqlCredentialQuery::require_cryptographic_holder_binding)
    }

    pub fn check_multiple<'a>(
        &self,
        selected_query_ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), SelectionError> {
        let ids: Vec<&str> = selected_query_ids.into_iter().collect();
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for &id in &ids {
            *counts.entry(id).or_default() += 1;
        }

        for id in ids {
            let count = counts[id];
            let query = self
                .credential_query(id)
                .ok_or_else(|| SelectionError::UnknownCredentialQuery(id.to_owned()))?;
            if count > 1 && !query.multiple() {
                return Err(SelectionError::MultipleNotAllowed {
                    id: id.to_owned(),
                    count,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dcql() -> DcqlQuery {
        serde_json::from_value(json!({
            "credentials": [
                { "id": "single", "format": "ldp_vc", "meta": {} },
                { "id": "many", "format": "ldp_vc", "meta": {}, "multiple": true },
                {
                    "id": "unbound",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["x"] },
                    "require_cryptographic_holder_binding": false
                }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn one_credential_per_query_is_always_allowed() {
        assert_eq!(dcql().check_multiple(["single", "many", "unbound"]), Ok(()));
        assert_eq!(dcql().check_multiple([]), Ok(()));
    }

    #[test]
    fn multiple_credentials_need_multiple() {
        assert_eq!(dcql().check_multiple(["many", "many", "many"]), Ok(()));
        assert_eq!(
            dcql().check_multiple(["many", "single", "unbound", "single"]),
            Err(SelectionError::MultipleNotAllowed {
                id: "single".into(),
                count: 2
            })
        );
    }

    #[test]
    fn the_first_offending_query_is_reported() {
        assert_eq!(
            dcql().check_multiple(["unbound", "single", "single", "unbound"]),
            Err(SelectionError::MultipleNotAllowed {
                id: "unbound".into(),
                count: 2
            })
        );
    }

    #[test]
    fn unknown_queries_are_rejected() {
        assert_eq!(
            dcql().check_multiple(["single", "other"]),
            Err(SelectionError::UnknownCredentialQuery("other".into()))
        );
    }

    #[test]
    fn holder_binding_defaults_to_required() {
        let dcql = dcql();
        assert!(dcql.requires_holder_binding("single"));
        assert!(!dcql.requires_holder_binding("unbound"));
        assert!(dcql.requires_holder_binding("other"));
    }

    #[test]
    fn finds_credential_queries_by_id() {
        let dcql = dcql();
        assert_eq!(dcql.credential_query("many").unwrap().id(), "many");
        assert!(dcql.credential_query("other").is_none());
    }
}
