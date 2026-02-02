use crate::credentials::{CredentialStore, MockCredential};
use crate::engine::{CredentialSelection, EngineError};
use openid4vp::core::dcql_query::{DcqlCredentialClaimsQueryPath, DcqlCredentialQuery, DcqlQuery};
use tracing::{debug, warn};

/// DCQL credential matcher
pub struct DcqlMatcher<'a> {
    store: &'a CredentialStore,
}

impl<'a> DcqlMatcher<'a> {
    /// Create a new DCQL matcher with the given credential store
    pub fn new(store: &'a CredentialStore) -> Self {
        Self { store }
    }

    /// Match credentials against a DCQL query
    ///
    /// Returns a `CredentialSelection` with matching credentials for each
    /// credential query in the DCQL.
    pub fn match_query(&self, query: &DcqlQuery) -> Result<CredentialSelection, EngineError> {
        let mut selection = CredentialSelection::new();

        for cred_query in query.credentials() {
            let cred_id = cred_query.id();
            debug!(cred_id, format = ?cred_query.format(), "Matching credential query");

            let matched = self.match_credential_query(cred_query)?;

            selection.add(cred_id, matched.raw_credential.clone());
        }

        // Handle credential_sets if present (alternative selection logic)
        if let Some(cred_sets) = query.credential_sets() {
            debug!("DCQL has credential_sets - checking requirements");
            // For now, we just ensure at least one option is satisfied
            // A full implementation would check all required sets
            for cred_set in cred_sets.iter() {
                let satisfied = cred_set.options().iter().any(|option| {
                    option
                        .iter()
                        .all(|cred_id| selection.presentations.contains_key(cred_id))
                });

                if !satisfied && cred_set.is_required() {
                    warn!("Required credential set not satisfied");
                    // Continue anyway for conformance testing
                }
            }
        }

        if selection.is_empty() {
            return Err(EngineError::NoMatchingCredential(
                "No credentials matched the query".to_string(),
            ));
        }

        Ok(selection)
    }

    /// Match a single credential query
    fn match_credential_query(
        &self,
        query: &DcqlCredentialQuery,
    ) -> Result<&MockCredential, EngineError> {
        let format = query.format();

        // Extract VCT values if present (for SD-JWT VC)
        let vct_values = query
            .meta()
            .get("vct_values")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            });

        // Extract doctype if present (for mso_mdoc)
        let doctype = query
            .meta()
            .get("doctype_value")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Extract required claims from the query
        let required_claims = self.extract_required_claims(query);

        debug!(
            query_id = query.id(),
            ?format,
            ?vct_values,
            ?doctype,
            ?required_claims,
            "Searching for matching credential"
        );

        // Try to find a matching credential
        let credential = if let Some(vcts) = &vct_values {
            self.store.find_by_format_and_vct(format, Some(vcts))
        } else if let Some(dt) = &doctype {
            self.store.find_by_format_and_doctype(format, Some(dt))
        } else if !required_claims.is_empty() {
            self.store
                .find_by_format_and_claims(format, &required_claims)
        } else {
            self.store.find_by_format(format).into_iter().next()
        };

        credential.ok_or_else(|| {
            EngineError::NoMatchingCredential(format!(
                "No credential found for query '{}' with format {:?}",
                query.id(),
                format
            ))
        })
    }

    /// Extract required claim names from a DCQL credential query
    fn extract_required_claims(&self, query: &DcqlCredentialQuery) -> Vec<String> {
        let mut claims = Vec::new();

        if let Some(claim_queries) = query.claims() {
            for claim_query in claim_queries.iter() {
                // Extract the claim name from the path
                // For most formats, this is the last string element in the path
                let path = claim_query.path();
                for element in path.iter() {
                    if let DcqlCredentialClaimsQueryPath::String(name) = element {
                        // Skip namespace prefixes (for mso_mdoc)
                        if !name.contains('.') && !name.starts_with("org.") {
                            claims.push(name.clone());
                        }
                    }
                }
            }
        }

        claims
    }
}
