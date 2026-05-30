use crate::credentials::{CredentialStore, MockCredential};
use crate::crypto::sign_issuer_jwt;
use crate::engine::{CredentialSelection, EngineError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openid4vp::core::dcql_query::{DcqlCredentialClaimsQueryPath, DcqlCredentialQuery, DcqlQuery};
use sha2::{Digest, Sha256};
use tracing::debug;

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
        let mut unmatched: Vec<String> = Vec::new();

        // Try to satisfy each credential query, but don't fail hard yet: a query
        // may belong to an optional `credential_sets` option, in which case it is
        // fine for it to go unmatched (OID4VP §6.1 DCQL credential_sets).
        for cred_query in query.credentials() {
            let cred_id = cred_query.id();
            debug!(cred_id, format = ?cred_query.format(), "Matching credential query");

            match self.match_credential_query(cred_query) {
                Ok(matched) => {
                    let requested = self.extract_required_claims(cred_query);
                    let presentation = reissue_sd_jwt(matched, &requested)?;
                    selection.add(cred_id, presentation);
                }
                Err(e) => {
                    debug!(cred_id, "credential query did not match: {e}");
                    unmatched.push(cred_id.to_string());
                }
            }
        }

        if let Some(cred_sets) = query.credential_sets() {
            // With credential_sets, every *required* set must have at least one
            // fully-matched option; unmatched credentials in optional sets are ok.
            for cred_set in cred_sets.iter() {
                if !cred_set.is_required() {
                    continue;
                }
                let satisfied = cred_set.options().iter().any(|option| {
                    option
                        .iter()
                        .all(|cred_id| selection.presentations.contains_key(cred_id))
                });
                if !satisfied {
                    return Err(EngineError::NoMatchingCredential(
                        "no matchable option for a required credential_set".to_string(),
                    ));
                }
            }
        } else if !unmatched.is_empty() {
            // Without credential_sets, every credential query is required.
            return Err(EngineError::NoMatchingCredential(format!(
                "no credential found for required query/queries: {}",
                unmatched.join(", ")
            )));
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

/// Re-issue a stored SD-JWT VC with a real issuer signature (HAIP `dc+sd-jwt`
/// header + `x5c`) and disclose only the requested claims.
///
/// The stored `raw_credential` provides the issuer claims (`iss`, `vct`, `cnf`,
/// `iat`, `exp`) and the disclosures; we recompute the `_sd` digests, sign a
/// fresh issuer JWT, and append only the disclosures whose claim name appears in
/// `requested` (none when no claims are requested, per OID4VP §6.4.1). The
/// returned string ends with `~` and carries no KB-JWT (added later).
fn reissue_sd_jwt(cred: &MockCredential, requested: &[String]) -> Result<String, EngineError> {
    let parts: Vec<&str> = cred.raw_credential.split('~').collect();
    let issuer_jwt = parts.first().copied().unwrap_or_default();

    // Disclosures are dot-free base64url segments; the issuer JWT and the mock
    // KB-JWT both contain '.', so filtering on '.' drops them.
    let disclosures: Vec<&str> = parts[1..]
        .iter()
        .copied()
        .filter(|p| !p.is_empty() && !p.contains('.'))
        .collect();

    // Decode the original issuer JWT payload to reuse its claims.
    let payload_b64 = issuer_jwt.split('.').nth(1).ok_or_else(|| {
        EngineError::Internal("stored credential issuer JWT is malformed".to_string())
    })?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| EngineError::Internal(format!("issuer JWT payload base64: {e}")))?;
    let original: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| EngineError::Internal(format!("issuer JWT payload JSON: {e}")))?;

    // Compute the _sd digest of every disclosure and map digests to claim names.
    let mut sd_digests = Vec::new();
    let mut name_by_disclosure: Vec<(String, &str)> = Vec::new();
    for d in &disclosures {
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(d.as_bytes()));
        sd_digests.push(serde_json::Value::String(digest));

        let decoded = URL_SAFE_NO_PAD
            .decode(d)
            .map_err(|e| EngineError::Internal(format!("disclosure base64: {e}")))?;
        let arr: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| EngineError::Internal(format!("disclosure JSON: {e}")))?;
        // Disclosure format: [salt, claim_name, value]
        let name = arr
            .get(1)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        name_by_disclosure.push((name, d));
    }

    // Build the fresh issuer payload, committing to all disclosures via `_sd`.
    let mut payload = serde_json::Map::new();
    for key in ["iss", "vct", "cnf", "iat", "exp", "sub"] {
        if let Some(v) = original.get(key) {
            payload.insert(key.to_string(), v.clone());
        }
    }
    payload.insert("_sd".to_string(), serde_json::Value::Array(sd_digests));
    payload.insert(
        "_sd_alg".to_string(),
        serde_json::Value::String("sha-256".to_string()),
    );

    let new_issuer_jwt = sign_issuer_jwt(&serde_json::Value::Object(payload))
        .map_err(|e| EngineError::CryptoError(e.to_string()))?;

    // Disclose only the requested claims (none when `requested` is empty).
    let mut out = new_issuer_jwt;
    for (name, disclosure) in &name_by_disclosure {
        if requested.iter().any(|r| r == name) {
            out.push('~');
            out.push_str(disclosure);
        }
    }
    out.push('~');
    Ok(out)
}
