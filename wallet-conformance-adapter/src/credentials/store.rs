use openid4vp::core::credential_format::ClaimFormatDesignation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// A mock credential for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockCredential {
    /// Unique identifier for this credential
    pub id: String,
    /// Credential format (dc+sd-jwt, etc.)
    pub format: ClaimFormatDesignation,
    /// Verifiable Credential Type (for SD-JWT VC)
    pub vct: Option<String>,
    /// Document type (for mso_mdoc)
    #[serde(default)]
    pub doctype: Option<String>,
    /// Pre-built raw credential string (SD-JWT, etc.)
    pub raw_credential: String,
    /// Claims contained in this credential
    pub claims: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CredentialsFile {
    credentials: Vec<CredentialConfig>,
}

#[derive(Debug, Deserialize)]
struct CredentialConfig {
    id: String,
    format: String,
    #[serde(default)]
    vct: Option<String>,
    #[serde(default)]
    doctype: Option<String>,
    raw_credential: String,
    claims: HashMap<String, serde_json::Value>,
}

pub struct CredentialStore {
    credentials: Vec<MockCredential>,
}

impl CredentialStore {
    /// Create a store with embedded mock credentials
    pub fn with_mock_credentials() -> Self {
        let json = include_str!("../../credentials.json");
        let file: CredentialsFile =
            serde_json::from_str(json).expect("Failed to parse embedded credentials.json");

        let credentials: Vec<MockCredential> = file
            .credentials
            .into_iter()
            .map(|config| MockCredential {
                id: config.id,
                format: parse_format(&config.format),
                vct: config.vct,
                doctype: config.doctype,
                raw_credential: config.raw_credential,
                claims: config.claims,
            })
            .collect();

        info!(count = credentials.len(), "Loaded credentials");
        Self { credentials }
    }

    pub fn find_by_format(&self, format: &ClaimFormatDesignation) -> Vec<&MockCredential> {
        self.credentials
            .iter()
            .filter(|cred| format_matches(&cred.format, format))
            .collect()
    }

    /// Find a credential by format and VCT (for SD-JWT VC)
    pub fn find_by_format_and_vct(
        &self,
        format: &ClaimFormatDesignation,
        vct_values: Option<&[String]>,
    ) -> Option<&MockCredential> {
        self.credentials.iter().find(|cred| {
            if !format_matches(&cred.format, format) {
                return false;
            }

            if let Some(vcts) = vct_values {
                if let Some(cred_vct) = &cred.vct {
                    return vcts.iter().any(|v| v == cred_vct);
                }
                return false;
            }

            true
        })
    }

    /// Find a credential by format and doctype (for mso_mdoc)
    pub fn find_by_format_and_doctype(
        &self,
        format: &ClaimFormatDesignation,
        doctype: Option<&str>,
    ) -> Option<&MockCredential> {
        self.credentials.iter().find(|cred| {
            if !format_matches(&cred.format, format) {
                return false;
            }

            if let Some(dt) = doctype {
                if let Some(cred_dt) = &cred.doctype {
                    return cred_dt == dt;
                }
                return false;
            }

            true
        })
    }

    /// Find the first credential matching the format that has the required claims
    pub fn find_by_format_and_claims(
        &self,
        format: &ClaimFormatDesignation,
        required_claims: &[String],
    ) -> Option<&MockCredential> {
        self.credentials.iter().find(|cred| {
            if !format_matches(&cred.format, format) {
                return false;
            }

            required_claims
                .iter()
                .all(|claim| cred.claims.contains_key(claim))
        })
    }

    /// Get the number of credentials
    pub fn count(&self) -> usize {
        self.credentials.len()
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::with_mock_credentials()
    }
}

/// Check if two formats match (case-insensitive for SD-JWT variants)
fn format_matches(
    cred_format: &ClaimFormatDesignation,
    query_format: &ClaimFormatDesignation,
) -> bool {
    match (cred_format, query_format) {
        (ClaimFormatDesignation::Other(a), ClaimFormatDesignation::Other(b)) => {
            a.to_lowercase() == b.to_lowercase()
        }
        _ => false,
    }
}

fn parse_format(format: &str) -> ClaimFormatDesignation {
    ClaimFormatDesignation::Other(format.to_string())
}
