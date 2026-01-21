//! Mock credentials for headless testing
//!
//! This module provides a simple in-memory credential store with pre-populated
//! mock credentials for conformance testing.

mod store;

pub use store::{CredentialStore, MockCredential};
