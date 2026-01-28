# Changelog

## [Unreleased]

### Added

- **DCQL (Digital Credentials Query Language)** support per Section 6:
  - `DcqlQuery` struct with `credentials` and optional `credential_sets` fields
  - `DcqlCredentialQuery` with all v1.0 fields including:
    - `meta`: REQUIRED object for format-specific constraints (default empty `{}`)
    - `trusted_authorities`: Array of trust framework objects (Section 6.1.1)
    - `require_cryptographic_holder_binding`: Boolean (default `true`)
    - `multiple`: Boolean (default `false`)
  - `TrustedAuthoritiesQuery` with types: `aki`, `etsi_tl`, `openid_federation`
  - `DcqlCredentialSetQuery` with `options` and `is_required()` (default `true`)
  - `DcqlCredentialClaimsQuery` with `path` (NonEmptyVec) and optional `values` (NonEmptyVec)
  - `AuthorizationRequestObject::dcql_query()` method for retrieving DCQL queries
- New authorization request parameters per Section 5.1:
  - `transaction_data`: Array of base64url-encoded transaction binding objects
  - `verifier_info`: Array of verifier attestation objects
  - `request_uri_method`: HTTP method selector (`get`/`post`) for request URI dereferencing
  - `expected_origins`: Array of expected origin strings for Digital Credentials API (Appendix A.2)
- New response modes for Digital Credentials API (Appendix A):
  - `dc_api`: Unencrypted response via DC API
  - `dc_api.jwt`: Encrypted (JARM) response via DC API
- New client identifier schemes per Section 5.9.3:
  - `x509_hash`: X.509 certificate hash-based identification
  - `verifier_attestation`: Verifier attestation JWT-based identification
  - `origin`: Reserved for Digital Credentials API (Wallet MUST reject)
- New `X509SanDnsClient` verifier client for `x509_san_dns` scheme
- **ISO 18013-7 mdoc support** for OID4VP v1.0 (Section B.2.6):
  - `Handover` struct for redirect flow per Section B.2.6.1
  - `DcApiHandover` struct for Digital Credentials API flow per Section B.2.6.2
  - `SessionTranscript` struct (`[null, null, Handover]`) for mdoc DeviceAuthentication
  - `compute_jwk_thumbprint()` function per RFC 7638
  - `get_encryption_jwk_thumbprint()` helper for extracting JWK thumbprint from request
  - Test vectors from specification Annex B
- **JWE builder** (`JweBuilder`) for encrypted authorization responses per Section 8.3:
  - `alg` is obtained from JWK's `alg` field (MUST be present per spec)
  - `enc` is obtained from `encrypted_response_enc_values_supported` (default: `A128GCM`)
  - `find_encryption_jwk()` returns `EncryptionJwkInfo` with `alg`, `kid`, and `jwk`
  - `kid` from JWK is propagated to JWE header when present
  - APU/APV parameters intentionally omitted (optional per spec, not used in v1.0)
- `x509_hash` client identifier scheme verification per Section 5.9.3.3
- `DcqlQuery::matching_credentials()` method for credential matching against queries
- Wallet `submit_response()` validates verifier response per Section 8.2:
  - Empty response body returns `Ok(None)` (no redirect required)
  - Invalid JSON returns explicit error
  - Invalid `redirect_uri` URL returns explicit error
  - Valid JSON with `redirect_uri` returns `Ok(Some(url))`

### Changed

- **BREAKING**: HTTP Prefer header updated from `OID4VP-0.0.20` to `OID4VP-1.0.0` (Note: This header is not required by the spec but kept for compatibility)
- **BREAKING**: Request Object JWT `typ` header changed to `oauth-authz-req+jwt` per Section 5
- **BREAKING**: Client identifier scheme constants renamed to match v1.0 spec (Section 5.9.3):
  - `DID` → `DECENTRALIZED_IDENTIFIER`
  - `ENTITY_ID` → `OPENID_FEDERATION`
- **BREAKING**: `RequestVerifier` trait method `did()` renamed to `decentralized_identifier()`
- **BREAKING**: `X509SanClient` renamed to `X509SanDnsClient` (simplified to DNS-only)
- **BREAKING**: `RequestBuilder` now uses `with_dcql_query()` instead of `with_presentation_definition()`
- **BREAKING**: `Session` struct now contains `dcql_query: DcqlQuery` instead of optional `presentation_definition`
- **BREAKING**: `VpToken` changed from `Vec<VpTokenItem>` to `HashMap<String, Vec<VpTokenItem>>` per Section 8.1:
  - Keys are credential query `id` values from the `dcql_query`
  - Values are arrays of Verifiable Presentations matching that query
  - New constructors: `VpToken::new()`, `VpToken::with_credential(id, presentations)`
  - New methods: `insert()`, `get()`, `is_empty()`, `len()`, `iter()`
- **BREAKING**: `UnencodedAuthorizationResponse` simplified for v1.0:
  - Removed `presentation_submission` field (not used in v1.0 with DCQL)
  - Removed `should_strip_quotes` field
  - New constructors: `new(vp_token)`, `with_state(vp_token, state)`
- **BREAKING**: `AuthorizationResponse::from_x_www_form_urlencoded()` no longer takes a boolean parameter
- **BREAKING**: `ResponseMode::default()` changed from `Unsupported("fragment")` to `DirectPost`
  - Fragment response mode is not valid for OID4VP v1.0
- **BREAKING**: Wallet metadata parameter renamed per Section 10.1:
  - `client_id_schemes_supported` → `client_id_prefixes_supported`
  - `WalletMetadata::add_client_id_schemes_supported()` → `add_client_id_prefixes_supported()`
- **BREAKING**: Verifier metadata key renamed per Section 11.1:
  - `VpFormats::KEY` changed from `vp_formats` to `vp_formats_supported`
### Removed

- **BREAKING**: Removed `presentation_definition` and `presentation_submission` modules entirely
  - Use `dcql_query::DcqlQuery` instead per OpenID4VP v1.0 spec
  - Use `response::parameters::VpToken` instead of `PresentationSubmission`
  - Removed all DIF Presentation Exchange test fixtures
- **BREAKING**: Removed `presentation_definition` and `presentation_definition_uri` parameters
  - Use `dcql_query` instead per OpenID4VP v1.0 spec
  - `AuthorizationRequestObject::resolve_presentation_definition()` removed
  - `PresentationDefinition` and `PresentationDefinitionUri` types removed from `authorization_request::parameters`
  - `PresentationDefinitionIndirection` enum removed
- **BREAKING**: Removed client identifier schemes not in v1.0 spec:
  - `HTTPS` (use `OPENID_FEDERATION` instead)
  - `WEB_ORIGIN`
  - `X509_SAN_URI` (use `X509_SAN_DNS` or `X509_HASH` instead)
- **BREAKING**: Removed `RequestVerifier` trait methods:
  - `web_origin()`
  - `x509_san_uri()`
- **BREAKING**: Removed `X509SanVariant` enum (no longer needed)
- **BREAKING**: Removed `client_metadata_uri` parameter (not in v1.0 spec)
  - `ClientMetadataUri` type removed from `authorization_request::parameters`
  - `ClientMetadata::resolve()` no longer takes HTTP client parameter (metadata must be inline)
- **BREAKING**: Removed `maximize_interoperability` feature flag
  - No longer needed; library now targets v1.0 compliance exclusively
- **BREAKING**: Removed `input_descriptor` module entirely
  - Use `dcql_query` module instead for credential queries
- **BREAKING**: Removed JARM parameters from verifier metadata (not in OID4VP v1.0):
  - `AuthorizationEncryptedResponseAlg` - use JWK's `alg` field instead
  - `AuthorizationEncryptedResponseEnc` - use `EncryptedResponseEncValuesSupported` instead
  - `AuthorizationSignedResponseAlg` - not used in v1.0
  - `RequireSignedRequestObject` - not used in v1.0
- **BREAKING**: Removed `ClientMetadata` methods (replaced by v1.0 approach):
  - `authorization_signed_response_alg()` - not in v1.0
  - `authorization_encrypted_response_alg()` - use JWK's `alg` field
  - `authorization_encrypted_response_enc()` - use `encrypted_response_enc_values_supported()`

## [0.1.0]

Initial release supporting OpenID4VP Draft 20.
