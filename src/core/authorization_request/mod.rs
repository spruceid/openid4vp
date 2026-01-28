use std::ops::{Deref, DerefMut};

use anyhow::{anyhow, bail, Context, Error, Result};
use base64::prelude::*;
use parameters::{ClientMetadata, State};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use url::Url;

use crate::wallet::Wallet;

use self::{
    parameters::{
        ClientId, ClientIdScheme, Nonce, RedirectUri, ResponseMode, ResponseType, ResponseUri,
    },
    verification::verify_request,
};

use super::{
    dcql_query::DcqlQuery,
    metadata::parameters::verifier::VpFormats,
    object::{ParsingErrorContext, UntypedObject},
    util::{base_request, AsyncHttpClient},
};

/// Required `typ` header value for Request Objects per OID4VP v1.0 Section 5.
const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

pub mod parameters;
pub mod verification;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "UntypedObject", into = "UntypedObject")]
pub struct AuthorizationRequestObject {
    inner: UntypedObject,
    client_id: Option<ClientId>,
    client_id_scheme: Option<ClientIdScheme>,
    response_mode: ResponseMode,
    response_type: ResponseType,
    return_uri: Url,
    nonce: Nonce,
}

/// An Authorization Request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_id: Option<String>,
    #[serde(flatten)]
    pub request_indirection: RequestIndirection,
}

/// A RequestObject, passed by value or by reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum RequestIndirection {
    ByValue { request: String },
    ByReference { request_uri: Url },
    Direct(UntypedObject),
}

impl AuthorizationRequest {
    /// Validate the [AuthorizationRequest] according to the Client Identifier Prefix and return
    /// the parsed [AuthorizationRequestObject].
    ///
    /// Per OID4VP v1.0 Section 5, this validates:
    /// - The `typ` header of Request Objects (MUST be `oauth-authz-req+jwt`)
    /// - The Client Identifier Prefix rules per Section 5.9
    /// - The response mode requirements
    ///
    /// Custom wallet metadata can be provided, otherwise the default metadata for this profile is used.
    pub async fn validate<W: Wallet + ?Sized>(
        self,
        wallet: &W,
    ) -> Result<AuthorizationRequestObject> {
        let (aro, jwt) = self.resolve_request(wallet.http_client()).await?;
        verify_request(wallet, &aro, jwt)
            .await
            .context("unable to validate Authorization Request")?;
        let aro_client_id_raw = aro
            .get::<ClientId>()
            .map(|c| c.parsing_error().map(|c| c.0))
            .transpose()?;
        if let (Some(x), Some(y)) = (self.client_id, aro_client_id_raw) {
            if x != y {
                bail!("Authorization Request and Request Object have different client ids: '{x}' vs. '{y}'");
            }
        }
        Ok(aro)
    }

    /// Returns the authorization request object and the JWT if it exists.
    ///
    /// Per OID4VP v1.0 Section 5, when a Request Object JWT is present,
    /// the `typ` header MUST be `oauth-authz-req+jwt`.
    ///
    /// Note: For `redirect_uri` prefix, Section 5.9.3 states "The Authorization Request
    /// MUST NOT be signed", so typ validation is relaxed for that case.
    pub async fn resolve_request<H: AsyncHttpClient>(
        &self,
        http_client: &H,
    ) -> Result<(AuthorizationRequestObject, Option<String>)> {
        // Check if this is a redirect_uri prefix (unsigned requests per Section 5.9.3)
        let is_redirect_uri_prefix = self
            .client_id
            .as_ref()
            .map(|c| c.starts_with("redirect_uri:"))
            .unwrap_or(false);

        match &self.request_indirection {
            RequestIndirection::ByValue { request: jwt } => {
                validate_request_object_typ(jwt, is_redirect_uri_prefix)?;
                let aro: AuthorizationRequestObject =
                    ssi::claims::jwt::decode_unverified::<UntypedObject>(jwt)
                        .context("unable to decode Authorization Request Object JWT")?
                        .try_into()?;
                Ok((aro, Some(jwt.clone())))
            }
            RequestIndirection::ByReference { request_uri: url } => {
                let request = base_request()
                    .method("GET")
                    .uri(url.to_string())
                    .body(vec![])
                    .context("failed to build authorization request request")?;

                let response = http_client.execute(request).await.context(format!(
                    "failed to make authorization request request at {url}"
                ))?;

                let status = response.status();
                let Ok(body) = String::from_utf8(response.into_body()) else {
                    bail!("failed to parse authorization request response as UTF-8 from {url} (status: {status})")
                };

                if !status.is_success() {
                    bail!(
                        "authorization request request was unsuccessful (status: {status}): {body}"
                    )
                }

                validate_request_object_typ(&body, is_redirect_uri_prefix)?;
                let aro: AuthorizationRequestObject =
                    ssi::claims::jwt::decode_unverified::<UntypedObject>(&body)
                        .context("unable to decode Authorization Request Object JWT")?
                        .try_into()?;

                Ok((aro, Some(body)))
            }
            RequestIndirection::Direct(untyped_object) => {
                // Direct requests (unsigned) don't have a typ header to validate
                let mut untyped_object = untyped_object.clone();
                if let Some(client_id) = self.client_id.clone() {
                    untyped_object.insert(ClientId(client_id));
                }
                let aro: AuthorizationRequestObject = untyped_object.try_into()?;
                Ok((aro, None))
            }
        }
    }

    /// Encode as [Url], using the `authorization_endpoint` as a base.
    /// ```
    /// # use openid4vp::core::authorization_request::AuthorizationRequest;
    /// # use openid4vp::core::authorization_request::RequestIndirection;
    /// # use url::Url;
    /// let authorization_endpoint: Url = "example://".parse().unwrap();
    /// let authorization_request = AuthorizationRequest {
    ///     client_id: Some("xyz".to_string()),
    ///     request_indirection: RequestIndirection::ByValue{request: "test".to_string()},
    /// };
    ///
    /// let authorization_request_url = authorization_request.to_url(authorization_endpoint).unwrap();
    ///
    /// assert_eq!(authorization_request_url.as_str(), "example://?client_id=xyz&request=test");
    /// ```
    pub fn to_url(self, mut authorization_endpoint: Url) -> Result<Url> {
        let query = serde_urlencoded::to_string(self)?;
        authorization_endpoint.set_query(Some(&query));
        Ok(authorization_endpoint)
    }

    /// Parse from [Url], validating the authorization_endpoint.
    /// ```
    /// # use openid4vp::core::authorization_request::AuthorizationRequest;
    /// # use openid4vp::core::authorization_request::RequestIndirection;
    /// # use url::Url;
    /// let url: Url = "example://?client_id=xyz&request=test".parse().unwrap();
    /// let authorization_endpoint: Url = "example://".parse().unwrap();
    ///
    /// let authorization_request = AuthorizationRequest::from_url(
    ///     url,
    ///     &authorization_endpoint
    /// ).unwrap();
    ///
    /// assert_eq!(authorization_request.client_id.unwrap(), "xyz");
    ///
    /// let RequestIndirection::ByValue{request: request_object} =
    ///     authorization_request.request_indirection
    /// else {
    ///     panic!("expected request-by-value")
    /// };
    ///
    /// assert_eq!(request_object, "test");
    /// ```
    pub fn from_url(url: Url, authorization_endpoint: &Url) -> Result<Self> {
        let query = url
            .query()
            .ok_or(anyhow!("missing query params in Authorization Request uri"))?
            .to_string();
        let fnd = url.authority();
        let exp = authorization_endpoint.authority();
        if fnd != exp {
            bail!("unexpected authorization_endpoint authority, expected '{exp}', received '{fnd}'")
        }
        let fnd = url.path();
        let exp = authorization_endpoint.path();
        if fnd != exp {
            bail!("unexpected authorization_endpoint path, expected '{exp}', received '{fnd}'")
        }
        Self::from_query_params(&query)
    }

    /// Parse from urlencoded query parameters.
    /// ```
    /// # use openid4vp::core::authorization_request::AuthorizationRequest;
    /// # use openid4vp::core::authorization_request::RequestIndirection;
    /// let query = "client_id=xyz&request=test";
    ///
    /// let authorization_request = AuthorizationRequest::from_query_params(query).unwrap();
    ///
    /// assert_eq!(authorization_request.client_id.unwrap(), "xyz");
    ///
    /// let RequestIndirection::ByValue{request: request_object} = authorization_request.request_indirection
    /// else { panic!("expected request-by-value") };
    /// assert_eq!(request_object, "test");
    /// ```
    pub fn from_query_params(query_params: &str) -> Result<Self> {
        serde_urlencoded::from_str(query_params)
            .context("unable to parse Authorization Request from query params")
    }
}

impl AuthorizationRequestObject {
    pub fn client_id(&self) -> Option<&ClientId> {
        self.client_id.as_ref()
    }

    pub fn client_id_scheme(&self) -> Option<&ClientIdScheme> {
        self.client_id_scheme.as_ref()
    }

    /// Return the `dcql_query` from the authorization request.
    ///
    /// `dcql_query` is the mechanism for specifying credential requirements.
    /// Either `dcql_query` or `scope` (as a DCQL alias) MUST be present, but not both.
    /// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1
    pub fn dcql_query(&self) -> Option<Result<DcqlQuery>> {
        self.get()
    }

    pub fn is_id_token_requested(&self) -> Option<bool> {
        match self.response_type {
            ResponseType::VpToken => Some(false),
            ResponseType::VpTokenIdToken => Some(true),
            ResponseType::Unsupported(_) => None,
        }
    }

    pub fn response_mode(&self) -> &ResponseMode {
        &self.response_mode
    }

    pub fn response_type(&self) -> &ResponseType {
        &self.response_type
    }

    /// Uri to submit the response at.
    ///
    /// AKA [ResponseUri] or [RedirectUri] depending on [ResponseMode].
    pub fn return_uri(&self) -> &Url {
        &self.return_uri
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Return the `client_metadata` field from the authorization request.
    pub fn client_metadata(&self) -> Result<ClientMetadata> {
        self.get()
            .ok_or(anyhow!("missing `client_metadata` object"))?
    }

    /// Return the `VpFormats` from the `client_metadata` field.
    pub fn vp_formats(&self) -> Result<VpFormats> {
        self.client_metadata()?
            .0
            .get()
            .ok_or(anyhow!("missing vp_formats"))?
    }

    /// Return the `state` of the authorization request,
    /// if it was provided.
    pub fn state(&self) -> Option<Result<State>> {
        self.get()
    }
}

impl From<AuthorizationRequestObject> for UntypedObject {
    fn from(value: AuthorizationRequestObject) -> Self {
        value.inner
    }
}

impl TryFrom<UntypedObject> for AuthorizationRequestObject {
    type Error = Error;

    fn try_from(value: UntypedObject) -> std::result::Result<Self, Self::Error> {
        let client_id = value
            .get::<ClientId>()
            .map(|c| c.parsing_error())
            .transpose()?;
        let client_id_scheme = client_id.as_ref().and_then(|c| c.resolve_prefix());

        let redirect_uri = value.get::<RedirectUri>();
        let response_uri = value.get::<ResponseUri>();

        let (return_uri, response_mode) = match (
            redirect_uri,
            response_uri,
            value.get_or_default::<ResponseMode>().parsing_error()?,
        ) {
            (_, _, ResponseMode::Unsupported(m)) => {
                bail!("this 'response_mode' ({m}) is not currently supported")
            }
            (Some(_), Some(_), _) => {
                bail!("'response_uri' and 'redirect_uri' are mutually exclusive")
            }
            (_, None, response_mode @ ResponseMode::DirectPost)
            | (_, None, response_mode @ ResponseMode::DirectPostJwt) => {
                bail!("'response_uri' is required for this 'response_mode' ({response_mode})")
            }
            (_, Some(uri), response_mode @ ResponseMode::DirectPost)
            | (_, Some(uri), response_mode @ ResponseMode::DirectPostJwt) => {
                (uri.parsing_error()?.0, response_mode)
            }
            (_, Some(_), response_mode @ ResponseMode::DcApi)
            | (_, Some(_), response_mode @ ResponseMode::DcApiJwt) => {
                bail!("'response_uri' cannot be present for this 'response_mode' ({response_mode})")
            }
            (Some(_), _, response_mode @ ResponseMode::DcApi)
            | (Some(_), _, response_mode @ ResponseMode::DcApiJwt) => {
                bail!("'redirect_uri' cannot be present for this 'response_mode' ({response_mode})")
            }
            (None, None, response_mode @ ResponseMode::DcApi)
            | (None, None, response_mode @ ResponseMode::DcApiJwt) => {
                ("https://example.com".parse()?, response_mode)
            }
        };

        let response_type: ResponseType = value.get().parsing_error()?;

        let nonce = value.get().parsing_error()?;

        Ok(Self {
            inner: value,
            client_id,
            client_id_scheme,
            response_mode,
            response_type,
            return_uri,
            nonce,
        })
    }
}

impl Deref for AuthorizationRequestObject {
    type Target = UntypedObject;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for AuthorizationRequestObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Validates that a Request Object JWT has the required `typ` header.
///
/// Per OID4VP v1.0 Section 5:
/// "Wallets MUST NOT process Request Objects where the `typ` Header Parameter
/// is not present or does not have the value `oauth-authz-req+jwt`."
///
/// However, for `redirect_uri` prefix (Section 5.9.3), "The Authorization Request
/// MUST NOT be signed", so we relax validation for that case since it shouldn't
/// be a JWT at all per the spec.
fn validate_request_object_typ(jwt: &str, is_redirect_uri_prefix: bool) -> Result<()> {
    let (headers_b64, _, _) = ssi::claims::jws::split_jws(jwt).context("invalid JWT structure")?;

    let headers_json_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(headers_b64)
        .context("JWT headers were not valid base64url")?;

    let headers: Map<String, Json> =
        serde_json::from_slice(&headers_json_bytes).context("JWT headers were not valid JSON")?;

    let typ = headers.get("typ").and_then(|v| v.as_str());

    match typ {
        Some(t) if t == REQUEST_OBJECT_TYP => Ok(()),
        Some(t) => {
            if is_redirect_uri_prefix {
                // For redirect_uri, the request shouldn't be signed per spec,
                // so we're lenient about typ header
                tracing::warn!(
                    "Request Object has incorrect 'typ' header '{}' (expected '{}'), \
                    but allowing for redirect_uri prefix per Section 5.9.3",
                    t,
                    REQUEST_OBJECT_TYP
                );
                Ok(())
            } else {
                bail!(
                    "Request Object 'typ' header must be '{}', found '{}' (per OID4VP v1.0 Section 5)",
                    REQUEST_OBJECT_TYP,
                    t
                )
            }
        }
        None => {
            if is_redirect_uri_prefix {
                // For redirect_uri, the request shouldn't be signed per spec,
                // so we're lenient about typ header
                tracing::warn!(
                    "Request Object missing 'typ' header (expected '{}'), \
                    but allowing for redirect_uri prefix per Section 5.9.3",
                    REQUEST_OBJECT_TYP
                );
                Ok(())
            } else {
                bail!("Request Object missing required 'typ' header (per OID4VP v1.0 Section 5)")
            }
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn deserialize_authorization_request_object() {
        // Using DCQL (Digital Credentials Query Language) format per OID4VP v1.0
        let json = json!({
          "aud": "https://self-issued.me/v2",
          "response_type": "vp_token",
          "dcql_query": {
            "credentials": [
              {
                "id": "my_credential",
                "format": "mso_mdoc",
                "meta": {
                  "doctype_value": "org.iso.18013.5.1.mDL"
                },
                "claims": [
                  { "namespace": "org.iso.18013.5.1", "claim_name": "family_name" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "given_name" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "birth_date" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "issue_date" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "expiry_date" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "issuing_country" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "issuing_authority" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "document_number" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "portrait" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "driving_privileges" },
                  { "namespace": "org.iso.18013.5.1", "claim_name": "un_distinguishing_sign" }
                ]
              }
            ]
          },
          "client_metadata": {
            "jwks": {
              "keys": [
                {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "StF0H4foaK2f_ed4aw6FwNALrHz7FkGk5Iz9TtiRjyo",
                  "y": "OCgRLGrs6lZHp1Rye2xJ3r9aXdMP1DcoeQuNpA0ryn8",
                  "kid": "f67813a4-7a2a-4c39-b290-c0d03f372400",
                  "alg": "ECDH-ES",
                  "use": "enc"
                }
              ]
            },
            "authorization_encrypted_response_enc": "A256GCM",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "vp_formats": {
              "mso_mdoc": {
                "alg": [
                  "ES256",
                  "ES384",
                  "ES512",
                  "EdDSA"
                ]
              }
            },
            "require_signed_request_object": true
          },
          "state": "134ea6fe-cfe9-4243-b349-d00a8edb38e4",
          "nonce": "mG2Xi1nVIIepJ7fwwj5qjNgNzp7KOYOhJbvAlbKCJYI",
          "client_id": "labs-online-presentation-sample-app.vii.au01.mattr.global",
          "client_id_scheme": "x509_san_dns",
          "response_mode": "direct_post.jwt",
          "response_uri": "https://labs-online-presentation-sample-app.vii.au01.mattr.global/v2/presentations/sessions/response"
        });
        let untyped_object: UntypedObject = serde_json::from_value(json).unwrap();
        let authorization_request_object: AuthorizationRequestObject =
            untyped_object.try_into().unwrap();
        assert_eq!(
            authorization_request_object.response_mode,
            ResponseMode::DirectPostJwt
        );
    }

    #[test]
    fn deserialize_authorization_request_object_jwt() {
        let jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjJlYzI5MDFlLTc2Y2EtNDE2Yy04ODBlLTgzY2U2ODkzYjdkYSIsIng1YyI6WyJNSUlEb2pDQ0EwbWdBd0lCQWdJS1pXSlM1RGVsN3BxTXd6QUtCZ2dxaGtqT1BRUURBakJhTVFzd0NRWURWUVFHRXdKT1dqRkxNRWtHQTFVRUF3eENiR0ZpY3kxdmJteHBibVV0Y0hKbGMyVnVkR0YwYVc5dUxYTmhiWEJzWlMxaGNIQXVkbWxwTG1GMU1ERXViV0YwZEhJdVoyeHZZbUZzSUZabGNtbG1hV1Z5TUI0WERUSTFNRFV4TXpFd016ZzFNMW9YRFRJMU1URXhNVEV3TXpnMU0xb3daekVMTUFrR0ExVUVCaE1DVGxveFdEQldCZ05WQkFNTVQyeGhZbk10YjI1c2FXNWxMWEJ5WlhObGJuUmhkR2x2YmkxellXMXdiR1V0WVhCd0xuWnBhUzVoZFRBeExtMWhkSFJ5TG1kc2IySmhiQ0JTWldGa1pYSWdRWFYwYUdWdWRHbGpZWFJwYjI0d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSMDFRd0wxc0dlMjV4Z3Z5cVBMQ3V4TE5HbTVrcDJxbmd3MVEvallGODhwSHI2YVpvZHJaMjF3OXZ0TWFtZE1Vd3k5RlU2WitSMy94S0xobm5LNTF2OG80SUI2RENDQWVRd0hRWURWUjBPQkJZRUZBenpMc2hpaGZJRytheTBVWlgzZW43cVlBRjNNQTRHQTFVZER3RUIvd1FFQXdJSGdEQk1CZ05WSFJJRVJUQkRoa0ZvZEhSd2N6b3ZMMnhoWW5NdGIyNXNhVzVsTFhCeVpYTmxiblJoZEdsdmJpMXpZVzF3YkdVdFlYQndMblpwYVM1aGRUQXhMbTFoZEhSeUxtZHNiMkpoYkRDQmlBWURWUjBSQklHQU1INkdRV2gwZEhCek9pOHZiR0ZpY3kxdmJteHBibVV0Y0hKbGMyVnVkR0YwYVc5dUxYTmhiWEJzWlMxaGNIQXVkbWxwTG1GMU1ERXViV0YwZEhJdVoyeHZZbUZzZ2psc1lXSnpMVzl1YkdsdVpTMXdjbVZ6Wlc1MFlYUnBiMjR0YzJGdGNHeGxMV0Z3Y0M1MmFXa3VZWFV3TVM1dFlYUjBjaTVuYkc5aVlXd3dnWjhHQTFVZEh3U0JsekNCbERDQmthQ0JqcUNCaTRhQmlHaDBkSEJ6T2k4dmJHRmljeTF2Ym14cGJtVXRjSEpsYzJWdWRHRjBhVzl1TFhOaGJYQnNaUzFoY0hBdWRtbHBMbUYxTURFdWJXRjBkSEl1WjJ4dlltRnNMM1l5TDNCeVpYTmxiblJoZEdsdmJuTXZZMlZ5ZEdsbWFXTmhkR1Z6THprMk1tRTNaakJoTFdFek1EUXROREEzWmkxaFlqaG1MV1k0WTJJME5qbGxZVFpoTUM5amNtd3dId1lEVlIwakJCZ3dGb0FVN1Nidlk0cjhsMzhFOGJ0eE1nbk9YbnNaaGVnd0Z3WURWUjBsQVFIL0JBMHdDd1lKS3dZQkJBR0Q0R29DTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUQ3TXRsSXBxaU51Qi91MmtaOEdwcUNNNGRUYXE2aVJnSXlRNkR0NnNxSlhBaUErWFhEK0ZHRGZxcFNPSkNrSE1hcVZDUGwyUTI0MlhNdjh1b3huS3d4RjZnPT0iXX0.eyJhdWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiJjNWE4NzQ2ZS0wMmIwLTRmYTUtODcyZi02NDQ5YmQ2ZTVjNGEiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJvcmcuaXNvLjE4MDEzLjUuMS5tREwiLCJmb3JtYXQiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2ZhbWlseV9uYW1lJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6dHJ1ZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2dpdmVuX25hbWUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjp0cnVlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnYmlydGhfZGF0ZSddIl0sImludGVudF90b19yZXRhaW4iOnRydWV9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydpc3N1ZV9kYXRlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6dHJ1ZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2V4cGlyeV9kYXRlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6dHJ1ZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2lzc3VpbmdfY291bnRyeSddIl0sImludGVudF90b19yZXRhaW4iOnRydWV9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydpc3N1aW5nX2F1dGhvcml0eSddIl0sImludGVudF90b19yZXRhaW4iOnRydWV9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydkb2N1bWVudF9udW1iZXInXSJdLCJpbnRlbnRfdG9fcmV0YWluIjp0cnVlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsncG9ydHJhaXQnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjp0cnVlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnZHJpdmluZ19wcml2aWxlZ2VzJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6dHJ1ZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ3VuX2Rpc3Rpbmd1aXNoaW5nX3NpZ24nXSJdLCJpbnRlbnRfdG9fcmV0YWluIjp0cnVlfV0sImxpbWl0X2Rpc2Nsb3N1cmUiOiJyZXF1aXJlZCJ9fV19LCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ik5CaDY0NTdPRTFlMk1kSkZWNk9KRGxWdC1UeXZjaU1Tc1RzcHRIdHNFY0kiLCJ5IjoiWE9zMk5OdGtGTkpvXzE5eHZldGhpYnFUM29qNmRpUDVzNXplSnE0NXFmYyIsImtpZCI6ImEyODMwYThlLTFiZjQtNDlmOS04MjNiLTJhZmJhMjU0MmRkMyIsImFsZyI6IkVDREgtRVMiLCJ1c2UiOiJlbmMifV19LCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIiwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiRUNESC1FUyIsInZwX2Zvcm1hdHMiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2IiwiRVMzODQiLCJFUzUxMiIsIkVkRFNBIl19fSwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3QiOnRydWV9LCJzdGF0ZSI6IjFiNmYyYzdlLTcxZDEtNGE4Ny1iYWIyLTE2MmM3N2FjNjEyYSIsIm5vbmNlIjoiODdZSGNNYm9ZRUVFaUlsZ1YxQ2VkcVNlbzFBVmRReXNjbHFiZHVGUG15MCIsImNsaWVudF9pZCI6ImxhYnMtb25saW5lLXByZXNlbnRhdGlvbi1zYW1wbGUtYXBwLnZpaS5hdTAxLm1hdHRyLmdsb2JhbCIsImNsaWVudF9pZF9zY2hlbWUiOiJ4NTA5X3Nhbl9kbnMiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3Quand0IiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly9sYWJzLW9ubGluZS1wcmVzZW50YXRpb24tc2FtcGxlLWFwcC52aWkuYXUwMS5tYXR0ci5nbG9iYWwvdjIvcHJlc2VudGF0aW9ucy9zZXNzaW9ucy9yZXNwb25zZSJ9.RvoIxCU0xznb-MkUvoSCavj4C60dn8Jn3PVoGGmxBk6kO5Uf2iHfxjb8M4I-hEWs9XxjSBJQolgM5PqFeyXl6A";
        let authorization_request_object: AuthorizationRequestObject =
            ssi::claims::jwt::decode_unverified::<UntypedObject>(jwt)
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            authorization_request_object.response_mode,
            ResponseMode::DirectPostJwt
        );
    }
    #[test]
    fn deserialize_authorization_request_url() {
        let url: Url = "mdoc-openid4vp://?client_id=api.verify.spruceid.xyz&request_uri=https%3A%2F%2Fapi.verify.spruceid.xyz%2Fsessions%2Fcadmv%2Frequest%2F0fc25eb0-f845-4733-9c4c-fae695c9c04c".parse().unwrap();
        let authorization_endpoint: Url = "example://".parse().unwrap();
        let req = AuthorizationRequest::from_url(url, &authorization_endpoint).unwrap();
        let expected = RequestIndirection::ByReference{request_uri: "https://api.verify.spruceid.xyz/sessions/cadmv/request/0fc25eb0-f845-4733-9c4c-fae695c9c04c".parse().unwrap()};
        assert_eq!(req.request_indirection, expected);
    }

    #[test]
    fn deserialize_authorization_request_url_with_scheme() {
        let url: Url = "mdoc-openid4vp://?client_id=labs-online-presentation-sample-app.vii.au01.mattr.global&client_id_scheme=x509_san_dns&request_uri=https%3A%2F%2Flabs-online-presentation-sample-app.vii.au01.mattr.global%2Fv2%2Fpresentations%2Fsessions%2Ff7e72833-6f3f-4385-b9dd-3a4ea9453948%2Frequests%2Ff7286044-4c94-4ccf-9956-29a8cc6d0687".parse().unwrap();
        let authorization_endpoint: Url = "example://".parse().unwrap();
        let req = AuthorizationRequest::from_url(url, &authorization_endpoint).unwrap();
        let expected = RequestIndirection::ByReference{request_uri:"https://labs-online-presentation-sample-app.vii.au01.mattr.global/v2/presentations/sessions/f7e72833-6f3f-4385-b9dd-3a4ea9453948/requests/f7286044-4c94-4ccf-9956-29a8cc6d0687".parse().unwrap()};
        assert_eq!(req.request_indirection, expected);
    }

    #[test]
    fn validate_request_object_typ_valid() {
        // JWT with correct typ header: {"alg":"none","typ":"oauth-authz-req+jwt"}
        // Payload: {"client_id":"test"}
        let jwt =
            "eyJhbGciOiJub25lIiwidHlwIjoib2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJjbGllbnRfaWQiOiJ0ZXN0In0.";
        assert!(validate_request_object_typ(jwt, false).is_ok());
    }

    #[test]
    fn validate_request_object_typ_missing() {
        // JWT without typ header: {"alg":"none"}
        // Payload: {"client_id":"test"}
        let jwt = "eyJhbGciOiJub25lIn0.eyJjbGllbnRfaWQiOiJ0ZXN0In0.";
        let err = validate_request_object_typ(jwt, false).unwrap_err();
        assert!(err.to_string().contains("missing required 'typ' header"));
    }

    #[test]
    fn validate_request_object_typ_wrong_value() {
        // JWT with wrong typ header: {"alg":"none","typ":"JWT"}
        // Payload: {"client_id":"test"}
        let jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJjbGllbnRfaWQiOiJ0ZXN0In0.";
        let err = validate_request_object_typ(jwt, false).unwrap_err();
        assert!(err.to_string().contains("must be 'oauth-authz-req+jwt'"));
    }

    #[test]
    fn validate_request_object_typ_missing_allowed_for_redirect_uri() {
        // JWT without typ header: {"alg":"none"}
        // For redirect_uri prefix, this should be allowed (with warning)
        let jwt = "eyJhbGciOiJub25lIn0.eyJjbGllbnRfaWQiOiJ0ZXN0In0.";
        assert!(validate_request_object_typ(jwt, true).is_ok());
    }

    #[test]
    fn validate_request_object_typ_wrong_allowed_for_redirect_uri() {
        // JWT with wrong typ header: {"alg":"none","typ":"JWT"}
        // For redirect_uri prefix, this should be allowed (with warning)
        let jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJjbGllbnRfaWQiOiJ0ZXN0In0.";
        assert!(validate_request_object_typ(jwt, true).is_ok());
    }
}
