use crate::core::{
    authorization_request::{parameters::ClientIdScheme, AuthorizationRequestObject},
    metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
    object::ParsingErrorContext,
};
use anyhow::{bail, Context, Result};
use base64::prelude::*;
use serde_json::{Map, Value as Json};

use ssi::jwk::JWKResolver;

/// Default implementation of request validation for `decentralized_identifier` Client Identifier Prefix.
/// Per Section 5.9.3.
///
/// The Request Object MUST be signed with a private key associated with the DID in `client_id`.
/// Unsigned Request Objects (`alg: none`) are always rejected, even if the wallet metadata lists
/// `none` in `request_object_signing_alg_values_supported`.
pub async fn verify_with_resolver(
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_dids: Option<&[String]>,
    resolver: impl JWKResolver,
) -> Result<()> {
    let (headers_b64, _, _) = ssi::claims::jws::split_jws(&request_jwt)?;

    let headers_json_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(headers_b64)
        .context("jwt headers were not valid base64url")?;

    let mut headers = serde_json::from_slice::<Map<String, Json>>(&headers_json_bytes)
        .context("jwt headers were not valid json")?;

    let Json::String(alg) = headers
        .remove("alg")
        .context("'alg' was missing from jwt headers")?
    else {
        bail!("'alg' header was not a string")
    };

    // Checked before the supported algorithms, so that wallet metadata listing `none` cannot
    // re-enable unsigned requests.
    if alg.eq_ignore_ascii_case("none") {
        bail!(
            "unsigned request object ('alg': '{alg}') is not allowed for the \
            'decentralized_identifier' Client Identifier Prefix: the request MUST be signed \
            with a private key associated with the DID (OID4VP 1.0 Section 5.9.3)"
        )
    }

    let supported_algs: RequestObjectSigningAlgValuesSupported =
        wallet_metadata.get().parsing_error()?;

    if !supported_algs.0.contains(&alg) {
        bail!("request was signed with unsupported algorithm: {alg}")
    }

    let Json::String(kid) = headers
        .remove("kid")
        .context("'kid' was missing from jwt headers")?
    else {
        bail!("'kid' header was not a string")
    };

    let client_id = request_object
        .client_id()
        .context("client_id is required")?;
    let (did, _f) = kid.split_once('#').context(format!(
        "expected a DID verification method in 'kid' header, received '{kid}'"
    ))?;

    // Extract the DID from client_id, removing the "decentralized_identifier:" prefix if present
    let prefix = format!("{}:", ClientIdScheme::DECENTRALIZED_IDENTIFIER);
    let client_id_did = client_id.0.strip_prefix(&prefix).unwrap_or(&client_id.0);

    if client_id_did != did {
        bail!("DIDs from 'kid' ({did}) and 'client_id' ({client_id_did}) do not match",)
    }

    if let Some(dids) = trusted_dids {
        if !dids.iter().any(|trusted_did| trusted_did == did) {
            bail!("'client_id' ({did}) is not in the list of trusted dids")
        }
    }

    let jwk = resolver
        .fetch_public_jwk(Some(&kid))
        .await
        .context("unable to resolve key from verification method")?;

    let _: Json = ssi::claims::jwt::decode_verify(&request_jwt, &jwk)
        .context("request signature could not be verified")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use serde_json::json;
    use ssi::{claims::ProofValidationError, jwk::JWK};

    use crate::core::object::UntypedObject;

    use super::*;

    const DID: &str = "did:key:zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn";

    /// Resolver that must never be reached: unsigned requests are refused before any DID
    /// resolution happens.
    struct PanickingResolver;

    impl JWKResolver for PanickingResolver {
        async fn fetch_public_jwk(
            &self,
            _key_id: Option<&str>,
        ) -> Result<Cow<'_, JWK>, ProofValidationError> {
            panic!("DID resolution must not happen for unsigned requests")
        }
    }

    fn wallet_metadata(request_object_signing_algs: &[&str]) -> WalletMetadata {
        serde_json::from_value(json!({
            "authorization_endpoint": "openid4vp:",
            "client_id_prefixes_supported": ["decentralized_identifier"],
            "request_object_signing_alg_values_supported": request_object_signing_algs,
            "response_types_supported": ["vp_token"],
            "vp_formats_supported": {
                "jwt_vc_json": { "alg_values_supported": ["ES256"] }
            }
        }))
        .unwrap()
    }

    fn request_object() -> AuthorizationRequestObject {
        let object: UntypedObject = serde_json::from_value(json!({
            "client_id": format!("decentralized_identifier:{DID}"),
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": "https://example.com/response",
            "nonce": "nonce",
        }))
        .unwrap();
        object.try_into().unwrap()
    }

    /// Unsecured JWT (RFC 7519 Section 6) with an empty signature.
    fn unsigned_jwt(alg: &str) -> String {
        let header = json!({
            "alg": alg,
            "typ": "oauth-authz-req+jwt",
            "kid": format!("{DID}#key-1"),
        });
        let header = BASE64_URL_SAFE_NO_PAD.encode(header.to_string());
        let payload = BASE64_URL_SAFE_NO_PAD.encode(r#"{"nonce":"nonce"}"#);
        format!("{header}.{payload}.")
    }

    async fn verify_unsigned(alg: &str, metadata_algs: &[&str]) -> anyhow::Error {
        verify_with_resolver(
            &wallet_metadata(metadata_algs),
            &request_object(),
            unsigned_jwt(alg),
            Some(&[DID.to_owned()]),
            PanickingResolver,
        )
        .await
        .expect_err("unsigned request object must be rejected")
    }

    #[tokio::test]
    async fn rejects_alg_none_even_if_wallet_metadata_lists_none() {
        let err = verify_unsigned("none", &["ES256", "none"]).await;
        assert!(err.to_string().contains("unsigned request object"), "{err}");
        assert!(err.to_string().contains("5.9.3"), "{err}");
    }

    #[tokio::test]
    async fn rejects_alg_none_case_insensitively() {
        for alg in ["None", "NONE", "nOnE"] {
            let err = verify_unsigned(alg, &["ES256", alg]).await;
            assert!(err.to_string().contains("unsigned request object"), "{err}");
        }
    }

    #[tokio::test]
    async fn rejects_alg_none_before_supported_alg_check() {
        // Without `none` in the metadata the specific error is still returned, which shows
        // the check runs first.
        let err = verify_unsigned("none", &["ES256"]).await;
        assert!(err.to_string().contains("unsigned request object"), "{err}");
    }
}
