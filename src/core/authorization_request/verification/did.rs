use crate::core::{
    authorization_request::AuthorizationRequestObject,
    metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
    object::ParsingErrorContext,
};
use anyhow::{bail, Context, Result};
use base64::prelude::*;
use didkit::{resolve_key, DIDResolver};
use serde_json::{Map, Value as Json};

/// Default implementation of request verification for `client_id_scheme` `did`.
///
/// Uses the default didkit [DIDResolver].
pub async fn verify(
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_dids: Option<&[String]>,
) -> Result<()> {
    verify_with_resolver(
        wallet_metadata,
        request_object,
        request_jwt,
        trusted_dids,
        didkit::DID_METHODS.to_resolver(),
    )
    .await
}

/// Default implementation of request validation for `client_id_scheme` `did`.
pub async fn verify_with_resolver(
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_dids: Option<&[String]>,
    resolver: &dyn DIDResolver,
) -> Result<()> {
    let (headers_b64, _, _) = didkit::ssi::jws::split_jws(&request_jwt)?;

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

    let client_id = request_object.client_id();
    let (did, _f) = kid.split_once('#').context(format!(
        "expected a DID verification method in 'kid' header, received '{kid}'"
    ))?;

    if &client_id.0 != did {
        bail!(
            "DIDs from 'kid' ({did}) and 'client_id' ({}) do not match",
            client_id.0
        )
    }

    if let Some(dids) = trusted_dids {
        if !dids.iter().any(|trusted_did| trusted_did == did) {
            bail!("'client_id' ({did}) is not in the list of trusted dids")
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(
            &didkit::dereference(resolver, did, &Default::default())
                .await
                .1
        )
        .unwrap()
    );

    println!("{kid:?}");

    let jwk = resolve_key(&kid, resolver)
        .await
        .context("unable to resolve verification method from 'kid' header")?;

    let _: Json = didkit::ssi::jwt::decode_verify(&request_jwt, &jwk)
        .context("request signature could not be verified")?;

    Ok(())
}
