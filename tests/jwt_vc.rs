use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use http::{Request, Response};
use oid4vp::{
    core::{
        authorization_request::{
            verification::{did, RequestVerifier},
            AuthorizationRequestObject,
        },
        metadata::WalletMetadata,
        response::AuthorizationResponse,
        util::AsyncHttpClient,
    },
    verifier::{
        request_signer::P256Signer,
        session::{MemoryStore, Outcome},
        Verifier,
    },
    wallet::Wallet,
};
use serde_json::json;
use ssi_dids::{DIDKey, VerificationMethodDIDResolver};
use ssi_verification_methods::AnyJwkMethod;

pub async fn wallet_verifier() -> (JwtVcWallet, Arc<Verifier>) {
    let verifier_did = "did:key:zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn".to_owned();
    let verifier_did_vm =
        "did:key:zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn#zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn".to_owned();
    let signer = Arc::new(
        P256Signer::new(
            p256::SecretKey::from_jwk_str(include_str!("examples/verifier.jwk"))
                .unwrap()
                .into(),
        )
        .unwrap(),
    );

    let resolver: VerificationMethodDIDResolver<DIDKey, AnyJwkMethod> =
        VerificationMethodDIDResolver::new(DIDKey);

    let client = Arc::new(
        oid4vp::verifier::client::DIDClient::new(
            verifier_did_vm.clone(),
            signer.clone(),
            &resolver,
        )
        .await
        .unwrap(),
    );
    let verifier = Arc::new(
        Verifier::builder()
            .with_client(client)
            .with_submission_endpoint("http://example.com/submission".parse().unwrap())
            .with_session_store(Arc::new(MemoryStore::default()))
            .build()
            .await
            .unwrap(),
    );

    let http_client = MockHttpClient {
        verifier: verifier.clone(),
    };

    let metadata = serde_json::from_value(json!(
      {
        "authorization_endpoint": "openid4vp:",
        "client_id_schemes_supported": [
          "did"
        ],
        "request_object_signing_alg_values_supported": [
          "ES256"
        ],
        "response_types_supported": [
          "vp_token"
        ],
        "vp_formats_supported": {
          "jwt_vc_json": {
            "alg_values_supported": ["ES256"]
          }
        }
      }
    ))
    .unwrap();

    (
        JwtVcWallet {
            http_client,
            metadata,
            trusted_dids: vec![verifier_did],
        },
        verifier,
    )
}

pub struct JwtVcWallet {
    http_client: MockHttpClient,
    metadata: WalletMetadata,
    trusted_dids: Vec<String>,
}

pub struct MockHttpClient {
    verifier: Arc<Verifier>,
}

impl JwtVcWallet {
    fn trusted_dids(&self) -> &[String] {
        &self.trusted_dids
    }
}

#[async_trait]
impl Wallet for JwtVcWallet {
    type HttpClient = MockHttpClient;

    fn http_client(&self) -> &Self::HttpClient {
        &self.http_client
    }
    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

#[async_trait]
impl RequestVerifier for JwtVcWallet {
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<()> {
        let resolver: VerificationMethodDIDResolver<DIDKey, AnyJwkMethod> =
            VerificationMethodDIDResolver::new(DIDKey);

        did::verify_with_resolver(
            self.metadata(),
            decoded_request,
            request_jwt,
            Some(self.trusted_dids()),
            &resolver,
        )
        .await
    }
}

#[async_trait]
impl AsyncHttpClient for MockHttpClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        // Only expect submission.
        let body = request.body();
        let uri = request.uri();
        let id = uri
            .path()
            .strip_prefix("/submission/")
            .context("failed to extract id from path")?;

        self.verifier
            .verify_response(
                id.parse().context("failed to parse id")?,
                AuthorizationResponse::from_x_www_form_urlencoded(body)
                    .context("failed to parse authorization response request")?,
                |_, _| Box::pin(async { Outcome::Success }),
            )
            .await?;

        Response::builder()
            .status(200)
            .body(vec![])
            .context("failed to build response")
    }
}
