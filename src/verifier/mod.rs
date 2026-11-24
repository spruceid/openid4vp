use std::{fmt::Debug, future::Future, pin::Pin, sync::Arc};

use anyhow::{bail, Context, Result};
use client::Client;
use request_builder::RequestBuilder;
use session::{Outcome, Session, SessionStore, Status};
use url::Url;
use uuid::Uuid;

use crate::core::{
    object::{TypedParameter, UntypedObject},
    response::AuthorizationResponse,
    util::require_https,
};

use by_reference::ByReference;

mod by_reference;
pub mod client;
pub mod request_builder;
pub mod request_signer;
pub mod session;

/// An OpenID4VP verifier, also known as the client.
#[derive(Debug, Clone)]
pub struct Verifier {
    client: Arc<dyn Client + Send + Sync>,
    default_request_params: UntypedObject,
    pass_by_reference: ByReference,
    session_store: Arc<dyn SessionStore + Send + Sync>,
    submission_endpoint: Url,
}

impl Verifier {
    /// Build a new verifier.
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::default()
    }

    /// Begin building a new authorization request (credential presentation).
    pub fn build_authorization_request(&self) -> RequestBuilder<'_> {
        RequestBuilder::new(self)
    }

    /// Retrieve the current status of an authorization request.
    ///
    /// This should be triggered by a request from the application frontend.
    ///
    /// ## Returns
    /// The status of the authorization request.
    pub async fn poll_status(&self, uuid: Uuid) -> Result<Status> {
        self.session_store
            .get_session(uuid)
            .await
            .map(|session| session.status)
    }

    /// Retrieve an authorization request that was passed by-reference.
    ///
    /// This should be triggered by a request from the wallet when the verifier is configured to
    /// pass the authorization request by reference using [VerifierBuilder::by_reference]. The
    /// wallet will make a request to `<configured-url>/<reference>`. For example:
    ///
    /// ```ignore
    /// let url: Url = "https://verifier.example.com/some/sub/path".parse()?;
    /// let verifier = Verifier::builder()
    ///     .by_reference(url)
    ///     ...
    ///     .build()
    ///     .await?;
    /// ```
    ///
    /// The wallet will request the authorization request from
    /// `GET https://verifier.example.com/some/sub/path/<reference>`.
    ///
    /// This will update the presentation status.
    ///
    /// ## Returns
    /// The signed authorization request as a JWT.
    pub async fn retrieve_authorization_request(&self, reference: Uuid) -> Result<String> {
        let session = self
            .session_store
            .get_session(reference)
            .await
            .context("failed to retrieve session")?;
        if session.status < Status::SentRequest {
            self.session_store
                .update_status(reference, Status::SentRequest)
                .await
                .context("failed to update session status")?;
        }
        Ok(session.authorization_request_jwt)
    }

    /// Verify an authorization response.
    ///
    /// This should be triggered by a request from the wallet. The wallet will submit the
    /// authorization response to `<configured-url>/<reference>`. For example:
    ///
    /// ```ignore
    /// let url: Url = "https://verifier.example.com/some/sub/path".parse()?;
    /// let verifier = Verifier::builder()
    ///     .with_submission_endpoint(url)
    ///     ...
    ///     .build()
    ///     .await?;
    /// ```
    ///
    /// For `direct_post` or `direct_post.jwt` response modes, the wallet will submit the
    /// authorization response to `POST https://verifier.example.com/some/sub/path/<reference>`.
    ///
    /// This will update the presentation status.
    pub async fn verify_response<F, Fut>(
        &self,
        reference: Uuid,
        authorization_response: AuthorizationResponse,
        validator_function: F,
    ) -> Result<()>
    where
        F: FnOnce(Session, AuthorizationResponse) -> Pin<Box<Fut>>,
        Fut: Future<Output = Outcome>,
    {
        let session = self.session_store.get_session(reference).await?;

        let outcome = validator_function(session, authorization_response).await;

        self.session_store
            .update_status(reference, Status::Complete(outcome))
            .await
    }
}

/// Builder struct for [Verifier].
#[derive(Debug, Clone, Default)]
pub struct VerifierBuilder {
    client: Option<Arc<dyn Client + Send + Sync>>,
    default_request_params: UntypedObject,
    pass_by_reference: ByReference,
    session_store: Option<Arc<dyn SessionStore + Send + Sync>>,
    submission_endpoint: Option<Url>,
}

impl VerifierBuilder {
    /// Build the verifier.
    ///
    /// Fails when the client, session store or submission endpoint is missing, or when the
    /// submission endpoint or the [by_reference](Self::by_reference) URL fails
    /// [require_https].
    pub async fn build(self) -> Result<Verifier> {
        let Self {
            client,
            default_request_params,
            pass_by_reference,
            session_store,
            submission_endpoint,
        } = self;

        let Some(client) = client else {
            bail!("client is required, see `with_client`")
        };

        let Some(session_store) = session_store else {
            bail!("session store is required, see `with_session_store`")
        };

        let Some(submission_endpoint) = submission_endpoint else {
            bail!("submission endpoint is required, see `with_submission_endpoint`")
        };

        // Wallets refuse a non-https `response_uri` or `request_uri`.
        require_https(&submission_endpoint, "submission endpoint")?;
        if let ByReference::True { at } = &pass_by_reference {
            require_https(at, "by_reference URL")?;
        }

        Ok(Verifier {
            client,
            default_request_params,
            pass_by_reference,
            session_store,
            submission_endpoint,
        })
    }

    /// Encode the Authorization Request directly in the `request` parameter.
    pub fn by_value(mut self) -> Self {
        self.pass_by_reference = ByReference::False;
        self
    }

    /// Pass the Authorization Request by reference in the `request_uri` parameter.
    pub fn by_reference(mut self, at: Url) -> Self {
        self.pass_by_reference = ByReference::True { at };
        self
    }

    /// Set default parameters that every
    /// [AuthorizationRequest](crate::core::authorization_request::AuthorizationRequest) will
    /// contain.
    ///
    /// Note: `client_id` is always set by the [Client],
    /// which embeds the Client Identifier Prefix per OID4VP v1.0 Section 5.9.
    pub fn with_default_request_parameter<T: TypedParameter>(mut self, t: T) -> Self {
        self.default_request_params.insert(t);
        self
    }

    /// Set the [Client] that the [Verifier] will use to identify
    /// itself to the Wallet.
    pub fn with_client(mut self, client: Arc<dyn Client + Send + Sync>) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the [`SessionStore`] that the [`Verifier`]
    /// will use to maintain session state across transactions.
    pub fn with_session_store(
        mut self,
        session_store: Arc<dyn SessionStore + Send + Sync>,
    ) -> Self {
        self.session_store = Some(session_store);
        self
    }

    /// Set the [Url] that the [Verifier] will listen at to receive the presentation submission
    /// from the Wallet.
    pub fn with_submission_endpoint(mut self, endpoint: Url) -> Self {
        self.submission_endpoint = Some(endpoint);
        self
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use anyhow::Result;
    use async_trait::async_trait;

    use super::{session::MemoryStore, Client, Verifier, VerifierBuilder};
    use crate::core::authorization_request::{
        parameters::{ClientId, ClientIdScheme},
        AuthorizationRequestObject,
    };

    #[derive(Debug)]
    struct UnsignedClient(ClientId);

    #[async_trait]
    impl Client for UnsignedClient {
        fn id(&self) -> &ClientId {
            &self.0
        }

        fn prefix(&self) -> ClientIdScheme {
            ClientIdScheme("x509_san_dns".to_string())
        }

        async fn generate_request_object_jwt(
            &self,
            _body: &AuthorizationRequestObject,
        ) -> Result<String> {
            Ok("eyJhbGciOiJub25lIn0.e30.".to_string())
        }
    }

    fn builder(submission_endpoint: &str) -> VerifierBuilder {
        Verifier::builder()
            .with_client(Arc::new(UnsignedClient(ClientId(
                "x509_san_dns:verifier.example".to_string(),
            ))))
            .with_session_store(Arc::new(MemoryStore::default()))
            .with_submission_endpoint(submission_endpoint.parse().unwrap())
    }

    #[tokio::test]
    async fn build_accepts_https_endpoints() {
        builder("https://verifier.example/submit")
            .by_reference("https://verifier.example/request".parse().unwrap())
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    #[cfg(debug_assertions)]
    async fn build_accepts_loopback_http_in_debug() {
        builder("http://127.0.0.1:3000/submit")
            .by_reference("http://localhost:3000/request".parse().unwrap())
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    #[cfg(not(debug_assertions))]
    async fn build_refuses_loopback_http_in_release() {
        assert!(builder("http://127.0.0.1:3000/submit")
            .build()
            .await
            .is_err());
    }

    #[tokio::test]
    async fn build_refuses_an_http_submission_endpoint() {
        let err = builder("http://verifier.example/submit")
            .build()
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("submission endpoint"), "{msg}");
        assert!(msg.contains("http://verifier.example/submit"), "{msg}");
    }

    #[tokio::test]
    async fn build_refuses_an_http_by_reference_url() {
        let err = builder("https://verifier.example/submit")
            .by_reference("http://verifier.example/request".parse().unwrap())
            .build()
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("by_reference"), "{msg}");
        assert!(msg.contains("http://verifier.example/request"), "{msg}");
    }
}
