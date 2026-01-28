use anyhow::{bail, Context, Result};
use url::Url;
use uuid::Uuid;

use crate::{
    core::{
        authorization_request::{
            parameters::{ResponseMode, ResponseType, ResponseUri},
            AuthorizationRequest, AuthorizationRequestObject, RequestIndirection,
        },
        dcql_query::DcqlQuery,
        metadata::{
            parameters::wallet::{AuthorizationEndpoint, ClientIdPrefixesSupported},
            WalletMetadata,
        },
        object::{ParsingErrorContext, TypedParameter, UntypedObject},
    },
    verifier::{by_reference::ByReference, session::Status},
};

use super::{session::Session, Verifier};

#[derive(Debug, Clone)]
#[must_use]
pub struct RequestBuilder<'a> {
    dcql_query: Option<DcqlQuery>,
    request_parameters: UntypedObject,
    verifier: &'a Verifier,
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(verifier: &'a Verifier) -> Self {
        Self {
            dcql_query: None,
            request_parameters: verifier.default_request_params.clone(),
            verifier,
        }
    }

    /// Set the DCQL query for credential requirements.
    pub fn with_dcql_query(mut self, dcql_query: DcqlQuery) -> Self {
        self.dcql_query = Some(dcql_query);
        self
    }

    /// Set or override the default authorization request parameters.
    pub fn with_request_parameter<T: TypedParameter>(mut self, t: T) -> Self {
        self.request_parameters.insert(t);
        self
    }

    /// Build the request.
    ///
    /// ## Returns
    /// - UUID that can be used by the application frontend to poll for the status of this request.
    /// - URL that the application frontend should use to drive the user to their wallet application.
    pub async fn build(self, wallet_metadata: WalletMetadata) -> Result<(Uuid, Url)> {
        let uuid = Uuid::new_v4();

        let authorization_request_url = self.build_with_session_id(uuid, wallet_metadata).await?;

        Ok((uuid, authorization_request_url))
    }

    pub async fn build_with_session_id(
        mut self,
        uuid: Uuid,
        wallet_metadata: WalletMetadata,
    ) -> Result<Url> {
        let client_id = self.verifier.client.id();
        let client_id_prefix = self.verifier.client.prefix();

        let _ = self.request_parameters.insert(client_id.clone());

        let Some(dcql_query) = self.dcql_query else {
            bail!("dcql_query is required, see `with_dcql_query`")
        };

        let _ = self.request_parameters.insert(dcql_query.clone());

        let _ = self
            .request_parameters
            .get::<ResponseType>()
            .context("response type is required, see `with_request_parameter`")?
            .context("error occurred when retrieving response type")?;

        match self
            .request_parameters
            .get::<ResponseMode>()
            .context("response mode is required, see `with_request_parameter`")?
            .context("error occurred when retrieving response mode")?
        {
            ResponseMode::DirectPost | ResponseMode::DirectPostJwt => {
                let mut uri = self.verifier.submission_endpoint.clone();
                {
                    let Ok(mut path) = uri.path_segments_mut() else {
                        bail!("invalid base URL for the submission endpoint")
                    };
                    path.push(&uuid.to_string());
                }
                self.request_parameters.insert(ResponseUri(uri));
            }
            ResponseMode::DcApi | ResponseMode::DcApiJwt => {}
            ResponseMode::Unsupported(r) => bail!("unsupported response_mode: {r}"),
        }

        if !wallet_metadata
            .get_or_default::<ClientIdPrefixesSupported>()?
            .0
            .contains(&client_id_prefix)
        {
            bail!(
                "the wallet does not support Client Identifier Prefix '{}'",
                client_id_prefix.0
            )
        }

        let authorization_request_object: AuthorizationRequestObject =
            self.request_parameters.try_into().context(
                "unable to construct the Authorization Request from provided request parameters",
            )?;

        let authorization_request_jwt = self
            .verifier
            .client
            .generate_request_object_jwt(&authorization_request_object)
            .await?;

        let mut initial_status = Status::SentRequest;

        let request_indirection = match self.verifier.pass_by_reference.clone() {
            ByReference::False => RequestIndirection::ByValue {
                request: authorization_request_jwt.clone(),
            },
            ByReference::True { mut at } => {
                {
                    let Ok(mut path) = at.path_segments_mut() else {
                        bail!("invalid base URL for Authorization Request by reference")
                    };
                    path.push(&uuid.to_string());
                }
                initial_status = Status::SentRequestByReference;
                RequestIndirection::ByReference { request_uri: at }
            }
        };

        let authorization_endpoint = wallet_metadata
            .get::<AuthorizationEndpoint>()
            .parsing_error()?
            .0;

        let authorization_request_url = AuthorizationRequest {
            client_id: Some(client_id.0.clone()),
            request_indirection,
        }
        .to_url(authorization_endpoint)
        .context("unable to generate authorization request URL")?;

        let session = Session {
            uuid,
            status: initial_status,
            authorization_request_jwt,
            authorization_request_object,
            dcql_query,
        };

        self.verifier
            .session_store
            .initiate(session)
            .await
            .context("failed to store the session in the session store")?;

        Ok(authorization_request_url)
    }

    pub async fn build_dc_api(mut self) -> Result<(Uuid, String)> {
        let uuid = Uuid::new_v4();

        let client_id = self.verifier.client.id();

        let _ = self.request_parameters.insert(client_id.clone());

        let Some(dcql_query) = self.dcql_query else {
            bail!("dcql query is required, see `with_dcql_query`")
        };

        let _ = self.request_parameters.insert(dcql_query.clone());

        let _ = self
            .request_parameters
            .get::<ResponseType>()
            .context("response type is required, see `with_request_parameter`")?
            .context("error occurred when retrieving response type")?;

        match self
            .request_parameters
            .get::<ResponseMode>()
            .context("response mode is required, see `with_request_parameter`")?
            .context("error occurred when retrieving response mode")?
        {
            ResponseMode::DirectPost | ResponseMode::DirectPostJwt => {
                let mut uri = self.verifier.submission_endpoint.clone();
                {
                    let Ok(mut path) = uri.path_segments_mut() else {
                        bail!("invalid base URL for the submission endpoint")
                    };
                    path.push(&uuid.to_string());
                }
                self.request_parameters.insert(ResponseUri(uri));
            }
            ResponseMode::DcApi | ResponseMode::DcApiJwt => {}
            ResponseMode::Unsupported(r) => bail!("unsupported response_mode: {r}"),
        }

        let authorization_request_object: AuthorizationRequestObject =
            self.request_parameters.try_into().context(
                "unable to construct the Authorization Request from provided request parameters",
            )?;

        let authorization_request_jwt = self
            .verifier
            .client
            .generate_request_object_jwt(&authorization_request_object)
            .await?;

        let initial_status = Status::SentRequest;

        let session = Session {
            uuid,
            status: initial_status,
            authorization_request_jwt: authorization_request_jwt.clone(),
            authorization_request_object: authorization_request_object.clone(),
            dcql_query,
        };

        self.verifier
            .session_store
            .initiate(session)
            .await
            .context("failed to store the session in the session store")?;

        Ok((uuid, authorization_request_jwt))
    }
}
