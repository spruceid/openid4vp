use anyhow::{bail, Context, Result};
use didkit::{DIDResolver, DID_METHODS};
use tracing::{debug, warn};
use url::Url;
use x509_cert::{
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::core::{
    authorization_request::{
        parameters::ClientId, AuthorizationRequest, AuthorizationRequestObject, RequestIndirection,
    },
    metadata::{parameters::wallet::AuthorizationEndpoint, WalletMetadata},
    object::{ParsingErrorContext, TypedParameter, UntypedObject},
    profile::Profile,
};

use self::{by_reference::ByReference, client::Client};

use super::{
    request_signer::{P256Signer, RequestSigner},
    Session,
};

mod by_reference;
mod client;

#[derive(Debug, Clone)]
pub struct SessionBuilder<S: RequestSigner = P256Signer> {
    wallet_metadata: WalletMetadata,
    client: Option<Client<S>>,
    pass_by_reference: ByReference,
    request_params: UntypedObject,
}

impl<S: RequestSigner> SessionBuilder<S> {
    pub fn new(wallet_metadata: WalletMetadata) -> Self {
        Self {
            wallet_metadata,
            client: None,
            pass_by_reference: ByReference::False,
            request_params: UntypedObject::default(),
        }
    }

    pub async fn build<P: Profile>(self, p: P) -> Result<Session> {
        let Self {
            wallet_metadata,
            client,
            pass_by_reference,
            mut request_params,
        } = self;

        let authorization_endpoint = wallet_metadata
            .get::<AuthorizationEndpoint>()
            .parsing_error()?
            .0;

        let Some(client) = client else {
            bail!("client is required, see `with_X_client_id` functions")
        };

        let client_id = client.id();
        let client_id_scheme = client.scheme();
        if !wallet_metadata
            .client_id_schemes_supported()
            .0
            .contains(&client_id_scheme)
        {
            bail!("wallet does not support client_id_scheme '{client_id_scheme}'")
        }

        let _ = request_params.insert(client_id.clone());
        let _ = request_params.insert(client_id_scheme.clone());

        let request_object: AuthorizationRequestObject = request_params
            .try_into()
            .context("unable to construct Authorization Request Object from provided parameters")?;

        p.validate_request(&request_object)?;

        let request_object_jwt = client.generate_request_object_jwt(&request_object).await?;

        let request_indirection = match pass_by_reference {
            ByReference::False => RequestIndirection::ByValue(request_object_jwt.clone()),
            ByReference::True { at } => RequestIndirection::ByReference(at),
        };

        let authorization_request = AuthorizationRequest {
            client_id: client_id.0.clone(),
            request_indirection,
        }
        .to_url(authorization_endpoint)?;

        Ok(Session {
            authorization_request,
            request_object,
            request_object_jwt,
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

    pub fn with_request_parameter<P: TypedParameter>(mut self, p: P) -> Self {
        self.request_params.insert(p);
        self
    }

    /// Configure the [ClientId] and set the [ClientIdScheme] to `did`.
    ///
    /// Uses the default didkit [DIDResolver].
    pub async fn with_did_client_id<T: RequestSigner>(
        self,
        vm: String,
        signer: T,
    ) -> Result<SessionBuilder<T>> {
        self.with_did_client_id_and_resolver(vm, signer, DID_METHODS.to_resolver())
            .await
    }

    /// Configure the [ClientId] and set the [ClientIdScheme] to `did`.
    pub async fn with_did_client_id_and_resolver<T: RequestSigner>(
        self,
        vm: String,
        signer: T,
        resolver: &dyn DIDResolver,
    ) -> Result<SessionBuilder<T>> {
        let (id, _f) = vm.rsplit_once('#').context(format!(
            "expected a DID verification method, received '{vm}'"
        ))?;

        let key = didkit::resolve_key(&vm, resolver)
            .await
            .context("unable to resolve key from verification method")?;

        if &key != signer.jwk() {
            bail!(
                "verification method resolved from DID document did not match public key of signer"
            )
        }

        let SessionBuilder {
            wallet_metadata,
            pass_by_reference,
            request_params,
            ..
        } = self;

        let client = Some(Client::Did {
            id: ClientId(id.to_string()),
            vm,
            signer,
        });

        Ok(SessionBuilder {
            wallet_metadata,
            client,
            pass_by_reference,
            request_params,
        })
    }

    /// Configure the [ClientId] and set the [ClientIdScheme] to `x509_san_dns`.
    pub fn with_x509_san_dns_client_id(mut self, x5c: Vec<Certificate>, signer: S) -> Result<Self> {
        // TODO: Check certificate chain.
        let leaf = &x5c[0];
        let id = if let Some(san) = leaf
            .tbs_certificate
            .filter::<SubjectAltName>()
            .filter_map(|r| match r {
                Ok((_crit, san)) => Some(san.0.into_iter()),
                Err(e) => {
                    debug!("unable to parse SubjectAlternativeName from DER: {e}");
                    None
                }
            })
            .flatten()
            .filter_map(|gn| match gn {
                GeneralName::DnsName(uri) => Some(uri.to_string()),
                _ => {
                    debug!("found non-DNS SAN: {gn:?}");
                    None
                }
            })
            .next()
        {
            san
        } else {
            bail!("x509 certificate does not contain Subject Alternative Name");
        };
        self.client = Some(Client::X509SanUri {
            id: ClientId(id),
            x5c,
            signer,
        });
        Ok(self)
    }

    /// Configure the [ClientId] and set the [ClientIdScheme] to `x509_san_uri`.
    pub fn with_x509_san_uri_client_id(mut self, x5c: Vec<Certificate>, signer: S) -> Result<Self> {
        // TODO: Check certificate chain.
        let leaf = &x5c[0];
        let id = if let Some(san) = leaf
            .tbs_certificate
            .filter::<SubjectAltName>()
            .filter_map(|r| match r {
                Ok((_crit, san)) => Some(san.0.into_iter()),
                Err(e) => {
                    debug!("unable to parse SubjectAlternativeName from DER: {e}");
                    None
                }
            })
            .flatten()
            .filter_map(|gn| match gn {
                GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                _ => {
                    debug!("found non-URI SAN: {gn:?}");
                    None
                }
            })
            .next()
        {
            san
        } else {
            let Some(cn) = leaf
                .tbs_certificate
                .subject
                .0
                .iter()
                .flat_map(|n| n.0.iter())
                .filter_map(|n| n.to_string().strip_prefix("CN=").map(ToOwned::to_owned))
                .next()
            else {
                bail!("x509 certificate does not contain Subject Alternative Name or Common Name");
            };
            warn!("x509 certificate does not contain Subject Alternative Name, falling back to Common Name for client_id");
            cn
        };
        self.client = Some(Client::X509SanUri {
            id: ClientId(id),
            x5c,
            signer,
        });
        Ok(self)
    }
}
