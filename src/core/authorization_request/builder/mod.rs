use std::marker::PhantomData;

use anyhow::{bail, Context, Result};
use ssi::did_resolve::DIDResolver;
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
    profile::{PresentationBuilder, Verifier, VerifierSession},
};

use by_reference::ByReference;
use client::Client;
use request_signer::{P256Signer, RequestSigner};

mod by_reference;
mod client;
pub mod request_signer;

#[derive(Debug, Clone)]
pub struct SessionBuilder<S, V, PB, RS: RequestSigner = P256Signer> {
    session: PhantomData<S>,
    verifier: V,
    wallet_metadata: WalletMetadata,
    presentation_builder: PB,
    client: Option<Client<RS>>,
    pass_by_reference: ByReference,
    request_params: UntypedObject,
}

impl<
        S: VerifierSession<Verifier = V>,
        V: Verifier<PresentationBuilder = PB>,
        PB: PresentationBuilder<Element = E>,
        RS: RequestSigner,
        E,
    > SessionBuilder<S, V, PB, RS>
{
    pub fn new(verifier: V, wallet_metadata: WalletMetadata) -> Self {
        Self {
            session: PhantomData::default(),
            verifier,
            wallet_metadata,
            presentation_builder: PB::default(),
            client: None,
            pass_by_reference: ByReference::False,
            request_params: UntypedObject::default(),
        }
    }

    pub async fn build(self) -> Result<S> {
        let Self {
            session: _,
            verifier,
            wallet_metadata,
            presentation_builder,
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

        let presentation_definition = presentation_builder.build()?;

        let client_id = client.id();
        let client_id_scheme = client.scheme();
        if !wallet_metadata
            .client_id_schemes_supported()
            .0
            .contains(client_id_scheme)
        {
            bail!("wallet does not support client_id_scheme '{client_id_scheme}'")
        }

        let _ = request_params.insert(client_id.clone());
        let _ = request_params.insert(client_id_scheme.clone());
        let _ = request_params.insert(presentation_definition);

        let request_object: AuthorizationRequestObject = request_params
            .try_into()
            .context("unable to construct Authorization Request Object from provided parameters")?;

        verifier.validate_request(&wallet_metadata, &request_object)?;

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

        Ok(S::build(verifier, authorization_request))
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

    pub fn with_request_parameter<T: TypedParameter>(mut self, t: T) -> Self {
        self.request_params.insert(t);
        self
    }

    pub fn with_requested_element(mut self, element: E) -> Self {
        self.presentation_builder = self.presentation_builder.with_requested_element(element);
        self
    }

    pub fn with_presentation_id(mut self, id: String) -> Self {
        self.presentation_builder = self.presentation_builder.with_presentation_id(id);
        self
    }

    /// Configure the [ClientId] and set the [ClientIdScheme] to `did`.
    pub async fn with_did_client_id_and_resolver<T: RequestSigner>(
        self,
        vm: String,
        signer: T,
        resolver: &dyn DIDResolver,
    ) -> Result<SessionBuilder<S, V, PB, T>> {
        let (id, _f) = vm.rsplit_once('#').context(format!(
            "expected a DID verification method, received '{vm}'"
        ))?;

        let key = ssi::did_resolve::resolve_key(&vm, resolver)
            .await
            .context("unable to resolve key from verification method")?;

        if &key != signer.jwk() {
            bail!(
                "verification method resolved from DID document did not match public key of signer"
            )
        }

        let SessionBuilder {
            session,
            verifier,
            wallet_metadata,
            presentation_builder,
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
            session,
            wallet_metadata,
            client,
            presentation_builder,
            pass_by_reference,
            request_params,
            verifier,
        })
    }

    /// Configure the [ClientId] and set the [ClientIdScheme] to `x509_san_dns`.
    pub fn with_x509_san_dns_client_id(
        mut self,
        x5c: Vec<Certificate>,
        signer: RS,
    ) -> Result<Self> {
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
    pub fn with_x509_san_uri_client_id(
        mut self,
        x5c: Vec<Certificate>,
        signer: RS,
    ) -> Result<Self> {
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
