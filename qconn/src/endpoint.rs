use std::sync::Arc;

use bytes::Bytes;
pub use qbase::endpoint::{LocalAuthority, RemoteAuthority};
use qbase::{
    error::{Error, ErrorKind, QuicError},
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
    },
    param::{ArcParameters, ParameterId, core::Parameters},
    role::IntoRole,
};
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use crate::{ArcConnection, network::Network};

pub type Connected = (Option<LocalAuthority>, RemoteAuthority, ArcConnection);
pub type Accepted = (Option<RemoteAuthority>, LocalAuthority, ArcConnection);

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Scope: u8 {
        const LOOPBACK = 1;
        const INTERNAL = 2;
        const EXTERNAL = 4;
    }
}

#[allow(non_upper_case_globals)]
pub const Loopback: Scope = Scope::LOOPBACK;
#[allow(non_upper_case_globals)]
pub const Internal: Scope = Scope::INTERNAL;
#[allow(non_upper_case_globals)]
pub const External: Scope = Scope::EXTERNAL;

impl Scope {
    pub(crate) fn allows(self, pathway: Pathway, link: Link) -> bool {
        let direct = matches!(pathway.local(), EndpointAddr::Direct { addr } if addr == link.src)
            && matches!(pathway.remote(), EndpointAddr::Direct { addr } if addr == link.dst);
        let scope = if direct && link.src.ip().is_loopback() && link.dst.ip().is_loopback() {
            Loopback
        } else if direct && private(link.src.ip()) && private(link.dst.ip()) {
            Internal
        } else {
            External
        };
        self.contains(scope)
    }
}

fn private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        std::net::IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

/// Identity material and local parameter template; UDP sockets belong to Network.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub(crate) identity: Arc<qbase::endpoint::Endpoint>,
    pub(crate) parameters: ArcParameters,
}

impl Endpoint {
    pub fn new(
        provider: &CryptoProvider,
        name: &str,
        cert: Vec<CertificateDer<'static>>,
        priv_key: PrivateKeyDer<'static>,
        ocsp: Option<Bytes>,
        parameters: ArcParameters,
    ) -> Result<Self, rustls::Error> {
        Ok(Self {
            identity: qbase::endpoint::Endpoint::new(provider, name, cert, priv_key, ocsp)?,
            parameters,
        })
    }

    pub fn name(&self) -> &str {
        self.identity.name()
    }

    pub async fn connect(&self, name: &str) -> Result<Connected, Error> {
        Network::global()?.connect(Some(self.clone()), name).await
    }

    pub fn listen<F>(&self, scope: Scope, handler: F) -> Result<(), Error>
    where
        F: Fn(Accepted) + Send + Sync + 'static,
    {
        let network = Network::global()?;
        network.bind_scope(scope)?;
        network
            .listener
            .register(Arc::new(self.clone()), scope, Arc::new(handler))
    }

    pub fn unlisten(&self) -> Result<(), Error> {
        Network::global()?.listener.unregister(self)
    }

    pub(crate) fn local_parameters<R: IntoRole + Default>(&self) -> Result<Parameters<R>, Error> {
        let template = self.parameters.lock_guard()?;
        if template.is_remote_params_received() {
            return Err(QuicError::with_default_fty(
                ErrorKind::TransportParameter,
                "endpoint requires a local parameter template",
            )
            .into());
        }
        let values = match template.role() {
            qbase::role::Role::Client => template
                .client()
                .unwrap()
                .iter()
                .map(|(id, value)| (*id, value.clone()))
                .collect::<Vec<_>>(),
            qbase::role::Role::Server => template
                .server()
                .unwrap()
                .iter()
                .map(|(id, value)| (*id, value.clone()))
                .collect::<Vec<_>>(),
        };
        let mut parameters = Parameters::<R>::new();
        for (id, value) in values {
            if matches!(
                id,
                ParameterId::InitialSourceConnectionId
                    | ParameterId::OriginalDestinationConnectionId
                    | ParameterId::RetrySourceConnectionId
                    | ParameterId::StatelessResetToken
                    | ParameterId::PreferredAddress
            ) || id.belong_to(R::into_role()).is_err()
            {
                continue;
            }
            parameters.set(id, value).map_err(QuicError::from)?;
        }
        Ok(parameters)
    }
}

impl qtls::ResolveServerAuthority for Endpoint {
    fn resolve(&self, request: qtls::ServerCredentialRequest<'_>) -> Option<qtls::LocalAuthority> {
        if request.server_name != Some(self.name()) {
            return None;
        }
        crate::tls::local_authority(&LocalAuthority::from(self.identity.clone())).ok()
    }
}

impl qtls::ResolveClientAuthority for Endpoint {
    fn resolve(&self, _: qtls::ClientCertificateRequest<'_>) -> Option<qtls::LocalAuthority> {
        crate::tls::local_authority(&LocalAuthority::from(self.identity.clone())).ok()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Anonymous;

impl Anonymous {
    pub async fn connect(&self, name: &str) -> Result<Connected, Error> {
        Network::global()?.connect(None, name).await
    }
}

impl qtls::ResolveClientAuthority for Anonymous {
    fn resolve(&self, _: qtls::ClientCertificateRequest<'_>) -> Option<qtls::LocalAuthority> {
        None
    }
    fn has_authority(&self) -> bool {
        false
    }
}
