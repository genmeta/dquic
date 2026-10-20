use std::{
    borrow::Cow,
    fmt::Display,
    io,
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
};

use derive_more::{Display, Into};
use qbase::{net::Family, util::UniqueIdGenerator};
use thiserror::Error;

#[derive(Debug, Display, Clone, Into, PartialEq, Eq, Hash)]
pub struct BindUri(http::Uri);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBindUri {
    pub addr: SocketAddr,
    pub device: Option<ResolvedBindDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBindDevice {
    pub name: String,
    pub index: u32,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid uri {0}")]
    InvalidUri(<http::Uri as FromStr>::Err),
    #[error("Missing scheme")]
    NoScheme,
    #[error("Unsupported bind uri scheme: {0}")]
    Unsupported(String),
    #[error("Path must be empty")]
    Malformed,
    #[error("Missing ip family for iface scheme BindUri")]
    NoFamily,
    #[error("Missing port for iface scheme BindUri")]
    NoPort,
    #[error("Invalid IP address family for iface scheme")]
    UnknownFamily,
    #[error("Invalid IP address for inet scheme BindUri: {0}")]
    InvalidIpAddr(AddrParseError),
}

fn parse_iface_bind_uri(uri: &http::Uri) -> Result<(Family, &str, u16), ParseError> {
    let authority = uri.authority().expect("BindUri is absolute URI");
    let (ip_family, interface) = authority
        .host()
        .split_once('.')
        .ok_or(ParseError::NoFamily)?;
    let port = authority.port_u16().ok_or(ParseError::NoPort)?;
    let ip_family: Family = ip_family.parse().or(Err(ParseError::UnknownFamily))?;
    Ok((ip_family, interface, port))
}

fn parse_inet_bind_uri(uri: &http::Uri) -> Result<SocketAddr, ParseError> {
    let authority = uri.authority().expect("BindUri is absolute URI");
    let port = authority.port_u16().ok_or(ParseError::NoPort)?;
    let host = match authority.host().as_bytes() {
        [b'[', .., b']'] => authority.host().trim_matches(|c| matches!(c, '[' | ']')),
        _ => authority.host(),
    };
    match IpAddr::from_str(host) {
        Ok(ip) => Ok(SocketAddr::new(ip, port)),
        Err(e) => Err(ParseError::InvalidIpAddr(e)),
    }
}

impl FromStr for BindUri {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            return Ok(socket_addr.into());
        }
        s.parse::<http::Uri>()
            .map_err(ParseError::InvalidUri)?
            .try_into()
    }
}

impl TryFrom<http::Uri> for BindUri {
    type Error = ParseError;

    fn try_from(uri: http::Uri) -> Result<Self, Self::Error> {
        let scheme = uri
            .scheme()
            .ok_or(ParseError::NoScheme)?
            .as_str()
            .parse()
            .map_err(ParseError::Unsupported)?;
        debug_assert!(uri.authority().is_some(), "BindUri should be absolute URI");

        if uri.path() != "/" {
            return Err(ParseError::Malformed);
        }

        match scheme {
            Scheme::Iface => {
                parse_iface_bind_uri(&uri)?;
            }
            Scheme::Inet => {
                parse_inet_bind_uri(&uri)?;
            }
        }

        Ok(Self(uri))
    }
}

impl From<String> for BindUri {
    #[inline]
    fn from(value: String) -> Self {
        match BindUri::from_str(&value) {
            Ok(bind_uri) => bind_uri,
            Err(e) => panic!("bind uri should be valid: {e}"),
        }
    }
}

impl From<&str> for BindUri {
    #[inline]
    fn from(value: &str) -> Self {
        match BindUri::from_str(value) {
            Ok(bind_uri) => bind_uri,
            Err(e) => panic!("bind uri should be valid: {e}"),
        }
    }
}

impl From<SocketAddr> for BindUri {
    #[inline]
    fn from(value: SocketAddr) -> Self {
        match BindUri::from_str(&format!("inet://{value}")) {
            Ok(bind_uri) => bind_uri,
            Err(e) => panic!("{e}"),
        }
    }
}

impl<T: Copy + Into<BindUri>> From<&T> for BindUri {
    #[inline]
    fn from(value: &T) -> Self {
        (*value).into()
    }
}

impl From<&BindUri> for BindUri {
    #[inline]
    fn from(value: &BindUri) -> Self {
        value.clone()
    }
}

impl BindUri {
    pub const TEMPORARY_PROP: &str = "temporary";
    pub const STUN_PROP: &str = "stun";
    pub const STUN_SERVER_PROP: &str = "stun_server";
    pub const RELAY_PROP: &str = "relay";

    pub fn scheme(&self) -> Scheme {
        self.0
            .scheme()
            .expect("Invalid BindUri: Missing scheme")
            .as_str()
            .parse()
            .expect("Invalid BindUri: Invalid scheme")
    }

    #[inline]
    pub fn as_uri(&self) -> &http::Uri {
        &self.0
    }

    pub fn family(&self) -> Family {
        match self.scheme() {
            Scheme::Iface => {
                self.as_iface_bind_uri()
                    .expect("Already checked BindUriScheme is iface")
                    .0
            }
            Scheme::Inet => {
                match self
                    .as_inet_bind_uri()
                    .expect("Already checked BindUriScheme is inet")
                {
                    SocketAddr::V4(_) => Family::V4,
                    SocketAddr::V6(_) => Family::V6,
                }
            }
        }
    }

    pub fn as_iface_bind_uri(&self) -> Option<(Family, &str, u16)> {
        if self.scheme() != Scheme::Iface {
            return None;
        }
        Some(parse_iface_bind_uri(&self.0).expect("BindUri should be valid"))
    }

    pub fn as_inet_bind_uri(&self) -> Option<SocketAddr> {
        if self.scheme() != Scheme::Inet {
            return None;
        }
        Some(parse_inet_bind_uri(&self.0).expect("BindUri should be valid"))
    }

    pub fn add_prop(&mut self, key: &str, value: &str) {
        let mut uri_parts = self.0.clone().into_parts();
        uri_parts.path_and_query = uri_parts.path_and_query.map(|pq| {
            let query = match pq.query() {
                Some(exist_query) => format!("{exist_query}&{key}={value}"),
                None => format!("{key}={value}"),
            };
            format!("{}?{}", pq.path(), query)
                .parse()
                .expect("Path and query should be valid")
        });
        self.0 = http::Uri::from_parts(uri_parts).expect("BindUri should be valid");
    }

    pub const ALLOC_PORT_ID: &'static str = "alloc_port_id";

    pub fn alloc_port(&self) -> Self {
        match self.scheme() {
            Scheme::Iface => {
                let (.., port) = self
                    .as_iface_bind_uri()
                    .expect("Already checked BindUriScheme is iface");
                assert_eq!(port, 0, "Only port 0 is allocatable");
            }
            Scheme::Inet => {
                let addr = self
                    .as_inet_bind_uri()
                    .expect("Already checked BindUriScheme is inet");
                assert_eq!(addr.port(), 0, "Only port 0 is allocatable");
            }
        }

        let mut new_uri = self.clone();

        static ID_GENERATOR: UniqueIdGenerator = UniqueIdGenerator::new();
        let alloc_port_id = usize::from(ID_GENERATOR.generate()).to_string();
        new_uri.add_prop(Self::ALLOC_PORT_ID, &alloc_port_id);

        new_uri
    }

    #[inline]
    pub fn prop(&self, key: &str) -> Option<Cow<'_, str>> {
        // http://127.0.0.1/fx     ?key=value
        self.0
            .query()?
            .split('&')
            .find_map(|pair| match pair.split_once('=') {
                Some((k, v)) if k == key => Some(Cow::Borrowed(v)),
                None if pair == key => Some(Cow::Borrowed("")),
                _ => None,
            })
    }

    pub fn is_temporary(&self) -> bool {
        match self.prop(Self::TEMPORARY_PROP) {
            Some(bool) if bool == "true" => true,
            None | Some(..) => false,
        }
    }

    pub fn enable_stun(&mut self) {
        self.add_prop(Self::STUN_PROP, "true");
    }

    pub fn is_stun_enabled(&self) -> bool {
        match self.prop(Self::STUN_PROP) {
            Some(bool) if bool == "true" => true,
            None | Some(..) => false,
        }
    }

    pub fn with_stun_server(mut self, stun_server: &str) -> Self {
        self.add_prop(Self::STUN_SERVER_PROP, stun_server);
        self
    }

    pub fn stun_server(&self) -> Option<Cow<'_, str>> {
        self.prop(Self::STUN_SERVER_PROP)
    }

    // TODO: change to bool flag
    pub fn with_relay(mut self, relay: &str) -> Self {
        self.add_prop(Self::RELAY_PROP, relay);
        self
    }

    pub fn relay(&self) -> Option<Cow<'_, str>> {
        self.prop(Self::RELAY_PROP)
    }

    /// Return whether two bind URIs should be considered the same candidate
    /// during interface reconciliation.
    ///
    /// Full [`BindUri`] equality remains the identity rule for registries and
    /// lookup. Reconciliation is narrower: it ignores only `alloc_port_id`,
    /// which is generated by [`BindUri::alloc_port`] to distinguish concurrent
    /// port-0 allocation attempts. All other query properties remain semantic.
    pub fn matches_reconcile_candidate(&self, candidate: &Self) -> bool {
        fn without_alloc_port_id(uri: &http::Uri) -> http::Uri {
            let mut parts = uri.clone().into_parts();
            parts.path_and_query = parts.path_and_query.map(|path_and_query| {
                let Some(query) = path_and_query.query() else {
                    return path_and_query;
                };

                let retained = query
                    .split('&')
                    .filter(|pair| match pair.split_once('=') {
                        Some((key, _)) => key != BindUri::ALLOC_PORT_ID,
                        None => *pair != BindUri::ALLOC_PORT_ID,
                    })
                    .collect::<Vec<_>>();

                if retained.is_empty() {
                    path_and_query
                        .path()
                        .parse()
                        .expect("path portion should always be valid")
                } else {
                    format!("{}?{}", path_and_query.path(), retained.join("&"))
                        .parse()
                        .expect("path and retained query should be valid")
                }
            });
            http::Uri::from_parts(parts).expect("BindUri without alloc_port_id should be valid")
        }

        without_alloc_port_id(&self.0) == without_alloc_port_id(&candidate.0)
    }

    pub fn resolve_binding(&self) -> Result<ResolvedBindUri, io::Error> {
        match self.scheme() {
            Scheme::Iface => {
                let (ip_family, interface, port) = self
                    .as_iface_bind_uri()
                    .expect("Already checked BindUriScheme is iface");

                let device = netdev::get_interfaces()
                    .into_iter()
                    .find(|device| {
                        device.name.trim_start_matches('{').trim_end_matches('}') == interface
                    })
                    .ok_or(io::Error::new(
                        io::ErrorKind::NotFound,
                        "device not found".to_string(),
                    ))?;
                let ip_addr = match ip_family {
                    Family::V4 => device.ipv4.first().map(|ipnet| IpAddr::V4(ipnet.addr())),
                    Family::V6 => device
                        .ipv6
                        .iter()
                        .map(|ipnet| ipnet.addr())
                        .find(|ip| !matches!(ip.octets(), [0xfe, 0x80, ..]))
                        .map(IpAddr::V6),
                }
                .ok_or(io::Error::new(
                    io::ErrorKind::NotFound,
                    "ip not matched".to_string(),
                ))?;

                Ok(ResolvedBindUri {
                    addr: SocketAddr::new(ip_addr, port),
                    device: Some(ResolvedBindDevice {
                        name: device.name,
                        index: device.index,
                    }),
                })
            }
            Scheme::Inet => Ok(ResolvedBindUri {
                addr: self
                    .as_inet_bind_uri()
                    .expect("Already checked BindUriScheme is inet"),
                device: None,
            }),
        }
    }

    pub fn resolve(&self) -> Result<SocketAddr, io::Error> {
        self.resolve_binding().map(|binding| binding.addr)
    }
}

impl TryFrom<&BindUri> for SocketAddr {
    type Error = io::Error;

    fn try_from(bind_uri: &BindUri) -> Result<Self, Self::Error> {
        bind_uri.resolve()
    }
}

impl TryFrom<BindUri> for SocketAddr {
    type Error = io::Error;

    fn try_from(bind_uri: BindUri) -> Result<Self, Self::Error> {
        SocketAddr::try_from(&bind_uri)
    }
}
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Iface,
    Inet,
}

impl Scheme {
    pub const fn to_str(&self) -> &'static str {
        match self {
            Scheme::Iface => "iface",
            Scheme::Inet => "inet",
        }
    }
}

impl From<Scheme> for http::uri::Scheme {
    fn from(value: Scheme) -> Self {
        value
            .to_str()
            .parse()
            .expect("BindUriScheme should be valid URI scheme")
    }
}

impl FromStr for Scheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "iface" => Ok(Scheme::Iface),
            "inet" => Ok(Scheme::Inet),
            other => Err(other.to_string()),
        }
    }
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_str().fmt(f)
    }
}
