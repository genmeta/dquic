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

    /// Returns a canonical key for reconciliation purposes.
    ///
    /// Strips ephemeral query parameters (like `alloc_port_id`) so that two
    /// `BindUri`s pointing at the same interface/port compare as equal even
    /// when produced by separate `alloc_port()` calls.
    pub fn identity_key(&self) -> String {
        let uri = &self.0;
        let mut parts = uri.clone().into_parts();
        parts.path_and_query = parts.path_and_query.map(|pq| {
            pq.path()
                .parse()
                .expect("path portion should always be valid")
        });
        http::Uri::from_parts(parts)
            .expect("BindUri without query should be valid")
            .to_string()
    }

    pub fn resolve_binding(&self) -> Result<ResolvedBindUri, io::Error> {
        match self.scheme() {
            Scheme::Iface => {
                let (ip_family, interface, port) = self
                    .as_iface_bind_uri()
                    .expect("Already checked BindUriScheme is iface");

                let devices = crate::device::Devices::global();
                let device = devices.get(interface).ok_or(io::Error::new(
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
                        name: interface.to_owned(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_uri() {
        assert!(matches!(
            BindUri::from_str("iface://"),
            Err(ParseError::InvalidUri(_))
        ));
    }

    #[test]
    fn missing_scheme() {
        assert!(matches!(
            BindUri::from_str("invalid_uri"),
            Err(ParseError::NoScheme)
        ));
    }

    #[test]
    fn invalid_scheme() {
        assert!(matches!(
            BindUri::from_str("invalid://example.com"),
            Err(ParseError::Unsupported(_))
        ));
    }

    #[test]
    fn has_path() {
        assert!(matches!(
            BindUri::from_str("iface://v4.wlan0/1234"),
            Err(ParseError::Malformed)
        ));
    }

    #[test]
    fn missing_ip_family() {
        assert!(matches!(
            BindUri::from_str("iface://wlan0:8080"),
            Err(ParseError::NoFamily)
        ));
    }

    #[test]
    fn missing_port() {
        assert!(matches!(
            BindUri::from_str("iface://v4.wlan0"),
            Err(ParseError::NoPort)
        ));
    }

    #[test]
    fn invalid_ip_family() {
        assert!(matches!(
            BindUri::from_str("iface://invalid.wlan0:8080"),
            Err(ParseError::UnknownFamily)
        ));
    }

    #[test]
    fn invalid_ip_addr() {
        assert!(matches!(
            BindUri::from_str("inet://example.com:8080"),
            Err(ParseError::InvalidIpAddr(..))
        ));
    }

    #[test]
    fn iface_bind_uri() {
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=true").unwrap();
        assert_eq!(bind_uri.scheme(), Scheme::Iface);
        let (family, interface, port) = bind_uri.as_iface_bind_uri().unwrap();
        assert_eq!(family, Family::V4);
        assert_eq!(interface, "wlan0");
        assert_eq!(port, 8080);
        assert_eq!(
            bind_uri.prop(BindUri::TEMPORARY_PROP).as_deref(),
            Some("true")
        );
    }

    #[test]
    fn inet_bind_uri() {
        let bind_uri = BindUri::from_str("inet://127.0.0.1:7777").unwrap();
        assert_eq!(bind_uri.scheme(), Scheme::Inet);
        let addr = bind_uri.as_inet_bind_uri().unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 7777)
        );
        assert!(bind_uri.as_uri().query().is_none());
    }

    // tokio runtime requeired for device listing
    #[tokio::test]
    async fn interface_not_found() {
        let bind_uri = BindUri::from_str(
            "iface://v4.ygiubiougbuyasiudbahsdbadfbkjadbhvkjabvckagdoiuehfjoiajhrpfhrbovhaelvkamdjkfs:8080",
        )
        .unwrap();
        assert!(SocketAddr::try_from(bind_uri).is_err_and(|e| e.kind() == io::ErrorKind::NotFound))
    }

    #[tokio::test]
    async fn iface_binding_retains_device_index() {
        let devices = crate::device::Devices::global();
        let (device_name, iface, ip) = devices
            .interfaces()
            .into_iter()
            .find_map(|(device_name, iface)| {
                iface
                    .ipv4
                    .first()
                    .map(|ipnet| (device_name, iface.clone(), ipnet.addr()))
            })
            .expect("test host should have at least one IPv4 interface");

        let bind_uri = BindUri::from_str(&format!("iface://v4.{device_name}:8080")).unwrap();
        let binding = bind_uri.resolve_binding().unwrap();

        assert_eq!(binding.addr, SocketAddr::new(IpAddr::V4(ip), 8080));
        assert_eq!(
            binding.device.as_ref().map(|device| device.name.as_str()),
            Some(device_name.as_str())
        );
        assert_eq!(
            binding.device.as_ref().map(|device| device.index),
            Some(iface.index)
        );
    }

    #[test]
    fn to_socket_addr() {
        let bind_uri = BindUri::from_str("inet://127.0.0.1:8080").unwrap();
        assert_eq!(
            SocketAddr::try_from(bind_uri).unwrap(),
            "127.0.0.1:8080".parse().unwrap()
        );
    }

    #[test]
    fn alloc_port() {
        let bind_uri = BindUri::from_str("inet://0.0.0.0:0").unwrap();
        assert_ne!(bind_uri.clone().alloc_port(), bind_uri.clone().alloc_port());
    }

    #[test]
    #[should_panic]
    fn alloc_port_for_non_zero_port1() {
        let bind_uri = BindUri::from_str("inet://127.0.0.1:8080").unwrap();
        bind_uri.alloc_port();
    }

    #[test]
    #[should_panic]
    fn alloc_port_for_non_zero_port2() {
        let bind_uri = BindUri::from_str("inet://v4.lo:12345").unwrap();
        bind_uri.alloc_port();
    }

    #[test]
    fn temporary() {
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=true").unwrap();
        assert!(bind_uri.is_temporary());
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=false").unwrap();
        assert!(!bind_uri.is_temporary());
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(!bind_uri.is_temporary());
        let bind_uri =
            BindUri::from_str("iface://v4.C5563ED1-2BC9-42C5-8177-59F2F0AF37C8:8080").unwrap();
        assert!(!bind_uri.is_temporary());

        let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        bind_uri.add_prop(BindUri::TEMPORARY_PROP, "true");
        assert_eq!(
            bind_uri.to_string(),
            "iface://v4.wlan0:8080/?temporary=true"
        );
        assert!(bind_uri.is_temporary());
    }

    #[test]
    fn stun_enabled() {
        let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(!bind_uri.is_stun_enabled());

        bind_uri.enable_stun();
        assert!(bind_uri.is_stun_enabled());

        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?stun=true").unwrap();
        assert!(bind_uri.is_stun_enabled());

        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?stun=false").unwrap();
        assert!(!bind_uri.is_stun_enabled());
    }

    #[test]
    fn stun_server() {
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(bind_uri.stun_server().is_none());

        let bind_uri = bind_uri.with_stun_server("stun.example.com:3478");
        assert_eq!(
            bind_uri.stun_server().as_deref(),
            Some("stun.example.com:3478")
        );

        let bind_uri =
            BindUri::from_str("iface://v4.wlan0:8080?stun_server=stun.genmeta.net").unwrap();
        assert_eq!(bind_uri.stun_server().as_deref(), Some("stun.genmeta.net"));
    }

    #[test]
    fn relay() {
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(bind_uri.relay().is_none());

        let bind_uri = bind_uri.with_relay("turn.example.com:3478");
        assert_eq!(bind_uri.relay().as_deref(), Some("turn.example.com:3478"));

        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?relay=turn.genmeta.net").unwrap();
        assert_eq!(bind_uri.relay().as_deref(), Some("turn.genmeta.net"));
    }
}
