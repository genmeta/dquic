use std::{
    any::Any,
    fmt::{Debug, Display},
    io,
    net::{Ipv6Addr, SocketAddr},
    sync::{Arc, OnceLock, RwLock},
};

use dns_lookup::{AddrFamily, AddrInfoHints, SockType, getaddrinfo};
use futures::{
    FutureExt,
    future::{self, BoxFuture},
    stream::{BoxStream, FuturesUnordered},
};
pub use qbase::net::{Family, addr::EndpointAddr};

pub type PublishFuture<'a> = BoxFuture<'a, io::Result<()>>;

pub trait Publish: Any + Send + Sync + Display + Debug {
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &mut dyn Iterator<Item = EndpointAddr>,
    ) -> PublishFuture<'a>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    Mdns { nic: Arc<str>, family: Family },
    Http { server: Arc<str> },
    H3 { server: Arc<str> },
    System,
    Dht,
}

impl Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Mdns { nic, family } => write!(f, "MDNS Resolver({nic} {family})"),
            Source::Http { server } => write!(f, "HTTP DNS Resolver({server})"),
            Source::H3 { server } => write!(f, "H3 DNS Resolver({server})"),
            Source::System => write!(f, "System DNS Resolver"),
            Source::Dht => write!(f, "DHT"),
        }
    }
}

pub type Record = (Source, EndpointAddr);
pub type RecordStream = BoxStream<'static, Record>;
pub type ResolveResult = io::Result<RecordStream>;
pub type ResolveFuture<'r> = BoxFuture<'r, ResolveResult>;

/// Resolves names into QUIC peer endpoints.
///
/// The result is a stream to allow implementations that yield endpoints over time
/// (e.g. multi-source resolvers, H3x Dns, Mdns).
pub trait Resolve: Any + Send + Sync + Display + Debug {
    /// Resolves `hostname` and `servname` into peer endpoints.
    ///
    /// `hostname` may include a numeric port, which takes precedence over
    /// `servname`. An IPv6 address with a port must use `[address]:port` syntax;
    /// an unbracketed IPv6 address is treated as a hostname without a port.
    /// `servname` may be a service name such as `"https"` or a numeric port such
    /// as `"443"`; an empty `servname` defaults to `"443"`. A `family` of `None`
    /// corresponds to `AF_UNSPEC`; `Some(Family::V4)` and `Some(Family::V6)`
    /// correspond to `AF_INET` and `AF_INET6`, respectively.
    fn lookup<'l>(
        &'l self,
        hostname: &'l str,
        servname: &'l str,
        family: Option<Family>,
    ) -> ResolveFuture<'l>;
}

/// A snapshot of the process-wide resolvers. The registry is empty by default.
///
/// Register sources explicitly with [`Self::add`] and take a snapshot with
/// [`Self::get`] for each resolution. Lookups and result streams are polled
/// concurrently, preserving each record's source. No configuration lock is held
/// while a resolver runs. Later registrations affect subsequent snapshots only.
///
/// ```no_run
/// # async fn example() -> std::io::Result<()> {
/// qresolve::Resolver::add(std::sync::Arc::new(qresolve::SystemResolver));
/// let resolver = qresolve::Resolver::get();
/// let records = resolver.lookup("example.com", "443", None).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Resolver {
    resolvers: Vec<Arc<dyn Resolve>>,
}

impl Resolver {
    /// Snapshot all registered resolvers for an aggregate lookup.
    pub fn get() -> Arc<dyn Resolve> {
        Arc::new(Self {
            resolvers: Self::global().read().unwrap().clone(),
        })
    }

    /// Add a resolver for subsequent snapshots. System DNS is opt-in like any other source.
    pub fn add(resolver: Arc<dyn Resolve>) {
        Self::global().write().unwrap().push(resolver);
    }

    fn global() -> &'static RwLock<Vec<Arc<dyn Resolve>>> {
        static RESOLVERS: OnceLock<RwLock<Vec<Arc<dyn Resolve>>>> = OnceLock::new();
        RESOLVERS.get_or_init(|| RwLock::new(Vec::new()))
    }
}

impl Display for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Aggregate Resolver ({} sources)", self.resolvers.len())
    }
}

impl Resolve for Resolver {
    /// Return as soon as one resolver supplies a stream, then merge it with all
    /// other streams as they become available. A slow lookup or stream does not
    /// block records from another source. Records are not deduplicated.
    ///
    /// Failed sources are skipped. If every lookup fails, return the last error;
    /// a successful empty stream counts as success. Errors arriving after a
    /// successful lookup are also skipped because `RecordStream` carries records
    /// only. Dropping the future or stream drops its pending child operations.
    fn lookup<'l>(
        &'l self,
        hostname: &'l str,
        servname: &'l str,
        family: Option<Family>,
    ) -> ResolveFuture<'l> {
        let hostname: Arc<str> = Arc::from(hostname);
        let servname: Arc<str> = Arc::from(servname);
        let mut pending = self
            .resolvers
            .iter()
            .cloned()
            .map(|resolver| {
                let hostname = hostname.clone();
                let servname = servname.clone();
                async move { resolver.lookup(&hostname, &servname, family).await }.boxed()
            })
            .collect::<FuturesUnordered<_>>();
        async move {
            let mut error = io::Error::new(io::ErrorKind::NotFound, "no resolvers registered");
            while let Some(result) = pending.next().await {
                match result {
                    Ok(first) => {
                        let remaining = pending
                            .filter_map(|result| future::ready(result.ok()))
                            .flatten_unordered(None);
                        return Ok(stream::select(first, remaining).boxed());
                    }
                    Err(failed) => error = failed,
                }
            }
            Err(error)
        }
        .boxed()
    }
}

use futures::{StreamExt, stream};

/// Default resolver backed by the system `getaddrinfo` implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Display for SystemResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Source::System, f)
    }
}

impl Resolve for SystemResolver {
    fn lookup<'l>(
        &'l self,
        hostname: &'l str,
        servname: &'l str,
        family: Option<Family>,
    ) -> ResolveFuture<'l> {
        let hostname = hostname.to_owned();
        let servname = servname.to_owned();
        async move {
            let addrs = tokio::task::spawn_blocking(move || {
                lookup_socket_addrs(&hostname, &servname, family)
            })
            .await
            .map_err(io::Error::other)??;
            let source = Source::System;
            Ok(stream::iter(addrs.into_iter().map(move |addr| {
                let ep = EndpointAddr::direct(addr);
                (source.clone(), ep)
            }))
            .boxed())
        }
        .boxed()
    }
}

fn lookup_socket_addrs(
    hostname: &str,
    servname: &str,
    family: Option<Family>,
) -> io::Result<Vec<SocketAddr>> {
    let (hostname, port) = split_host_port(hostname);
    let servname = port.unwrap_or(servname);
    let servname = if servname.is_empty() { "443" } else { servname };
    let hints = AddrInfoHints {
        address: match family {
            None => 0,
            Some(Family::V4) => AddrFamily::Inet.into(),
            Some(Family::V6) => AddrFamily::Inet6.into(),
        },
        socktype: SockType::Stream.into(),
        ..AddrInfoHints::default()
    };
    getaddrinfo(Some(hostname), Some(servname), Some(hints))?
        .map(|info| info.map(|info| info.sockaddr))
        .collect()
}

/// Split an optional numeric port from a hostname or bracketed IPv6 address.
/// Bare IPv6 addresses have no port; unrecognized suffixes remain part of the host.
pub fn split_host_port(hostname: &str) -> (&str, Option<&str>) {
    if let Some(bracketed) = hostname.strip_prefix('[')
        && let Some((host, suffix)) = bracketed.split_once(']')
    {
        if suffix.is_empty() {
            return (host, None);
        }
        if let Some(port) = suffix.strip_prefix(':')
            && port.parse::<u16>().is_ok()
        {
            return (host, Some(port));
        }
    }

    if hostname.parse::<Ipv6Addr>().is_ok() {
        return (hostname, None);
    }

    if let Some((host, port)) = hostname.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
        && port.parse::<u16>().is_ok()
    {
        return (host, Some(port));
    }

    (hostname, None)
}

#[cfg(test)]
mod resolver_tests;

#[cfg(test)]
mod tests {
    use std::{
        any::Any,
        fmt::{self, Debug, Display},
    };

    use futures::FutureExt;

    use super::*;

    #[derive(Debug)]
    struct TestPublisher;

    impl Display for TestPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test publisher")
        }
    }

    impl Publish for TestPublisher {
        fn publish<'a>(
            &'a self,
            name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let endpoints: Vec<_> = endpoints.collect();
            async move {
                assert_eq!(name, "demo.dhttp.net");
                assert_eq!(endpoints.len(), 1);
                Ok(())
            }
            .boxed()
        }
    }

    #[test]
    fn publish_trait_accepts_endpoint_iterator() {
        let publisher: &dyn Publish = &TestPublisher;
        let endpoint = EndpointAddr::direct("203.0.113.10:4433".parse().unwrap());
        let mut endpoints = std::iter::once(endpoint);

        futures::executor::block_on(publisher.publish("demo.dhttp.net", &mut endpoints))
            .expect("publish succeeds");
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn resolve_trait_objects_upcast_to_any() {
        assert_send_sync::<SystemResolver>();
        let resolver: &dyn Resolve = &SystemResolver;
        let any: &dyn Any = resolver;

        assert!(any.is::<SystemResolver>());
    }

    #[test]
    fn publish_trait_objects_upcast_to_any() {
        assert_send_sync::<TestPublisher>();
        let publisher: &dyn Publish = &TestPublisher;
        let any: &dyn Any = publisher;

        assert!(any.is::<TestPublisher>());
    }

    #[test]
    fn h3_source_display_identifies_h3_dns() {
        let source = Source::H3 {
            server: Arc::from("https://dns.genmeta.net:4433"),
        };

        assert_eq!(
            source.to_string(),
            "H3 DNS Resolver(https://dns.genmeta.net:4433)"
        );
    }

    #[test]
    fn system_lookup_accepts_service_names_and_family() {
        let addrs = lookup_socket_addrs("localhost", "https", Some(Family::V4)).unwrap();

        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(SocketAddr::is_ipv4));
        assert!(addrs.iter().all(|addr| addr.port() == 443));

        let addrs = lookup_socket_addrs("localhost", "443", Some(Family::V4)).unwrap();
        assert!(addrs.iter().all(|addr| addr.port() == 443));

        let addrs = lookup_socket_addrs("localhost", "", Some(Family::V4)).unwrap();
        assert!(addrs.iter().all(|addr| addr.port() == 443));
    }

    #[test]
    fn hostname_port_overrides_servname() {
        let addrs = lookup_socket_addrs("localhost:8443", "443", Some(Family::V4)).unwrap();

        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|addr| addr.port() == 8443));
    }

    #[test]
    fn splits_host_and_port() {
        assert_eq!(
            split_host_port("example.com:8443"),
            ("example.com", Some("8443"))
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:8443"),
            ("2001:db8::1", Some("8443"))
        );
        assert_eq!(split_host_port("2001:db8::1"), ("2001:db8::1", None));
        assert_eq!(split_host_port("[2001:db8::1]"), ("2001:db8::1", None));
        assert_eq!(split_host_port("example.com"), ("example.com", None));
    }

    #[test]
    fn ipv6_hostname_port_requires_brackets() {
        let addrs = lookup_socket_addrs("[::1]:9443", "8443", Some(Family::V6)).unwrap();
        assert!(addrs.iter().all(|addr| addr.port() == 9443));

        let addrs = lookup_socket_addrs("::443", "8443", Some(Family::V6)).unwrap();
        assert!(addrs.iter().all(|addr| addr.port() == 8443));
    }
}
