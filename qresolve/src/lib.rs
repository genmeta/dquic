use std::{
    any::Any,
    fmt::{Debug, Display},
    io,
    sync::Arc,
};

use futures::{FutureExt, TryFutureExt, future::BoxFuture, stream::BoxStream};
pub use qbase::net::{Family, addr::EndpointAddr};

pub type PublishFuture<'a> = BoxFuture<'a, io::Result<()>>;

pub trait Publish: Any + Send + Sync + Display + Debug {
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a>;
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
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l>;
}

use futures::{StreamExt, stream};

/// Default resolver backed by `tokio::net::lookup_host`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Display for SystemResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Source::System, f)
    }
}

impl Resolve for SystemResolver {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        let source = Source::System;
        tokio::net::lookup_host(name.to_owned())
            .map_ok(|addrs| {
                stream::iter(addrs.map(move |addr| {
                    let ep = EndpointAddr::direct(addr);
                    (source.clone(), ep)
                }))
                .boxed()
            })
            .boxed()
    }
}

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
        fn publish<'a>(&'a self, _name: &'a str, _packet: &'a [u8]) -> PublishFuture<'a> {
            async { Ok(()) }.boxed()
        }
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
}
