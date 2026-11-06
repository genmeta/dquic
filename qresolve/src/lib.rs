use std::{
    any::Any,
    fmt::{Debug, Display},
    io,
    sync::{Arc, OnceLock, RwLock},
};

use futures::{
    FutureExt, StreamExt,
    future::{self, BoxFuture},
    stream::{self, BoxStream, FuturesUnordered},
};
pub use qbase::net::{Family, addr::EndpointAddr};

mod sys;
pub use sys::{SystemResolver, split_name_port};

pub type PublishFuture<'a> = BoxFuture<'a, io::Result<()>>;

pub trait Publish: Any + Send + Sync + Display + Debug {
    fn publish<'a>(&'a self, name: &'a str, endpoints: &mut dyn Iterator<Item = EndpointAddr>) -> PublishFuture<'a>;
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
    fn lookup<'l>(&'l self, hostname: &'l str, servname: &'l str, family: Option<Family>) -> ResolveFuture<'l>;
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
        Arc::new(Self { resolvers: Self::global().read().unwrap().clone() })
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
    fn lookup<'l>(&'l self, hostname: &'l str, servname: &'l str, family: Option<Family>) -> ResolveFuture<'l> {
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
                        let remaining = pending.filter_map(|result| future::ready(result.ok())).flatten_unordered(None);
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
