use std::{
    fmt, io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::{FutureExt, StreamExt, future, stream};
use qbase::net::addr::EndpointAddr;
use qinterface::{
    bind_uri::BindUri, component::Component, io::handy::DEFAULT_IO_FACTORY,
    manager::InterfaceManager,
};
use qresolve::{Resolve, ResolveFuture, Source};
use qtraversal::{
    nat::{client::StunClientsComponent, router::StunRouterComponent},
    route::ReceiveAndDeliverPacketComponent,
};

#[derive(Debug, Clone, Default)]
struct CountingResolver {
    lookups: Arc<AtomicUsize>,
}

impl CountingResolver {
    fn lookup_count(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
struct RecoveringResolver {
    lookups: Arc<AtomicUsize>,
    agent: SocketAddr,
}

#[derive(Debug, Clone)]
struct TimeoutThenRecoveringResolver {
    lookups: Arc<AtomicUsize>,
    agent: SocketAddr,
}

impl TimeoutThenRecoveringResolver {
    fn new(agent: SocketAddr) -> Self {
        Self {
            lookups: Arc::new(AtomicUsize::new(0)),
            agent,
        }
    }

    fn lookup_count(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl RecoveringResolver {
    fn new(agent: SocketAddr) -> Self {
        Self {
            lookups: Arc::new(AtomicUsize::new(0)),
            agent,
        }
    }

    fn lookup_count(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl fmt::Display for RecoveringResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("recovering resolver")
    }
}

impl Resolve for RecoveringResolver {
    fn lookup<'l>(&'l self, _name: &'l str) -> ResolveFuture<'l> {
        let lookup = self.lookups.fetch_add(1, Ordering::SeqCst);
        let agent = self.agent;
        async move {
            if lookup == 0 {
                return Err(io::Error::other("network is not ready"));
            }
            Ok(stream::once(async move { (Source::System, EndpointAddr::direct(agent)) }).boxed())
        }
        .boxed()
    }
}

impl fmt::Display for TimeoutThenRecoveringResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("timeout then recovering resolver")
    }
}

impl Resolve for TimeoutThenRecoveringResolver {
    fn lookup<'l>(&'l self, _name: &'l str) -> ResolveFuture<'l> {
        let lookup = self.lookups.fetch_add(1, Ordering::SeqCst);
        let agent = self.agent;
        async move {
            if lookup == 0 {
                future::pending::<()>().await;
            }
            Ok(stream::once(async move { (Source::System, EndpointAddr::direct(agent)) }).boxed())
        }
        .boxed()
    }
}

impl fmt::Display for CountingResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("counting resolver")
    }
}

impl Resolve for CountingResolver {
    fn lookup<'l>(&'l self, _name: &'l str) -> ResolveFuture<'l> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        async move {
            let records = stream::empty::<(Source, EndpointAddr)>().boxed();
            Ok(records)
        }
        .boxed()
    }
}

async fn wait_for_counting_lookup_count(
    resolver: &CountingResolver,
    expected: usize,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while resolver.lookup_count() < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(io::Error::other)
}

async fn wait_for_recovering_lookup_count(
    resolver: &RecoveringResolver,
    expected: usize,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while resolver.lookup_count() < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(io::Error::other)
}

async fn wait_for_client_count(clients: &StunClientsComponent, expected: usize) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while clients.with_clients(|clients| clients.len()) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(io::Error::other)
}

fn test_bind_uri() -> BindUri {
    let base: BindUri = "inet://127.0.0.1:0".into();
    base.alloc_port()
}

#[tokio::test]
async fn receive_reinit_refreshes_stun_router_dependency() {
    let manager = InterfaceManager::global().clone();
    let old_bind = manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let old_iface = old_bind.borrow();

    let stale_stun = StunRouterComponent::new(old_iface.downgrade());
    let stale_router = stale_stun.router();
    let receive = ReceiveAndDeliverPacketComponent::builder(old_iface.downgrade())
        .stun_router(stale_router.clone())
        .init();

    let new_bind = manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    new_bind.insert_component_with(|_| stale_stun);
    new_bind.insert_component_with(|_| receive);

    let stale_receive = tokio::spawn({
        let stale_router = stale_router.clone();
        async move { stale_router.receive_request().await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!stale_receive.is_finished());

    let reinit_called = new_bind.with_components(|components, iface| {
        components.with(|receive: &ReceiveAndDeliverPacketComponent| receive.reinit(iface))
    });
    assert!(reinit_called.is_some());

    let received = tokio::time::timeout(Duration::from_secs(1), stale_receive)
        .await
        .expect("stale stun router did not close")
        .expect("stale receive task panicked");
    assert!(received.is_none());
}

#[tokio::test]
async fn stun_clients_preserve_known_agents_across_reinit() {
    let manager = InterfaceManager::global().clone();
    let old_bind = manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let old_iface = old_bind.borrow();
    let stun = StunRouterComponent::new(old_iface.downgrade());
    let resolver = CountingResolver::default();
    let known_agent: SocketAddr = "192.0.2.1:20004".parse().unwrap();
    let clients = StunClientsComponent::new(
        old_iface.downgrade(),
        stun.router(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        std::iter::once(known_agent),
        None,
    );
    assert!(clients.with_clients(|clients| clients.contains_key(&known_agent)));
    wait_for_counting_lookup_count(&resolver, 1).await.unwrap();

    let new_bind = manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    new_bind.insert_component_with(|_| stun);
    new_bind.insert_component_with(|_| clients.clone());

    let reinit_called = new_bind.with_components(|components, iface| {
        components.with(|clients: &StunClientsComponent| clients.reinit(iface))
    });
    assert!(reinit_called.is_some());
    wait_for_counting_lookup_count(&resolver, 2).await.unwrap();

    assert!(clients.with_clients(|clients| clients.contains_key(&known_agent)));
}

#[tokio::test(start_paused = true)]
async fn stun_clients_retry_lookup_after_transient_failure() {
    let manager = InterfaceManager::global().clone();
    let bind = manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let iface = bind.borrow();
    let stun = StunRouterComponent::new(iface.downgrade());
    let agent: SocketAddr = "192.0.2.2:20004".parse().unwrap();
    let resolver = RecoveringResolver::new(agent);
    let clients = StunClientsComponent::new(
        iface.downgrade(),
        stun.router(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        std::iter::empty(),
        None,
    );

    wait_for_recovering_lookup_count(&resolver, 1)
        .await
        .unwrap();
    assert_eq!(clients.with_clients(|clients| clients.len()), 0);

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_recovering_lookup_count(&resolver, 2)
        .await
        .unwrap();
    wait_for_client_count(&clients, 1).await.unwrap();

    assert!(clients.with_clients(|clients| clients.contains_key(&agent)));
}

#[tokio::test(start_paused = true)]
async fn stun_clients_retry_lookup_after_timeout() {
    let manager = InterfaceManager::global().clone();
    let bind = manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let iface = bind.borrow();
    let stun = StunRouterComponent::new(iface.downgrade());
    let agent: SocketAddr = "192.0.2.3:20004".parse().unwrap();
    let resolver = TimeoutThenRecoveringResolver::new(agent);
    let clients = StunClientsComponent::new(
        iface.downgrade(),
        stun.router(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        std::iter::empty(),
        None,
    );

    tokio::task::yield_now().await;
    assert_eq!(resolver.lookup_count(), 1);

    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_client_count(&clients, 1).await.unwrap();

    assert_eq!(resolver.lookup_count(), 2);
    assert!(clients.with_clients(|clients| clients.contains_key(&agent)));
}
