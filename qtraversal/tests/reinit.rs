use std::{
    fmt, io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
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
    nat::{
        client::{DetectNatTypeError, DetectOuterAddrError, StunClientComponent},
        router::StunRouterComponent,
    },
    route::ReceiveAndDeliverPacketComponent,
};

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
    fn lookup<'l>(
        &'l self,
        _hostname: &'l str,
        _servname: &'l str,
        _family: Option<qbase::net::Family>,
    ) -> ResolveFuture<'l> {
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
    fn lookup<'l>(
        &'l self,
        _hostname: &'l str,
        _servname: &'l str,
        _family: Option<qbase::net::Family>,
    ) -> ResolveFuture<'l> {
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

async fn wait_for_client(component: &StunClientComponent) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while component.with_client(|client| client.is_none()) {
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
async fn stun_client_refreshes_dns_across_reinit() {
    let interface_manager = InterfaceManager::global().clone();
    let old_bind = interface_manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let old_iface = old_bind.borrow();
    let stun = StunRouterComponent::new(old_iface.downgrade());
    let known_agent: SocketAddr = "192.0.2.1:20004".parse().unwrap();
    let resolver = RecoveringResolver::new(known_agent);
    let stun_component = StunClientComponent::new(
        old_iface.downgrade(),
        stun.router(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        Some(known_agent),
        None,
    );
    assert!(
        stun_component.with_client(|client| {
            client.is_some_and(|client| client.agent_addr() == known_agent)
        })
    );
    let new_bind = interface_manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    new_bind.insert_component_with(|_| stun);
    new_bind.insert_component_with(|_| stun_component.clone());

    let reinit_called = new_bind.with_components(|components, iface| {
        components.with(|component: &StunClientComponent| component.reinit(iface))
    });
    assert!(reinit_called.is_some());
    wait_for_recovering_lookup_count(&resolver, 1)
        .await
        .unwrap();
    wait_for_client(&stun_component).await.unwrap();
    assert!(resolver.lookup_count() >= 2);
    assert!(
        stun_component.with_client(|client| {
            client.is_some_and(|client| client.agent_addr() == known_agent)
        })
    );
}

#[tokio::test]
async fn reinit_invalidates_escaped_client_clone() {
    let interface_manager = InterfaceManager::global().clone();
    let old_bind = interface_manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let old_iface = old_bind.borrow();
    let stun = StunRouterComponent::new(old_iface.downgrade());
    let known_agent: SocketAddr = "192.0.2.1:20004".parse().unwrap();
    let stun_component = StunClientComponent::new(
        old_iface.downgrade(),
        stun.router(),
        Arc::new(RecoveringResolver::new(known_agent)),
        "stun.example:20004",
        Some(known_agent),
        None,
    );
    let stale_client = stun_component
        .with_client(|client| client.cloned())
        .expect("known STUN client missing");

    assert!(!matches!(
        stale_client.get_outer_addr(),
        Some(Err(DetectOuterAddrError::Rebinded { .. }))
    ));
    assert!(!matches!(
        stale_client.get_nat_type(),
        Some(Err(DetectNatTypeError::Rebinded { .. }))
    ));

    let new_bind = interface_manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    new_bind.insert_component_with(|_| stun);
    new_bind.insert_component_with(|_| stun_component.clone());
    new_bind.with_components(|components, iface| {
        components
            .with(|component: &StunClientComponent| component.reinit(iface))
            .expect("STUN client component missing");
    });

    assert!(matches!(
        stale_client.get_outer_addr(),
        Some(Err(DetectOuterAddrError::Rebinded { .. }))
    ));
    assert!(matches!(
        stale_client.get_nat_type(),
        Some(Err(DetectNatTypeError::Rebinded { .. }))
    ));
    wait_for_client(&stun_component).await.unwrap();
    assert!(
        stun_component.with_client(|client| {
            client.is_some_and(|client| client.agent_addr() == known_agent)
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_client_blocks_reinit_until_reader_finishes() {
    #[derive(Debug, PartialEq)]
    enum Step {
        ReaderHasLock,
        ReinitStarted,
        ReinitFinished,
    }

    let interface_manager = InterfaceManager::global().clone();
    let old_bind = interface_manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let old_iface = old_bind.borrow();
    let stun = StunRouterComponent::new(old_iface.downgrade());
    let known_agent: SocketAddr = "192.0.2.1:20004".parse().unwrap();
    let stun_component = StunClientComponent::new(
        old_iface.downgrade(),
        stun.router(),
        Arc::new(RecoveringResolver::new(known_agent)),
        "stun.example:20004",
        Some(known_agent),
        None,
    );

    let new_bind = interface_manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    new_bind.insert_component_with(|_| stun);
    new_bind.insert_component_with(|_| stun_component.clone());

    // Reader: |------- with_client holds the state lock -------|
    // Reinit:          |---------- blocked ----------| reinit
    let (step_tx, step_rx) = mpsc::channel();
    let (release_reader_tx, release_reader_rx) = mpsc::channel();
    let reader_component = stun_component.clone();
    let reader_step_tx = step_tx.clone();
    let reader = thread::spawn(move || {
        reader_component.with_client(|client| {
            let client = client.expect("known STUN client missing");
            assert_eq!(client.agent_addr(), known_agent);
            reader_step_tx.send(Step::ReaderHasLock).unwrap();
            release_reader_rx.recv().unwrap();
            assert_eq!(client.agent_addr(), known_agent);
        });
    });
    assert_eq!(
        step_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        Step::ReaderHasLock
    );

    let reinit_step_tx = step_tx.clone();
    let reinit = tokio::task::spawn_blocking(move || {
        reinit_step_tx.send(Step::ReinitStarted).unwrap();
        new_bind.with_components(|components, iface| {
            components.with(|component: &StunClientComponent| component.reinit(iface))
        });
        reinit_step_tx.send(Step::ReinitFinished).unwrap();
    });
    assert_eq!(
        step_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        Step::ReinitStarted
    );
    assert_eq!(
        step_rx.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );

    release_reader_tx.send(()).unwrap();
    reader.join().unwrap();
    assert_eq!(
        step_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
        Step::ReinitFinished
    );
    reinit.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn stun_client_retries_lookup_after_transient_failure() {
    let interface_manager = InterfaceManager::global().clone();
    let bind = interface_manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let iface = bind.borrow();
    let stun = StunRouterComponent::new(iface.downgrade());
    let agent: SocketAddr = "192.0.2.2:20004".parse().unwrap();
    let resolver = RecoveringResolver::new(agent);
    let stun_component = StunClientComponent::new(
        iface.downgrade(),
        stun.router(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        None,
        None,
    );

    wait_for_recovering_lookup_count(&resolver, 1)
        .await
        .unwrap();
    assert!(stun_component.with_client(|client| client.is_none()));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_recovering_lookup_count(&resolver, 2)
        .await
        .unwrap();
    wait_for_client(&stun_component).await.unwrap();

    assert!(
        stun_component
            .with_client(|client| client.is_some_and(|client| client.agent_addr() == agent))
    );
}

#[tokio::test(start_paused = true)]
async fn stun_client_retries_lookup_after_timeout() {
    let interface_manager = InterfaceManager::global().clone();
    let bind = interface_manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let iface = bind.borrow();
    let stun = StunRouterComponent::new(iface.downgrade());
    let agent: SocketAddr = "192.0.2.3:20004".parse().unwrap();
    let resolver = TimeoutThenRecoveringResolver::new(agent);
    let stun_component = StunClientComponent::new(
        iface.downgrade(),
        stun.router(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        None,
        None,
    );

    tokio::task::yield_now().await;
    assert_eq!(resolver.lookup_count(), 1);

    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_client(&stun_component).await.unwrap();

    assert!(resolver.lookup_count() >= 2);
    assert!(
        stun_component
            .with_client(|client| client.is_some_and(|client| client.agent_addr() == agent))
    );
}
