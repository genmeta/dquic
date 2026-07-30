use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::{FutureExt, StreamExt, stream};
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

async fn wait_for_lookup_count(resolver: &CountingResolver, expected: usize) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(1), async {
        while resolver.lookup_count() < expected {
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
async fn stun_clients_lookup_once_for_each_interface_generation() {
    let manager = InterfaceManager::global().clone();
    let old_bind = manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    let old_iface = old_bind.borrow();
    let stun = StunRouterComponent::new(old_iface.downgrade());
    let resolver = CountingResolver::default();
    let clients = StunClientsComponent::new(
        old_iface.downgrade(),
        stun.router(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        std::iter::empty(),
        None,
    );
    wait_for_lookup_count(&resolver, 1).await.unwrap();

    let new_bind = manager
        .bind(test_bind_uri(), Arc::new(DEFAULT_IO_FACTORY))
        .await;
    new_bind.insert_component_with(|_| stun);
    new_bind.insert_component_with(|_| clients.clone());

    let reinit_called = new_bind.with_components(|components, iface| {
        components.with(|clients: &StunClientsComponent| clients.reinit(iface))
    });
    assert!(reinit_called.is_some());
    wait_for_lookup_count(&resolver, 2).await.unwrap();
    tokio::task::yield_now().await;

    assert_eq!(resolver.lookup_count(), 2);
}
