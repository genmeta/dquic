use std::{sync::Arc, time::Duration};

use qinterface::{bind_uri::BindUri, io::handy::DEFAULT_IO_FACTORY, manager::InterfaceManager};
use qtraversal::{nat::router::StunRouterComponent, route::ReceiveAndDeliverPacketComponent};

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
