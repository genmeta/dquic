mod common;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use common::*;
use qbase::net::addr::EndpointAddr;
use qinterface::{
    component::location::{AddressEvent, LocalEndpointSet, Locations, LocationsComponent},
    io::IO,
    manager::InterfaceManager,
};
use tokio::time;

#[test]
fn locations_component_emits_closed_then_upsert_on_rebind() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());

        let bind_uri = test_bind_uri();
        let bind_iface = manager.bind(bind_uri.clone(), factory).await;

        let locations = Arc::new(Locations::new());
        let mut observer = locations.subscribe();

        bind_iface.insert_component_with(|iface| {
            LocationsComponent::new(iface.downgrade(), locations.clone())
        });

        // initial upsert (bound_addr result) should be delivered to the subscriber
        let (u_bind, ev) = time::timeout(Duration::from_secs(2), observer.recv())
            .await
            .expect("timeout waiting for initial upsert")
            .expect("observer closed");
        assert_eq!(u_bind, bind_uri);
        assert!(matches!(ev, AddressEvent::Upsert(_)));

        // trigger rebind
        bind_iface.rebind().await;

        // must see Closed then Upsert for same bind_uri
        loop {
            let (c_bind, c_ev) = time::timeout(Duration::from_secs(2), observer.recv())
                .await
                .expect("timeout waiting for closed")
                .expect("observer closed");
            assert_eq!(c_bind, bind_uri);
            if matches!(c_ev, AddressEvent::Closed) {
                break;
            }
        }

        let (u2_bind, u2_ev) = time::timeout(Duration::from_secs(2), observer.recv())
            .await
            .expect("timeout waiting for upsert")
            .expect("observer closed");
        assert_eq!(u2_bind, bind_uri);
        assert!(matches!(u2_ev, AddressEvent::Upsert(_)));

        // sanity: stale interface should not be able to touch component
        let old_iface = bind_iface.borrow();
        bind_iface.rebind().await;
        let err = old_iface.with_components(|_c| ()).unwrap_err();
        let _ = err;
    })
}

async fn recv_local_endpoint_set(
    observer: &mut qinterface::component::location::Observer,
) -> (qinterface::bind_uri::BindUri, Arc<LocalEndpointSet>) {
    loop {
        let (bind_uri, event) = time::timeout(Duration::from_secs(2), observer.recv())
            .await
            .expect("timeout waiting for local endpoint set")
            .expect("observer closed");
        if let Ok(AddressEvent::Upsert(endpoints)) = event.downcast::<LocalEndpointSet>() {
            return (bind_uri, endpoints);
        }
    }
}

#[test]
fn interface_agent_location_raii_updates_aggregated_local_endpoint_set() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());

        let bind_uri = test_bind_uri();
        let bind_iface = manager.bind(bind_uri.clone(), factory).await;
        let direct_addr = bind_iface
            .borrow()
            .bound_addr()
            .expect("test interface should have bound addr");
        let direct_endpoint = EndpointAddr::direct(direct_addr);

        let locations = Arc::new(Locations::new());
        let mut observer = locations.subscribe();

        bind_iface.insert_component_with(|iface| {
            LocationsComponent::new(iface.downgrade(), locations.clone())
        });

        let (initial_bind, initial_set) = recv_local_endpoint_set(&mut observer).await;
        assert_eq!(initial_bind, bind_uri);
        assert_eq!(initial_set.endpoints(), &[direct_endpoint]);

        let first_agent: SocketAddr = "192.0.2.10:3478".parse().expect("socket addr");
        let first_outer: SocketAddr = "198.51.100.20:45678".parse().expect("socket addr");
        let second_agent: SocketAddr = "192.0.2.11:3478".parse().expect("socket addr");
        let second_outer: SocketAddr = "198.51.100.21:45679".parse().expect("socket addr");
        let first_endpoint = EndpointAddr::with_agent(first_agent, first_outer);
        let second_endpoint = EndpointAddr::with_agent(second_agent, second_outer);

        let first_location = bind_iface.with_components(|components, _iface| {
            components
                .get::<LocationsComponent>()
                .expect("locations component")
                .agent_location(first_agent)
        });
        first_location.upsert(first_outer);

        let (_bind, with_first) = recv_local_endpoint_set(&mut observer).await;
        assert_eq!(with_first.endpoints(), &[direct_endpoint, first_endpoint]);

        let second_location = bind_iface.with_components(|components, _iface| {
            components
                .get::<LocationsComponent>()
                .expect("locations component")
                .agent_location(second_agent)
        });
        second_location.upsert(second_outer);

        let (_bind, with_both) = recv_local_endpoint_set(&mut observer).await;
        assert_eq!(
            with_both.endpoints(),
            &[direct_endpoint, first_endpoint, second_endpoint]
        );

        drop(first_location);

        let (_bind, after_first_drop) = recv_local_endpoint_set(&mut observer).await;
        assert_eq!(
            after_first_drop.endpoints(),
            &[direct_endpoint, second_endpoint]
        );

        drop(second_location);

        let (_bind, after_second_drop) = recv_local_endpoint_set(&mut observer).await;
        assert_eq!(after_second_drop.endpoints(), &[direct_endpoint]);
    })
}
