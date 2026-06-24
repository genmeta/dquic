use std::{net::SocketAddr, sync::Arc};

use qbase::net::addr::EndpointAddr;
use qinterface::{
    bind_uri::BindUri,
    component::local_endpoint::{InterfaceEndpointKey, InterfaceEndpointUpdate, LocalEndpoints},
};
use tokio::time::{Duration, timeout};

fn bind_uri(port: u16) -> BindUri {
    format!("inet://127.0.0.1:{port}")
        .parse()
        .expect("valid bind uri")
}

fn socket(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}")
        .parse()
        .expect("valid socket addr")
}

async fn recv_update(
    subscriber: &mut qinterface::component::local_endpoint::LocalEndpointSubscriber,
) -> (BindUri, InterfaceEndpointUpdate) {
    timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("subscriber should receive before timeout")
        .expect("local endpoint hub should still be alive")
}

#[tokio::test]
async fn subscriber_replays_current_keyed_endpoints() {
    let local_endpoints = Arc::new(LocalEndpoints::new());
    let bind = bind_uri(10001);
    let direct_addr = socket(10002);
    let agent = socket(20004);
    let outer = socket(30005);

    let publishers = local_endpoints.publisher(bind.clone());
    let mut direct = publishers
        .direct_endpoint_publisher()
        .expect("direct claim should succeed");
    let mut agent_publisher = publishers
        .agent_endpoint_publisher(agent)
        .expect("agent claim should succeed");

    assert!(direct.upsert(direct_addr));
    assert!(agent_publisher.upsert(outer));

    let mut subscriber = local_endpoints.subscribe();
    let mut received = [
        recv_update(&mut subscriber).await,
        recv_update(&mut subscriber).await,
    ];
    received.sort_by(|left, right| format!("{:?}", left.1).cmp(&format!("{:?}", right.1)));

    assert_eq!(received[0].0, bind);
    assert_eq!(received[1].0, bind);
    assert!(received.iter().any(|(_, update)| match *update {
        InterfaceEndpointUpdate::Upsert {
            key: InterfaceEndpointKey::Direct,
            endpoint: EndpointAddr::Direct { addr },
        } => addr == direct_addr,
        _ => false,
    }));
    assert!(received.iter().any(|(_, update)| match *update {
        InterfaceEndpointUpdate::Upsert {
            key: InterfaceEndpointKey::Agent(key_agent),
            endpoint:
                EndpointAddr::Agent {
                    agent: endpoint_agent,
                    outer: endpoint_outer,
                },
        } => key_agent == agent && endpoint_agent == agent && endpoint_outer == outer,
        _ => false,
    }));
}

#[tokio::test]
async fn direct_publisher_is_unique_and_drop_removes_endpoint() {
    let local_endpoints = LocalEndpoints::new();
    let bind = bind_uri(10011);
    let publishers = local_endpoints.publisher(bind.clone());
    let mut direct = publishers
        .direct_endpoint_publisher()
        .expect("direct claim should succeed");

    assert!(publishers.direct_endpoint_publisher().is_err());

    let mut subscriber = local_endpoints.subscribe();
    assert!(direct.upsert(socket(10012)));
    let (_, upsert) = recv_update(&mut subscriber).await;
    assert!(matches!(
        upsert,
        InterfaceEndpointUpdate::Upsert {
            key: InterfaceEndpointKey::Direct,
            ..
        }
    ));

    drop(direct);
    let (remove_bind, remove) = recv_update(&mut subscriber).await;
    assert_eq!(remove_bind, bind);
    assert!(matches!(
        remove,
        InterfaceEndpointUpdate::Remove {
            key: InterfaceEndpointKey::Direct
        }
    ));

    assert!(publishers.direct_endpoint_publisher().is_ok());
}

#[tokio::test]
async fn old_generation_drop_does_not_remove_new_generation_endpoint() {
    let local_endpoints = LocalEndpoints::new();
    let bind = bind_uri(10021);
    let old_publishers = local_endpoints.publisher(bind.clone());
    let mut old_direct = old_publishers
        .direct_endpoint_publisher()
        .expect("old direct claim should succeed");
    assert!(old_direct.upsert(socket(10022)));

    let mut subscriber = local_endpoints.subscribe();
    let _ = recv_update(&mut subscriber).await;

    old_publishers.close();
    let (_, close) = recv_update(&mut subscriber).await;
    assert!(matches!(close, InterfaceEndpointUpdate::Close));

    let new_publishers = local_endpoints.publisher(bind.clone());
    let mut new_direct = new_publishers
        .direct_endpoint_publisher()
        .expect("new direct claim should succeed");
    assert!(new_direct.upsert(socket(10023)));
    let (_, new_upsert) = recv_update(&mut subscriber).await;
    assert!(matches!(
        new_upsert,
        InterfaceEndpointUpdate::Upsert {
            key: InterfaceEndpointKey::Direct,
            ..
        }
    ));

    drop(old_direct);
    assert!(
        timeout(Duration::from_millis(100), subscriber.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn agent_publishers_are_unique_per_agent_and_can_coexist_across_agents() {
    let local_endpoints = LocalEndpoints::new();
    let bind = bind_uri(10031);
    let first_agent = socket(20031);
    let second_agent = socket(20032);
    let publishers = local_endpoints.publisher(bind.clone());

    let mut first = publishers
        .agent_endpoint_publisher(first_agent)
        .expect("first agent claim should succeed");
    assert!(publishers.agent_endpoint_publisher(first_agent).is_err());
    let mut second = publishers
        .agent_endpoint_publisher(second_agent)
        .expect("second agent claim should succeed");

    let mut subscriber = local_endpoints.subscribe();
    assert!(first.upsert(socket(30031)));
    assert!(second.upsert(socket(30032)));

    let (_, first_update) = recv_update(&mut subscriber).await;
    let (_, second_update) = recv_update(&mut subscriber).await;
    assert!(matches!(
        first_update,
        InterfaceEndpointUpdate::Upsert { key: InterfaceEndpointKey::Agent(agent), .. }
        if agent == first_agent || agent == second_agent
    ));
    assert!(matches!(
        second_update,
        InterfaceEndpointUpdate::Upsert { key: InterfaceEndpointKey::Agent(agent), .. }
        if agent == first_agent || agent == second_agent
    ));

    drop(first);
    assert!(publishers.agent_endpoint_publisher(first_agent).is_ok());
}
