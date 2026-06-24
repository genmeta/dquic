use std::{io::Result, net::SocketAddr, sync::Arc};

use clap::Parser;
use qinterface::{
    component::local_endpoint::LocalEndpoints,
    io::{IO, ProductIO, handy::DEFAULT_IO_FACTORY},
};
use qtraversal::{
    nat::{client::StunClient, router::StunRouter},
    route::ReceiveAndDeliverPacket,
};
use tracing::info;
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(long, default_value = "0.0.0.0:12345")]
    pub bind: SocketAddr,
    #[arg(long, default_value = "nat.genmeta.net:20004")]
    pub stun_svr: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_logger().unwrap();
    let args = Arguments::parse();

    let stun_server = tokio::net::lookup_host(&args.stun_svr)
        .await?
        .find(|addr| addr.is_ipv4() == args.bind.is_ipv4())
        .ok_or_else(|| std::io::Error::other("failed to resolve stun server"))?;

    let bind_uri = format!("inet://{}", args.bind).into();
    let iface: Arc<dyn IO> = Arc::from(DEFAULT_IO_FACTORY.bind(bind_uri));

    let stun_router = StunRouter::new();
    let stun_client = StunClient::new(iface.clone(), stun_router.clone(), stun_server, None);

    let _task = ReceiveAndDeliverPacket::task()
        .stun_router(stun_router)
        .iface_ref(iface.clone())
        .spawn();

    let outer_addr = stun_client
        .outer_addr()
        .await
        .expect("failed to get outer addr");
    info!("outer addr: {} agent addr {}", outer_addr, stun_server);
    // Ok(())
    let nat_type = stun_client.nat_type().await;
    let local_endpoints = std::sync::Arc::new(LocalEndpoints::new());
    let mut subscriber = local_endpoints.subscribe();
    while let Some(event) = subscriber.recv().await {
        info!("local endpoint event: {:?}", event);
        info!("nat type: {:?}", nat_type);
    }
    Ok(())

    // unreachable!("Observer never return None")
}

fn init_logger() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    Ok(())
}
