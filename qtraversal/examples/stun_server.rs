use std::{io::Result, net::SocketAddr, sync::Arc};

use clap::Parser;
use qinterface::io::{IO, ProductIO, handy::DEFAULT_IO_FACTORY};
use qtraversal::{
    nat::{
        router::StunRouter,
        server::{StunServer, StunServerConfig},
    },
    route::{Forwarder, ReceiveAndDeliverPacket},
};
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(long, default_value = "127.0.0.1:20002")]
    pub bind_addr1: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:20003")]
    pub bind_addr2: SocketAddr,
    /// Public alternate listener on another node for requests received on bind-addr1.
    #[arg(long)]
    pub change_addr1: SocketAddr,
    /// Public primary listener on another node for requests received on bind-addr2.
    #[arg(long)]
    pub change_addr2: SocketAddr,
    /// Public address corresponding to bind-addr1.
    #[arg(long)]
    pub outer_addr1: SocketAddr,
    /// Public address corresponding to bind-addr2.
    #[arg(long)]
    pub outer_addr2: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Arguments::parse();
    validate_args(&args)?;
    init_logger();

    let factory: Arc<dyn ProductIO> = Arc::new(DEFAULT_IO_FACTORY);

    let bind_uri1 = format!("inet://{}", args.bind_addr1).into();
    let iface1: Arc<dyn IO> = Arc::from(factory.bind(bind_uri1));
    let stun_router1 = StunRouter::new();
    let _iface1_recv_task = ReceiveAndDeliverPacket::task()
        .stun_router(stun_router1.clone())
        .forwarder(Forwarder::Server {
            outer_addr: args.outer_addr1,
        })
        .iface_ref(iface1.clone())
        .spawn();

    let bind_uri2 = format!("inet://{}", args.bind_addr2).into();
    let iface2: Arc<dyn IO> = Arc::from(factory.bind(bind_uri2));
    let stun_router2 = StunRouter::new();
    let _iface2_recv_task = ReceiveAndDeliverPacket::task()
        .stun_router(stun_router2.clone())
        .forwarder(Forwarder::Server {
            outer_addr: args.outer_addr2,
        })
        .iface_ref(iface2.clone())
        .spawn();

    let server1 = StunServer::new(
        iface1,
        stun_router1,
        StunServerConfig::builder()
            .change_port(args.bind_addr2.port())
            .change_address(args.change_addr1)
            .outer_address(args.outer_addr1)
            .init(),
    );
    let server2 = StunServer::new(
        iface2,
        stun_router2,
        StunServerConfig::builder()
            .change_port(args.bind_addr1.port())
            .change_address(args.change_addr2)
            .outer_address(args.outer_addr2)
            .init(),
    );
    _ = tokio::try_join!(server1.spawn(), server2.spawn())?;
    Ok(())
}

fn validate_args(args: &Arguments) -> Result<()> {
    let addresses = [
        args.bind_addr1,
        args.bind_addr2,
        args.change_addr1,
        args.change_addr2,
        args.outer_addr1,
        args.outer_addr2,
    ];
    if addresses
        .iter()
        .any(|addr| addr.is_ipv4() != args.bind_addr1.is_ipv4())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "all STUN addresses must use the same address family",
        ));
    }
    if args.bind_addr1.ip() != args.bind_addr2.ip() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bind-addr1 and bind-addr2 must use the same local IP",
        ));
    }
    if args.outer_addr1.ip() != args.outer_addr2.ip() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "outer-addr1 and outer-addr2 must use the same public IP",
        ));
    }
    if args.bind_addr1.port() == args.bind_addr2.port() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the primary and alternate STUN ports must differ",
        ));
    }
    if args.outer_addr1.port() != args.bind_addr1.port()
        || args.outer_addr2.port() != args.bind_addr2.port()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "each outer address port must match its bind address port",
        ));
    }
    if args.change_addr1.port() != args.outer_addr2.port()
        || args.change_addr2.port() != args.outer_addr1.port()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "change-addr1 must use the alternate port and change-addr2 the primary port",
        ));
    }
    if args.change_addr1.ip() == args.outer_addr1.ip()
        || args.change_addr2.ip() == args.outer_addr2.ip()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "each change address must use a different public IP",
        ));
    }
    Ok(())
}

fn init_logger() {
    let _ = tracing_subscriber::fmt()
        .with_target(true)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args() -> Arguments {
        Arguments {
            bind_addr1: "10.0.0.1:20002".parse().unwrap(),
            bind_addr2: "10.0.0.1:20003".parse().unwrap(),
            change_addr1: "198.51.100.2:20003".parse().unwrap(),
            change_addr2: "198.51.100.2:20002".parse().unwrap(),
            outer_addr1: "198.51.100.1:20002".parse().unwrap(),
            outer_addr2: "198.51.100.1:20003".parse().unwrap(),
        }
    }

    #[test]
    fn production_pair_is_valid() {
        validate_args(&valid_args()).unwrap();
    }

    #[test]
    fn shared_change_address_cannot_preserve_both_port_relationships() {
        let mut args = valid_args();
        args.change_addr2 = args.change_addr1;
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn change_address_must_change_public_ip() {
        let mut args = valid_args();
        args.change_addr1 = "198.51.100.1:20003".parse().unwrap();
        assert!(validate_args(&args).is_err());
    }
}
