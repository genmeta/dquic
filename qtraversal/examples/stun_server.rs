//! A standalone dquic STUN node with two listeners and optional QUIC forwarding.
//! See stun-server/README.md for the three-node deployment topology.
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use qprotocol::{
    Dock, ForwardProtocol, QuicProtocol, StunProtocol, UdpSocket, protocol::stun::ChangeServer,
    topology::Topology,
};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Serve dquic STUN on two UDP ports; optionally relay dquic packets"
)]
struct Options {
    /// Concrete IP assigned to this machine (not 0.0.0.0 or ::).
    #[arg(long)]
    bind_ip: IpAddr,
    /// Advertised public IP. Defaults to bind-ip; a NAT mapping must preserve both ports.
    #[arg(long)]
    public_ip: Option<IpAddr>,
    /// Public IP of the next STUN node, listening on the same two ports.
    #[arg(long)]
    change_ip: IpAddr,
    #[arg(long, default_value_t = 20002, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    #[arg(long, default_value_t = 20003, value_parser = clap::value_parser!(u16).range(1..))]
    alternate_port: u16,
    /// Enable dquic UDP forwarding on both listeners (needed for relayed handshakes).
    #[arg(long)]
    relay: bool,
}

impl Options {
    fn public_ip(&self) -> IpAddr {
        self.public_ip.unwrap_or(self.bind_ip)
    }

    fn validate(&self) -> io::Result<()> {
        let public = self.public_ip();
        let addresses = [self.bind_ip, public, self.change_ip];
        if addresses.iter().any(|ip| {
            ip.is_unspecified()
                || ip.is_multicast()
                || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bind-ip, public-ip and change-ip must be concrete unicast addresses",
            ));
        }
        if addresses
            .iter()
            .any(|ip| ip.is_ipv4() != self.bind_ip.is_ipv4())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "all addresses must use the same IP family",
            ));
        }
        if public == self.change_ip || self.bind_ip == self.change_ip {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "change-ip must belong to another STUN node",
            ));
        }
        if self.port == self.alternate_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "port and alternate-port must differ",
            ));
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let options = Options::parse();
    options.validate()?;
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // This server owns its topology; it never bootstraps the client's global DNS.
    let stun = Arc::new(StunProtocol::new());
    stun.disable_service();
    let forward = Arc::new(ForwardProtocol::new());
    let dock = Dock::new(Arc::new(Topology::new(
        stun.clone(),
        forward.clone(),
        Arc::new(QuicProtocol::new()),
    )));
    let ports = [options.port, options.alternate_port];
    // Bind both sockets before starting either receive task, so partial startup fails cleanly.
    let sockets =
        ports.map(|port| UdpSocket::bind(SocketAddr::new(options.bind_ip, port)).map(Arc::new));
    let [first, second] = sockets;
    let sockets = [first?, second?];
    for (index, socket) in sockets.iter().enumerate() {
        let bound = socket.local_addr()?;
        let outer = SocketAddr::new(options.public_ip(), ports[index]);
        let changed = SocketAddr::new(options.change_ip, ports[1 - index]);
        dock.add(socket.clone())?;
        stun.set_change_server(
            bound,
            ChangeServer {
                change_port: ports[1 - index],
                change_address: changed,
                outer_address: outer,
            },
        )?;
        if options.relay {
            // The receiving address selects the socket; the public alias selects
            // the agent when this node is behind a port-preserving NAT.
            forward.serve(bound, socket);
            if outer != bound {
                forward.serve(outer, socket);
            }
        }
        tracing::info!(%bound, %outer, %changed, relay = options.relay, "STUN listener configured");
    }
    stun.enable_service();
    tracing::info!("STUN server ready");

    let result = tokio::select! {
        result = shutdown_signal() => result,
        result = receive_health(&dock, &sockets) => result,
    };
    stun.disable_service();
    for (index, socket) in sockets.iter().enumerate() {
        forward.stop_serving(socket.local_addr()?);
        forward.stop_serving(SocketAddr::new(options.public_ip(), ports[index]));
    }
    dock.shutdown();
    result?;
    tracing::info!("STUN server stopped");
    Ok(())
}

async fn receive_health(dock: &Dock, sockets: &[Arc<UdpSocket>; 2]) -> io::Result<()> {
    let mut ticks = tokio::time::interval(Duration::from_secs(1));
    loop {
        ticks.tick().await;
        for socket in sockets {
            let bound = socket.local_addr()?;
            if dock.find_socket(bound).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("UDP receive task stopped for {bound}"),
                ));
            }
        }
    }
}

async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}
