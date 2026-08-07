use std::{
    io::{self, IoSlice},
    sync::{Arc, Mutex},
};

use qbase::net::{
    addr::EndpointAddr,
    route::{Link, Pathway},
};
use qprotocol::{
    AddressBook, Dock, UdpSocket,
    address::AddressBookError,
    ephemeral::EphemeralSocket,
    forward::ForwardProtocol,
    quic::{EndpointInUse, QuicProtocol, QuicSocket},
    stun::{Response, StunProtocol},
    topology::Topology,
};

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    AddressBook(#[from] AddressBookError),
    #[error(transparent)]
    EndpointInUse(#[from] EndpointInUse),
    #[error(transparent)]
    Promote(#[from] qprotocol::ephemeral::PromoteError),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let stun = Arc::new(StunProtocol::new());
    stun.on_request(|_, _| Some(Response::with(Vec::new())));

    let quic = Arc::new(QuicProtocol::new());
    let (delivered, received) = tokio::sync::oneshot::channel();
    let delivered = Arc::new(Mutex::new(Some(delivered)));
    quic.set_handler(move |packet, socket, pathway, link| {
        println!(
            "QUIC datagram: {} bytes, local={}, pathway={}, link={}",
            packet.len(),
            socket.endpoint_addr(),
            pathway,
            link,
        );
        // The future qconnection integration starts at this callback.
        if let Some(delivered) = delivered.lock().unwrap().take() {
            let _ = delivered.send(());
        }
    });

    let forward = Arc::new(ForwardProtocol::new(quic.clone()));
    let topology = Arc::new(Topology::new(stun.clone(), forward, quic.clone()));
    let dock = Dock::new(topology);
    let addresses = AddressBook::new();

    // This example uses a private bind, so its bound address is Direct(inner).
    let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap())?);
    dock.add(raw.clone())?;
    let inner = Arc::new(QuicSocket::new(
        raw.clone(),
        EndpointAddr::direct(raw.local_addr()?),
    ));
    quic.register(&inner)?;
    addresses.insert_inner(inner.clone())?;

    // A FullCone result would add Direct(outer), while retaining the same raw socket.
    let outer = Arc::new(QuicSocket::new(
        raw.clone(),
        EndpointAddr::direct("203.0.113.10:50000".parse().unwrap()),
    ));
    quic.register(&outer)?;
    addresses.insert_outer(outer.clone())?;

    // A successful STUN agent is published independently of the Direct endpoints.
    let agent = Arc::new(QuicSocket::new(
        raw.clone(),
        EndpointAddr::mediate(
            "198.51.100.1:3478".parse().unwrap(),
            "203.0.113.10:50000".parse().unwrap(),
        ),
    ));
    quic.register(&agent)?;
    addresses.insert_agent(agent.clone())?;

    // A second raw socket demonstrates the complete independent receive path.
    let peer_raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap())?);
    dock.add(peer_raw.clone())?;
    let peer = Arc::new(QuicSocket::new(
        peer_raw.clone(),
        EndpointAddr::direct(peer_raw.local_addr()?),
    ));
    quic.register(&peer)?;

    let direct_link = Link::new(raw.local_addr()?, peer_raw.local_addr()?);
    let packet = [0x40, 1, 2, 3];
    inner
        .send(&[IoSlice::new(&packet)], peer.endpoint_addr(), direct_link)
        .await?;
    received
        .await
        .map_err(|_| io::Error::other("QUIC example receive task stopped"))?;

    let direct_path = Pathway::new(inner.endpoint_addr(), peer.endpoint_addr());
    let remote_agent = EndpointAddr::mediate(
        "198.51.100.2:3478".parse().unwrap(),
        "192.0.2.20:50000".parse().unwrap(),
    );
    let mixed_path = Pathway::new(outer.endpoint_addr(), remote_agent);
    println!("Direct Path: {direct_path}");
    println!("Direct -> Agent Path: {mixed_path}");
    println!("mDNS: {:?}", addresses.mdns_endpoints(raw.local_addr()?));
    println!("DDNS: {:?}", addresses.ddns_endpoints());

    // Ephemeral sockets join the same Dock/Topology, but never enter AddressBook.
    let ephemeral = EphemeralSocket::bind(dock.clone(), "127.0.0.1:0".parse().unwrap())?;
    let ephemeral_bound = ephemeral.udp_socket().local_addr()?;
    let punched = ephemeral.into_quic_socket(EndpointAddr::direct(ephemeral_bound))?;
    quic.register(&punched)?;
    println!("punched Direct endpoint: {}", punched.endpoint_addr());

    quic.unregister(&punched);
    dock.remove(punched.udp_socket());
    quic.unregister(&peer);
    dock.remove(&peer_raw);
    dock.shutdown();
    Ok(())
}
