use std::{
    io::{self, IoSlice},
    sync::{Arc, Mutex},
};

use qbase::net::{addr::EndpointAddr, route::Pathway};
use qprotocol::{
    AddressBook, BindUri, Dock, UdpSocket,
    addr_book::AddressBookError,
    protocol::{
        forward::ForwardProtocol,
        quic::{EndpointInUse, QuicProtocol},
        stun::StunProtocol,
    },
    socket::ephemeral::EphemeralSocket,
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
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let stun = Arc::new(StunProtocol::new());

    let quic = Arc::new(QuicProtocol::new());
    let (delivered, received) = tokio::sync::oneshot::channel();
    let delivered = Arc::new(Mutex::new(Some(delivered)));
    quic.on_receive(move |packet, pathway, link| {
        println!(
            "QUIC datagram: {} bytes, local={}, pathway={}, link={}",
            packet.len(),
            pathway.local(),
            pathway,
            link,
        );
        // The future qconnection integration starts at this callback.
        if let Some(delivered) = delivered.lock().unwrap().take() {
            let _ = delivered.send(());
        }
    });

    let forward = Arc::new(ForwardProtocol::new());
    let topology = Arc::new(Topology::new(stun.clone(), forward.clone(), quic.clone()));
    let dock = Dock::new(topology);
    let addresses = AddressBook::new();

    // This example uses a private bind, so its bound address is Direct(inner).
    let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap())?);
    dock.add(raw.clone())?;
    let bound = raw.local_addr()?;
    let inner = EndpointAddr::direct(bound);
    quic.register(inner, &raw)?;
    addresses.insert_inner(bound, inner)?;
    forward.serve(inner.addr(), &raw);

    // A FullCone result would add Direct(outer), while retaining the same raw socket.
    let outer = EndpointAddr::direct("203.0.113.10:50000".parse().unwrap());
    quic.register(outer, &raw)?;
    addresses.insert_outer(bound, outer)?;
    forward.serve(outer.addr(), &raw);

    // A successful STUN agent is published independently of the Direct endpoints.
    let agent = EndpointAddr::mediate(
        "198.51.100.1:3478".parse().unwrap(),
        "203.0.113.10:50000".parse().unwrap(),
    );
    quic.register(agent, &raw)?;
    addresses.insert_agent(bound, agent)?;

    // A second raw socket demonstrates the complete independent receive path.
    let peer_raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap())?);
    dock.add(peer_raw.clone())?;
    let peer = EndpointAddr::direct(peer_raw.local_addr()?);
    quic.register(peer, &peer_raw)?;

    let packet = [0x40, 1, 2, 3];
    quic.send(Pathway::new(inner, peer), &[IoSlice::new(&packet)])
        .await?;
    received
        .await
        .map_err(|_| io::Error::other("QUIC example receive task stopped"))?;

    let direct_path = Pathway::new(inner, peer);
    let remote_agent = EndpointAddr::mediate(
        "198.51.100.2:3478".parse().unwrap(),
        "192.0.2.20:50000".parse().unwrap(),
    );
    let mixed_path = Pathway::new(outer, remote_agent);
    println!("Direct Path: {direct_path}");
    println!("Direct -> Agent Path: {mixed_path}");
    println!("mDNS: {:?}", addresses.mdns_endpoints(raw.local_addr()?));
    println!("DDNS: {:?}", addresses.ddns_endpoints());

    // Ephemeral sockets join the same Dock/Topology, but never enter AddressBook.
    let ephemeral = EphemeralSocket::bind(
        dock.clone(),
        BindUri::from("127.0.0.1:0").resolve_binding()?,
    )?;
    let ephemeral_bound = ephemeral.udp_socket().local_addr()?;
    let punched_endpoint = EndpointAddr::direct(ephemeral_bound);
    let punched = ephemeral;
    println!("punched Direct endpoint: {punched_endpoint}");

    drop(punched);
    quic.unregister(peer, &peer_raw);
    dock.remove(&peer_raw);
    dock.shutdown();
    Ok(())
}
