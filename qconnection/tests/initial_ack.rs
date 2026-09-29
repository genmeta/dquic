mod common;

use std::{
    future::poll_fn,
    io::IoSliceMut,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    frame::{CryptoFrame, Frame, FrameReader},
    net::{
        addr::EndpointAddr,
        route::{Line, Link, Pathway},
    },
    packet::{DataHeader, GetDcid, LongHeaderBuilder, Packet, PacketReader, long},
    role::Role,
    time::ArcConnIdle,
};
use qconnection::{Scope, ServerRegistry, TlsContext};
use qprotocol::{QuicProtocol, UdpSocket};
use qrecovery::journal::ArcSentJournal;
use qtransport::{packet::CipherPacket, path::Path, router::QuicRouter};

#[tokio::test]
async fn server_sends_initial_ack_before_client_hello_is_complete() {
    let accepted = Arc::new(AtomicBool::new(false));
    let observed = accepted.clone();
    common::quic_endpoint()
        .listen(Scope::Loopback, move |_| {
            observed.store(true, Ordering::Relaxed);
        })
        .unwrap();
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let client_socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let client_addr = client_socket.local_addr().unwrap();
    let local = EndpointAddr::direct(server_addr);
    QuicProtocol::global()
        .register(local, &server_socket)
        .unwrap();

    let client = common::client_without_alpn();
    let (parameters, _) = common::parameters();
    let tls = TlsContext::client(&client, "localhost".try_into().unwrap(), &parameters).unwrap();
    let (_, hello) = tls.read_msg().await.unwrap();
    let odcid = ConnectionId::random_gen(8);
    let scid = ConnectionId::from_slice(b"client00");
    let keys = client
        .initial_keys(qtls::QuicVersion::V1, odcid.as_ref())
        .unwrap();
    let pathway = Pathway::new(EndpointAddr::direct(client_addr), local);
    let path = Path::new(
        pathway,
        Role::Client,
        ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO).timer(),
        Arc::default(),
    );
    path.client_handshaking();
    // Only the TLS handshake header: SNI and the rest of ClientHello are still missing.
    let data = [hello.slice(..4)];
    let mut crypto = (CryptoFrame::new(0u32.into(), 4u32.into()), data.as_slice());
    let packet = common::seal(
        LongHeaderBuilder::with_cid(odcid, scid).initial(vec![]),
        &keys.sealing,
        &ArcSentJournal::default(),
        [&mut crypto],
    )
    .unwrap();
    QuicRouter::global().receive(
        BytesMut::from(packet.as_ref()),
        Pathway::new(local, EndpointAddr::direct(client_addr)),
        Link::new(server_addr, client_addr),
        8,
    );

    let mut buffer = [0; 1500];
    let mut lines = [Line::default()];
    let count = tokio::time::timeout(
        Duration::from_secs(1),
        poll_fn(|cx| client_socket.poll_recv(cx, &mut [IoSliceMut::new(&mut buffer)], &mut lines)),
    )
    .await
    .expect("server must ACK an incomplete ClientHello")
    .unwrap();
    assert_eq!(count, 1);
    let Packet::Data(reply) =
        PacketReader::new(BytesMut::from(&buffer[..lines[0].seg_size as usize]), 8)
            .next()
            .unwrap()
            .unwrap()
    else {
        panic!("expected Initial")
    };
    assert_eq!(*reply.dcid(), scid);
    let DataHeader::Long(long::DataHeader::Initial(header)) = reply.header else {
        panic!("expected Initial")
    };
    let opened = CipherPacket::new(header, reply.bytes, reply.offset)
        .decrypt_long_packet(&keys.opening, |_| Ok(0))
        .unwrap()
        .unwrap();
    let mut acks = 0;
    for frame in FrameReader::new(
        opened.body(),
        qbase::packet::GetType::get_type(&LongHeaderBuilder::with_cid(odcid, scid).initial(vec![])),
    ) {
        match frame.unwrap().0 {
            Frame::Ack(ack) => {
                assert_eq!(ack.largest(), 0);
                acks += 1;
            }
            Frame::Padding(_) => {}
            _ => panic!("no TLS output is available yet"),
        }
    }
    assert_eq!(acks, 1);
    assert!(!accepted.load(Ordering::Relaxed));
    QuicProtocol::global().unregister(local, &server_socket);
    ServerRegistry::global().remove("localhost");
}
