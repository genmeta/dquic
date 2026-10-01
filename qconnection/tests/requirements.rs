mod common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    error::ErrorKind,
    frame::CryptoFrame,
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
    },
    packet::{DataHeader, LongHeaderBuilder, Packet, PacketReader, long},
    role::Role,
    time::ArcConnIdle,
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qconnection::{
    ArcConnPhase, CloseReason, ConnPhase, InitialPhase, Paths, Scope, ServerRegistry, TlsContext,
    server_growing,
};
use qprotocol::{QuicProtocol, UdpSocket};
use qrecovery::journal::ArcSentJournal;
use qtransport::{
    packet::{CipherPacket, channel},
    router::QuicRouter,
};
use tokio::sync::oneshot;

#[tokio::test(start_paused = true)]
async fn server_rejects_client_parameters_with_a_different_initial_scid() {
    let (accepted, acceptance) = oneshot::channel();
    let accepted = Mutex::new(Some(accepted));
    common::quic_endpoint()
        .listen(Scope::Loopback, move |result| {
            accepted.lock().unwrap().take().unwrap().send(result).ok();
        })
        .unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer_socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let link = Link::new(
        socket.local_addr().unwrap(),
        peer_socket.local_addr().unwrap(),
    );
    let pathway = Pathway::from(link);

    let client = common::client_without_alpn();
    let (client_parameters, _) = common::parameters();
    let tls =
        TlsContext::client(&client, "localhost".try_into().unwrap(), &client_parameters).unwrap();
    let (_, hello) = tls.read_msg().await.unwrap();
    let odcid = ConnectionId::from_slice(b"original");
    let client_keys = client
        .initial_keys(qtls::QuicVersion::V1, odcid.as_ref())
        .unwrap();
    let server_keys = ServerRegistry::global()
        .get("localhost")
        .unwrap()
        .tls_server
        .initial_keys(qtls::QuicVersion::V1, odcid.as_ref())
        .unwrap();
    let phase = ArcConnPhase::initial(InitialPhase::new(
        ConnectionId::from_slice(b"server00"),
        odcid,
        server_keys,
    ));
    let paths = Paths::new(
        Role::Server,
        phase.clone(),
        ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO),
    );
    paths.add_path(pathway).unwrap();
    let router = Arc::new(QuicRouter::new());
    let (inbox, received) = channel::new();
    let route = router.insert(odcid.into(), inbox.clone());

    let data = [hello];
    let mut crypto = (
        CryptoFrame::new(0u32.into(), (data[0].len() as u32).into()),
        data.as_slice(),
    );
    let packet = common::seal(
        LongHeaderBuilder::with_cid(odcid, ConnectionId::from_slice(b"wrongcid")).initial(vec![]),
        &client_keys.sealing,
        &ArcSentJournal::default(),
        [&mut crypto],
    )
    .unwrap();
    let Packet::Data(packet) = PacketReader::new(BytesMut::from(packet.as_ref()), 8)
        .next()
        .unwrap()
        .unwrap()
    else {
        panic!("expected Initial packet");
    };
    let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
        panic!("expected Initial header");
    };
    assert!(inbox.try_send_initial(
        CipherPacket::new(header, packet.bytes, packet.offset),
        pathway,
        link
    ));
    let tick = qconnection::recv::tick(paths.clone());
    let growing = server_growing(
        route,
        received,
        paths.clone(),
        ArcTokenRegistry::with_provider(Arc::new(NoopTokenRegistry)),
    );
    let growing = tokio::spawn(async move { tokio::join!(growing, tick).0 });
    let result = tokio::time::timeout(Duration::from_secs(1), acceptance)
        .await
        .unwrap()
        .unwrap();
    let error = result
        .err()
        .expect("growing must reject a CID different from the Initial header");
    assert_eq!(error.kind(), ErrorKind::TransportParameter);
    assert!(
        matches!(growing.await.unwrap(), CloseReason::Internal(error) if error.kind() == ErrorKind::TransportParameter)
    );
    assert!(matches!(phase.get(), ConnPhase::Initial(_)));
    assert!(paths.snapshot().is_empty());
    QuicProtocol::global().unregister(local, &socket);
    ServerRegistry::global().remove("localhost");
}
