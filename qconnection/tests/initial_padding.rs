mod common;

use std::{future::poll_fn, io::IoSliceMut, sync::Arc, task::Context, time::Duration};

use bytes::BytesMut;
use common::opening::PacketOpen as _;
use qbase::{
    cid::ConnectionId,
    frame::{CryptoFrame, Frame, FrameReader},
    net::{
        addr::EndpointAddr,
        route::{Line, Link, Pathway},
    },
    packet::{DataHeader, GetType, LongHeaderBuilder, Packet, PacketContent, PacketReader, long},
};
use qconnection::{Scope, ServerRegistry, TlsContext};
use qprotocol::{QuicProtocol, UdpSocket};
use qrecovery::journal::ArcSentJournal;
use qtransport::{packet::CipherPacket, router::QuicRouter};

#[tokio::test]
async fn server_sends_server_hello_when_initial_padding_is_outside_the_packet() {
    common::quic_endpoint().listen(Scope::Loopback, |_| {}).unwrap();
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap(), common::loopback_ifindex()).unwrap());
    let client = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), common::loopback_ifindex()).unwrap();
    let local = EndpointAddr::direct(server.local_addr().unwrap());
    let remote = EndpointAddr::direct(client.local_addr().unwrap());
    QuicProtocol::global().register(local, &server).unwrap();

    let tls_client = common::anonymous_client();
    let (parameters, _) = common::parameters();
    let tls = TlsContext::client(&tls_client, "localhost".try_into().unwrap(), &parameters).unwrap();
    let (_, hello) = tls.read_msg().await.unwrap();
    let odcid = ConnectionId::from_slice(b"original");
    let scid = ConnectionId::from_slice(b"client00");
    let keys = tls_client.initial_keys(qtls::QuicVersion::V1, odcid.as_ref()).unwrap();
    let data = [hello];
    let mut crypto = (CryptoFrame::new(0u32.into(), (data[0].len() as u32).into()), data.as_slice());
    let mut bytes = BytesMut::zeroed(1200);
    let mut packet = qtransport::send::Packet::new(
        DataHeader::Long(LongHeaderBuilder::with_cid(odcid, scid).initial(vec![]).into()),
        ArcSentJournal::default().next_pn().unwrap(),
        &keys.sealing,
    );
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        packet.assemble(
            &mut cx,
            &mut std::io::Cursor::new(bytes.as_mut()),
            1200,
            PacketContent::EffectivePayload,
            &mut frames,
            &mut [&mut crypto],
        ),
        std::task::Poll::Ready((n, _)) if n > 0
    ));
    // Match aioquic: the UDP datagram is 1200 bytes, but the protected Initial
    // only occupies its prefix. The remaining datagram bytes still grant credit.
    assert!(packet.len() <= 600);
    packet.padding(&mut bytes, 600 - packet.len());
    packet.seal(&mut bytes[..600]);
    QuicRouter::global().receive(
        bytes,
        Pathway::new(local, remote),
        Link::new(server.local_addr().unwrap(), client.local_addr().unwrap()),
        8,
    );

    let mut received_bytes = 0;
    let hello = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut bytes = [0; 1500];
            let mut lines = [Line::default()];
            poll_fn(|cx| client.poll_recv(cx, &mut [IoSliceMut::new(&mut bytes)], &mut lines)).await.unwrap();
            let length = lines[0].seg_size as usize;
            received_bytes += length;
            assert!(received_bytes <= 3 * 1200, "server exceeded the datagram's amplification allowance");
            for packet in PacketReader::new(BytesMut::from(&bytes[..length]), 8) {
                let Ok(Packet::Data(packet)) = packet else {
                    continue;
                };
                let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
                    continue;
                };
                let opened = CipherPacket::new(header, packet.bytes, packet.offset, 0)
                    .open_long(&keys.opening, |pn| Ok(pn.decode(0)))
                    .unwrap()
                    .unwrap();
                for frame in FrameReader::new(opened.body(), opened.get_type()) {
                    if let Frame::Crypto(frame, bytes) = frame.unwrap().0 {
                        assert_eq!(frame.offset(), 0);
                        assert_eq!(bytes[0], 2, "first TLS message must be ServerHello");
                        return;
                    }
                }
            }
        }
    })
    .await;
    QuicProtocol::global().unregister(local, &server);
    ServerRegistry::global().remove("localhost");
    assert!(hello.is_ok(), "server must send ServerHello without waiting for another client datagram");
}
