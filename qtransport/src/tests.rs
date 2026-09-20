use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::FutureExt;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{AppError, ErrorKind, QuicError},
    flow::FlowController,
    frame::{AckFrame, Frame, MaxStreamsFrame, PingFrame, StreamCtlFrame, io::ReceiveFrame},
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
        tx::ArcSendWakers,
    },
    packet::{DataPacket, OneRttHeader, Packet, PacketNumber, PacketReader},
    param::{
        ParameterId,
        handy::{client_parameters, server_parameters},
    },
    sid::{Dir, handy::DemandConcurrency},
    time::{ArcConnIdle, PathIdleTimer},
};
use qcongestion::{Feedback, HandshakeStatus};
use qrecovery::streams::DataStreams;
use tls_backend::pki_types::pem::PemObject;

use crate::{
    keys::{ArcOneRttKeys, KeyRetired, OneRttKeys, OpenPacket, SealPacket},
    packet::channel,
    path::Path,
    recv::{receive_packet, run_receive},
    send::{
        constraints::Constraints,
        write::{Packet as SendingPacket, PacketError, PacketWriter},
    },
    space::Space,
    transport::Transport,
    *,
};

fn packet_way() -> (Pathway, Link) {
    let link = Link::new(
        "127.0.0.1:4433".parse().unwrap(),
        "127.0.0.1:9000".parse().unwrap(),
    );
    (link.into(), link)
}

fn enqueue(inbox: &channel::Inbox, packet: Packet) -> bool {
    let (pathway, link) = packet_way();
    inbox.try_send(packet, pathway, link)
}

pub(crate) mod sender;
pub(crate) use sender::Sender;

const CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
const OCSP: &[u8] = include_bytes!("../../tests/keychain/localhost/server.ocsp");

fn tls_server(provider: Arc<qtls::CryptoProvider>, alpn: Vec<Vec<u8>>) -> qtls::TlsServer {
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
    let local = qtls::LocalAuthority::new(
        &provider,
        "localhost".into(),
        vec![qtls::CertificateDer::from_pem_slice(CERT).unwrap()],
        qtls::PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        OCSP.to_vec(),
    )
    .unwrap();
    qtls::TlsServer::new(qtls::ServerTlsConfig {
        provider,
        alpn,
        local,
        resumption: qtls::ServerResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap()
}

pub(crate) fn handshake() -> ([qtls::OneRttKeyMaterial; 2], [qtls::HandshakeSummary; 2]) {
    let provider = Arc::new(qtls::default_provider());
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
    let client = qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec(), b"ssh".to_vec()],
        local: None,
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let server = tls_server(provider, vec![b"ssh".to_vec(), b"h3".to_vec()]);
    let mut peers = [
        client
            .start(qtls::ClientStart {
                server_name: "localhost".try_into().unwrap(),
                quic_version: qtls::QuicVersion::V1,
                local_transport_parameters: Bytes::new(),
            })
            .unwrap(),
        server.start(qtls::QuicVersion::V1, Bytes::new()).unwrap(),
    ];
    let mut keys = [None, None];
    let mut summaries = [None, None];
    for _ in 0..16 {
        for i in 0..2 {
            while let Some(event) = peers[i].next_event() {
                match event {
                    qtls::TlsEvent::WriteCrypto { level, bytes } => {
                        peers[1 - i].receive_crypto(level, &bytes).unwrap()
                    }
                    qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(key)) => {
                        keys[i] = Some(key)
                    }
                    qtls::TlsEvent::HandshakeComplete(summary) => summaries[i] = Some(summary),
                    _ => {}
                }
            }
        }
        if summaries.iter().all(Option::is_some) {
            break;
        }
    }
    (keys.map(Option::unwrap), summaries.map(Option::unwrap))
}

fn transport(role: Role, keys: qtls::OneRttKeyMaterial, limits: u32) -> Arc<Transport> {
    let mut client = client_parameters();
    let mut server = server_parameters();
    client
        .set(ParameterId::InitialMaxStreamsBidi, limits)
        .unwrap();
    client
        .set(ParameterId::InitialMaxStreamsUni, limits)
        .unwrap();
    server
        .set(ParameterId::InitialMaxStreamsBidi, limits)
        .unwrap();
    server
        .set(ParameterId::InitialMaxStreamsUni, limits)
        .unwrap();
    let params = ArcParameters::new(role, Arc::new(client), Arc::new(server));
    let wakers = ArcSendWakers::default();
    let reliable = ReliableFrames::with_capacity_and_wakers(0, wakers.clone());
    let streams = match role {
        Role::Client => DataStreams::new(
            role,
            params.client(),
            params.server(),
            Box::new(DemandConcurrency),
            reliable.clone(),
            wakers.clone(),
            None,
        ),
        Role::Server => DataStreams::new(
            role,
            params.server(),
            params.client(),
            Box::new(DemandConcurrency),
            reliable.clone(),
            wakers.clone(),
            None,
        ),
    };
    let data = Arc::new(Space::<ArcOneRttKeys>::new(Epoch::Data, wakers.clone(), {
        let streams = streams.clone();
        let reliable = reliable.clone();
        move |frame| match frame {
            GuaranteedFrame::Stream(frame) => streams.may_loss_data(frame),
            GuaranteedFrame::Reliable(frame) => {
                use qbase::frame::io::SendFrame;
                reliable.send_frame([frame.clone()]);
            }
            GuaranteedFrame::Crypto(_) => unreachable!("Space recovers CRYPTO internally"),
        }
    }));
    data.install_1rtt_keys(qtls::InstalledKeys::OneRtt(keys))
        .unwrap();
    data.keys
        .clone()
        .now_or_never()
        .unwrap()
        .unwrap()
        .allow_update();
    let flow = FlowController::new(
        params.remote(ParameterId::InitialMaxData).unwrap(),
        params.local(ParameterId::InitialMaxData).unwrap(),
        reliable.clone(),
        wakers,
    );
    Arc::new(Transport::new(data, params, streams, flow, reliable))
}
pub(crate) fn pair(limits: u32) -> [(ArcConnection, Arc<Transport>, Arc<Path>); 2] {
    let (keys, summaries) = handshake();
    let [client, server] = keys;
    [
        transport(Role::Client, client, limits),
        transport(Role::Server, server, limits),
    ]
    .into_iter()
    .zip(summaries)
    .map(|(transport, summary)| {
        let path = path(&transport, 0);
        let conn = ArcConnection::new(transport.clone(), summary.alpn.unwrap(), Default::default());
        (conn, transport, path)
    })
    .collect::<Vec<_>>()
    .try_into()
    .ok()
    .unwrap()
}
pub(crate) fn keys(transport: &Transport) -> OneRttKeys {
    transport.data.keys.clone().now_or_never().unwrap().unwrap()
}

fn path(transport: &Arc<Transport>, index: u16) -> Arc<Path> {
    let (local, remote) = if transport.parameters.role() == Role::Client {
        (4400 + index, 5500 + index)
    } else {
        (5500 + index, 4400 + index)
    };
    let pathway = Pathway::new(
        EndpointAddr::direct(([127, 0, 0, 1], local).into()),
        EndpointAddr::direct(([127, 0, 0, 1], remote).into()),
    );
    let status = Arc::new(HandshakeStatus::new(
        transport.parameters.role() == Role::Server,
    ));
    status.handshake_confirmed();
    let feedback: Arc<dyn Feedback> = Arc::new(crate::space::ArcFeedback::from(
        transport.data.send_journal.clone(),
    ));
    let path = Arc::new(Path::new(
        pathway,
        ConnectionId::from_slice(b"original"),
        status,
        Duration::from_millis(25),
        path_idle(),
        [feedback.clone(), feedback.clone(), feedback],
    ));
    path.validate();
    path
}

fn path_idle() -> PathIdleTimer {
    ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO).timer()
}
fn parse(bytes: &[u8]) -> DataPacket {
    let Packet::Data(packet) = PacketReader::new(BytesMut::from(bytes), 8)
        .next()
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    packet
}
fn emit(sender: &mut Sender) -> BytesMut {
    assert!(sender.prepare().unwrap(), "sender has work");
    let mut wire = BytesMut::new();
    let result = sender.poll_send_with(
        &mut Context::from_waker(futures::task::noop_waker_ref()),
        |_, _, bytes| {
            wire.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        },
    );
    assert!(matches!(result, Poll::Ready(Ok(true))));
    wire
}
fn dispatch(transport: &Transport, path: &Arc<Path>, frame: Frame<Bytes>) -> Result<(), Error> {
    use qbase::frame::GetFrameType;
    let kind = frame.frame_type();
    match frame {
        Frame::Stream(frame, bytes) => {
            let fresh = transport.streams.recv_frame((frame, bytes))?;
            transport.flow.recver.on_new_rcvd(kind, fresh)?;
        }
        Frame::StreamCtl(frame) => {
            let fresh = transport.streams.recv_frame(frame)?;
            transport.flow.recver.on_new_rcvd(kind, fresh)?;
        }
        Frame::Ack(frame) => acknowledge(transport, &frame, path)?,
        Frame::MaxData(frame) => transport.flow.sender.recv_frame(frame)?,
        Frame::DataBlocked(frame) => transport.flow.recver.recv_frame(frame)?,
        Frame::PathChallenge(frame) => path.recv_frame(frame)?,
        Frame::PathResponse(frame) => path.recv_frame(frame)?,
        Frame::Crypto(frame, bytes) => transport
            .data
            .crypto
            .incoming()
            .recv_frame((frame, bytes))?,
        Frame::Close(frame) => transport.close(frame.into()),
        Frame::Padding(_) | Frame::Ping(_) => {}
        _ => {
            return Err(QuicError::with_default_fty(
                ErrorKind::ProtocolViolation,
                "unexpected test frame",
            )
            .into());
        }
    }
    Ok(())
}
fn receive(transport: &Arc<Transport>, path: &Arc<Path>, bytes: &[u8]) -> Option<u64> {
    let (pn, frames) = transport
        .data
        .keys
        .clone()
        .now_or_never()
        .unwrap()
        .unwrap()
        .open(
            parse(bytes),
            |pn| transport.data.rcvd_journal.decode_pn(pn),
            Duration::from_secs(1),
        )
        .unwrap()?;
    receive_packet(
        pn,
        frames,
        &transport.data,
        path,
        &AtomicBool::new(false),
        |_, frame, path| dispatch(transport, path, frame),
        |_, _| Ok(()),
    )
    .unwrap();
    Some(pn)
}
fn acknowledge(transport: &Transport, ack: &AckFrame, path: &Arc<Path>) -> Result<(), Error> {
    let keys = keys(transport);
    send::acknowledge(
        &transport.data,
        &transport.streams,
        &transport.parameters,
        ack,
        path,
        |generation| keys.on_ack(generation),
    )
}
fn ack(pn: u64) -> AckFrame {
    AckFrame::new(
        VarInt::from_u64(pn).unwrap(),
        0u32.into(),
        0u32.into(),
        vec![],
        None,
    )
}
pub(crate) fn seal_packet(
    packet: SendingPacket,
    keys: &OneRttKeys,
    journal: &send::records::ArcSendJournal,
    records: &mut Vec<GuaranteedFrame>,
) -> Result<send::write::PendingPacket, PacketError> {
    let ((pn, encoded), key) =
        keys.reserve(|generation| journal.record_pending(generation, records))?;
    send::finish_sealing(packet.seal(&key, pn, encoded), pn, journal, records)
}

fn ping(keys: &OneRttKeys, pn: u64) -> BytesMut {
    let mut recorded = Vec::new();
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    packet
        .assemble(
            &Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            &mut recorded,
            [&mut PingFrame],
        )
        .unwrap();
    seal_packet(
        packet,
        keys,
        &send::records::ArcSendJournal::starting_at(pn),
        &mut recorded,
    )
    .unwrap()
    .into_buffer()
}

#[test]
fn short_packet_numbers_round_trip_with_header_protection_padding() {
    let ([client, server], _) = handshake();
    let client = transport(Role::Client, client, 1);
    let server = transport(Role::Server, server, 1);
    for pn in [0, 1 << 15, 1 << 23] {
        let bytes = ping(&keys(&client), pn);
        let packet = parse(&bytes);
        assert!(bytes.len() >= packet.offset + 20);
        let (decoded, frames) = keys(&server)
            .open(
                packet,
                |encoded| {
                    assert_eq!(encoded, PacketNumber::encode(pn, 0));
                    Ok(pn)
                },
                Duration::from_secs(1),
            )
            .unwrap()
            .unwrap();
        assert_eq!(decoded, pn);
        assert!(matches!(
            frames.into_iter().next().unwrap().unwrap().0,
            Frame::Ping(_)
        ));
    }
}

#[test]
fn header_protection_padding_obeys_every_packet_limit() {
    use qbase::packet::HeaderSize;
    let header = OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original"));
    let minimum = header.size() + 22; // Four-byte reservation plus padding for a two-byte PN.
    for limited in 0..3 {
        let mut recorded = Vec::new();
        let mut packet = SendingPacket::new(BytesMut::zeroed(minimum), header, 16).unwrap();
        let mut constraints = Constraints {
            capacity: minimum,
            congestion: minimum,
            anti_amplification: minimum,
        };
        match limited {
            0 => constraints.capacity -= 1,
            1 => constraints.congestion -= 1,
            _ => constraints.anti_amplification -= 1,
        }
        assert!(
            packet
                .assemble(&constraints, &mut recorded, [&mut PingFrame])
                .is_err()
        );
        constraints.capacity = minimum;
        constraints.congestion = minimum;
        constraints.anti_amplification = minimum;
        packet
            .assemble(&constraints, &mut recorded, [&mut PingFrame])
            .unwrap();
    }
}

// Router tests only inspect headers; payload authentication belongs to the receive engine.
fn initial_datagram(cid: ConnectionId, size: usize) -> BytesMut {
    use qbase::{
        packet::{LongHeaderBuilder, header::io::WriteHeader},
        varint::WriteVarInt,
    };
    let header =
        LongHeaderBuilder::with_cid(cid, ConnectionId::from_slice(b"clientid")).initial(vec![]);
    let mut bytes = BytesMut::new();
    bytes.put_header(&header);
    bytes.put_varint(&VarInt::from_u32((size - bytes.len() - 2) as u32));
    bytes.resize(size, 0);
    bytes
}

fn close_packet(keys: &OneRttKeys, pn: u64) -> BytesMut {
    let mut recorded = Vec::new();
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    let mut close = qbase::frame::ConnectionCloseFrame::from(Error::from(AppError::new(
        VarInt::from_u32(7),
        "peer closed",
    )));
    packet
        .assemble(
            &Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            &mut recorded,
            [&mut PingFrame, &mut close],
        )
        .unwrap();
    seal_packet(
        packet,
        keys,
        &send::records::ArcSendJournal::starting_at(pn),
        &mut recorded,
    )
    .unwrap()
    .into_buffer()
}

#[tokio::test]
async fn long_header_receive_uses_each_spaces_keys_and_journal() {
    use qbase::{
        packet::{LongHeaderBuilder, header::io::WriteHeader},
        varint::WriteVarInt,
    };

    use crate::keys::ArcKeys;
    let [(_client, _, _), (_server, _st, path)] = pair(1);
    let cid = ConnectionId::from_slice(b"original");
    let endpoint = tls_server(Arc::new(qtls::default_provider()), vec![b"h3".to_vec()]);
    for (epoch, pn_len) in [Epoch::Initial, Epoch::Handshake]
        .into_iter()
        .flat_map(|epoch| (1..=4).map(move |pn_len| (epoch, pn_len)))
    {
        // Exercise both long-header layouts with deterministic qtls material;
        // TLS's selection of Handshake secrets is tested in qtls itself.
        let material = endpoint.initial_keys(qtls::QuicVersion::V1, &cid).unwrap();
        let mut bytes = if epoch == Epoch::Initial {
            initial_datagram(cid, 1200)
        } else {
            let mut bytes = BytesMut::new();
            bytes.put_header(&LongHeaderBuilder::with_cid(cid, cid).handshake());
            bytes.put_varint(&VarInt::from_u32((1200 - bytes.len() - 2) as u32));
            bytes.resize(1200, 0);
            bytes
        };
        let offset = parse(&bytes).offset;
        bytes[0] |= *qbase::packet::LongSpecificBits::with_pn_len(pn_len);
        bytes[offset + pn_len..offset + pn_len + 4].copy_from_slice(&[0x06, 0, 1, 0xaa]);
        material
            .opening
            .seal(
                0,
                &mut bytes,
                offset,
                offset + pn_len,
                material.opening.packet.tag_len(),
            )
            .unwrap();
        let space = Arc::new(Space::<ArcKeys>::new(epoch, Default::default(), |_| {}));
        space.install_initial_keys(material).unwrap();
        let ready = space.keys.clone().await.unwrap();
        assert!(Arc::ptr_eq(&space.keys.clone().await.unwrap(), &ready));
        let (inbox, rcvd_pkt) = channel::new();
        assert!(enqueue(&inbox, Packet::Data(parse(&bytes))));
        assert!(enqueue(&inbox, Packet::Data(parse(&bytes))));
        drop(inbox);
        let delivered = Arc::new(AtomicUsize::new(0));
        let dispatch = {
            let delivered = delivered.clone();
            move |_: &Arc<qtls::BidirectionalKeys>,
                  received_epoch,
                  frame: Frame<Bytes>,
                  _: &Arc<Path>| {
                assert_eq!(received_epoch, epoch);
                let Frame::Crypto(_, body) = frame else {
                    panic!("unexpected frame")
                };
                assert_eq!(body.as_ref(), &[0xaa]);
                delivered.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        };
        if epoch == Epoch::Initial {
            let received_path = path.clone();
            run_receive(
                rcvd_pkt.initial,
                space.clone(),
                move |_, _| Some(received_path.clone()),
                |keys: &Arc<qtls::BidirectionalKeys>, packet, _| {
                    packet
                        .decrypt_long_packet(&keys.opening, |pn| space.rcvd_journal.decode_pn(pn))
                        .transpose()
                        .map_err(Into::into)
                },
                Arc::default(),
                dispatch,
                |_, _| Ok(()),
                |_| panic!("receive failed"),
            )
            .await;
        } else {
            let received_path = path.clone();
            run_receive(
                rcvd_pkt.handshake,
                space.clone(),
                move |_, _| Some(received_path.clone()),
                |keys: &Arc<qtls::BidirectionalKeys>, packet, _| {
                    packet
                        .decrypt_long_packet(&keys.opening, |pn| space.rcvd_journal.decode_pn(pn))
                        .transpose()
                        .map_err(Into::into)
                },
                Arc::default(),
                dispatch,
                |_, _| Ok(()),
                |_| panic!("receive failed"),
            )
            .await;
        }
        assert_eq!(delivered.load(Ordering::Relaxed), 1);
        assert!(
            space
                .rcvd_journal
                .decode_pn(PacketNumber::encode(0, 0))
                .is_err()
        );
        space.retire();
        assert!(matches!(space.keys.clone().await, Err(KeyRetired)));
    }
}

#[tokio::test]
async fn router_splits_coalesced_packets_and_does_not_block_on_full_queues() {
    use crate::router::QuicRouter;
    let router = Arc::new(QuicRouter::new());
    let (inbox, mut rcvd_pkt) = channel::new();
    let link = Link::new(
        "127.0.0.1:4433".parse().unwrap(),
        "127.0.0.1:9000".parse().unwrap(),
    );
    let cid = ConnectionId::from_slice(b"original");
    let alias = ConnectionId::from_slice(b"newalias");
    let original = router.insert(cid.into(), inbox.clone());
    let alias_route = router.insert(alias.into(), inbox.clone());
    let mut datagram = initial_datagram(cid, 600);
    datagram.extend_from_slice(&initial_datagram(alias, 600));
    router.receive(datagram, link.into(), link, 8);
    assert_eq!(rcvd_pkt.initial.recv().await.unwrap().0.payload_len(), 600);
    assert_eq!(rcvd_pkt.initial.recv().await.unwrap().0.payload_len(), 600);
    for _ in 0..32 {
        router.receive(initial_datagram(alias, 1200), link.into(), link, 8);
    }
    let mut received = 0;
    while rcvd_pkt.initial.try_recv().is_ok() {
        received += 1;
    }
    assert_eq!(received, 8);
    drop(original);
    drop(alias_route);
    drop(inbox);
    assert!(rcvd_pkt.initial.recv().await.is_none());
}

#[tokio::test]
async fn router_and_receive_topology_deliver_streams_while_other_spaces_wait_and_keep_close_receiving()
 {
    use qbase::{
        ArcReceiving,
        frame::{NewConnectionIdFrame, NewTokenFrame, RetireConnectionIdFrame},
        net::route::Link,
    };
    use tokio::io::AsyncReadExt;

    use crate::{keys::ArcKeys, router::QuicRouter};
    let [(client, ct, cp), (_old_server, st, sp)] = pair(2);
    let closing = Arc::new(AtomicBool::new(false));
    let close = ArcReceiving::default();
    let server = ArcConnection::new(st.clone(), Bytes::from_static(b"h3"), close.clone());
    let initial = Arc::new(Space::<ArcKeys>::new(
        Epoch::Initial,
        Default::default(),
        |_| {},
    ));
    let handshake = Arc::new(Space::<ArcKeys>::new(
        Epoch::Handshake,
        Default::default(),
        |_| {},
    ));
    let close_seen = qbase::ArcReceiving::default();
    let close_sink = close_seen.clone();
    let dispatch = recv::frame_dispatcher(
        st.data.clone(),
        st.parameters.clone(),
        st.streams.clone(),
        st.flow.clone(),
        [
            initial.crypto.clone(),
            handshake.crypto.clone(),
            st.data.crypto.clone(),
        ],
        ArcReceiving::<RetireConnectionIdFrame>::default(),
        ArcReceiving::<NewConnectionIdFrame>::default(),
        ArcReceiving::<NewTokenFrame>::default(),
        closing.clone(),
        move |_, frame, _| close_sink.recv_frame(frame),
        |_, _, _| panic!("unexpected frame"),
    );
    let streams_seen = Arc::new(AtomicUsize::new(0));
    let seen = streams_seen.clone();
    let router = Arc::new(QuicRouter::new());
    let (inbox, rcvd_pkt) = channel::new();
    let link = Link::new(
        "127.0.0.1:5500".parse().unwrap(),
        "127.0.0.1:4400".parse().unwrap(),
    );
    let cid = ConnectionId::from_slice(b"original");
    let route = router.insert(cid.into(), inbox.clone());
    router.receive(initial_datagram(cid, 1200), link.into(), link, 8);
    // This handshake packet also waits for keys; neither wait may block Data.
    let mut packet = parse(&initial_datagram(cid, 1200));
    packet.header = qbase::packet::DataHeader::Long(qbase::packet::long::DataHeader::Handshake(
        qbase::packet::LongHeaderBuilder::with_cid(cid, cid).handshake(),
    ));
    router.deliver(Packet::Data(packet), link.into(), link);
    let task = tokio::spawn(recv::run(
        rcvd_pkt,
        initial.clone(),
        handshake.clone(),
        st.data.clone(),
        closing.clone(),
        move |_, _| Some(sp.clone()),
        move |epoch, frame, path, on_ack| {
            if matches!(frame, Frame::Stream(_, _)) {
                seen.fetch_add(1, Ordering::Relaxed);
            }
            dispatch(epoch, frame, path, on_ack)
        },
        |_, _| Ok(()),
        |_| panic!("receive failed"),
    ));
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"wired stream")).unwrap();
    let bytes = emit(&mut Sender::new(keys(&ct), ct.clone(), cp).unwrap());
    router.receive(bytes.clone(), link.into(), link, 8);
    router.receive(bytes, link.into(), link, 8);
    let (_, mut reader) = tokio::time::timeout(Duration::from_secs(2), server.accept_uni_stream())
        .await
        .unwrap()
        .unwrap();
    let mut body = [0; 12];
    reader.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"wired stream");
    // The lifecycle owner consumes the close reason and switches the existing engine.
    server.close(VarInt::from_u32(0), "done");
    assert!(matches!(
        close.await.unwrap(),
        Some(crate::CloseReason::App(_))
    ));
    closing.store(true, Ordering::Release);
    router.receive(ping(&keys(&ct), 1), link.into(), link, 8);
    router.receive(close_packet(&keys(&ct), 2), link.into(), link, 8);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), close_seen)
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    assert_eq!(streams_seen.load(Ordering::Relaxed), 1);
    assert_eq!(
        st.data.rcvd_journal.decode_pn(PacketNumber::encode(1, 0)),
        Ok(1)
    );
    initial.retire();
    handshake.retire();
    drop(route);
    drop(inbox);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn receive_error_keeps_the_engine_alive_for_peer_close() {
    let [(_client, ct, _), (server, st, sp)] = pair(1);
    let (inbox, rcvd_pkt) = channel::new();
    assert!(enqueue(&inbox, Packet::Data(parse(&ping(&keys(&ct), 0)))));
    assert!(enqueue(&inbox, Packet::Data(parse(&ping(&keys(&ct), 1)))));
    assert!(enqueue(
        &inbox,
        Packet::Data(parse(&close_packet(&keys(&ct), 2)))
    ));
    drop(inbox);
    let mut errors = 0;
    let mut ordinary = 0;
    let mut closes = 0;
    run_receive(
        rcvd_pkt.one_rtt,
        st.data.clone(),
        move |_, _| Some(sp.clone()),
        |keys: &OneRttKeys, packet, pto| {
            keys.open_packet(packet, |pn| st.data.rcvd_journal.decode_pn(pn), pto)
        },
        Arc::default(),
        |_, _, frame, _| {
            if matches!(frame, Frame::Close(_)) {
                closes += 1;
                Ok(())
            } else {
                ordinary += 1;
                Err(QuicError::with_default_fty(ErrorKind::Internal, "component failed").into())
            }
        },
        |_, _| Ok(()),
        |error| {
            errors += 1;
            st.close(error);
        },
    )
    .await;
    assert_eq!((errors, ordinary, closes), (1, 1, 1));
    assert!(server.accept_uni_stream().await.is_err());
    assert_eq!(
        st.data.rcvd_journal.decode_pn(PacketNumber::encode(0, 0)),
        Ok(0)
    );
}

#[tokio::test]
async fn frame_dispatcher_connects_crypto_cids_tokens_and_peer_close_to_original_components() {
    use qbase::{
        ArcReceiving,
        frame::{
            ConnectionCloseFrame, CryptoFrame, NewConnectionIdFrame, NewTokenFrame,
            RetireConnectionIdFrame,
        },
    };
    use qrecovery::crypto::CryptoStream;
    use tokio::io::AsyncReadExt;
    let [(client, ct, cp), (_server, _, _)] = pair(1);
    let crypto = std::array::from_fn(|_| CryptoStream::new(Default::default()));
    let retired = ArcReceiving::default();
    let issued = ArcReceiving::default();
    let token = ArcReceiving::default();
    let handshake_ack = ArcReceiving::default();
    let ack_sink = handshake_ack.clone();
    let closing = Arc::new(AtomicBool::new(false));
    let close_seen = ArcReceiving::default();
    let close_sink = close_seen.clone();
    let dispatch = recv::frame_dispatcher(
        ct.data.clone(),
        ct.parameters.clone(),
        ct.streams.clone(),
        ct.flow.clone(),
        crypto.clone(),
        retired.clone(),
        issued.clone(),
        token.clone(),
        closing.clone(),
        move |_, frame, _| close_sink.recv_frame(frame),
        move |epoch, frame, _| {
            assert_eq!(epoch, Epoch::Handshake);
            let Frame::Ack(frame) = frame else {
                panic!("unexpected frame")
            };
            ack_sink.recv_frame(frame)
        },
    );
    let ready = keys(&ct);
    let dispatch =
        |epoch, frame, path| dispatch(epoch, frame, path, &|generation| ready.on_ack(generation));
    for (index, epoch) in [Epoch::Initial, Epoch::Handshake, Epoch::Data]
        .into_iter()
        .enumerate()
    {
        dispatch(
            epoch,
            Frame::Crypto(
                CryptoFrame::new(0u32.into(), 1u32.into()),
                Bytes::from(vec![index as u8]),
            ),
            &cp,
        )
        .unwrap();
        let mut body = [0];
        crypto[index].reader().read_exact(&mut body).await.unwrap();
        assert_eq!(body, [index as u8]);
    }
    let retire = RetireConnectionIdFrame::new(0u32.into());
    let issue = NewConnectionIdFrame::new(
        ConnectionId::from_slice(b"newalias"),
        1u32.into(),
        0u32.into(),
    );
    let new_token = NewTokenFrame::new(b"token".to_vec());
    dispatch(Epoch::Data, Frame::RetireConnectionId(retire), &cp).unwrap();
    dispatch(Epoch::Data, Frame::NewConnectionId(issue), &cp).unwrap();
    dispatch(Epoch::Data, Frame::NewToken(new_token.clone()), &cp).unwrap();
    dispatch(Epoch::Handshake, Frame::Ack(ack(0)), &cp).unwrap();
    assert_eq!(retired.await.unwrap(), Some(retire));
    assert_eq!(issued.await.unwrap(), Some(issue));
    assert_eq!(token.await.unwrap(), Some(new_token));
    assert_eq!(handshake_ack.await.unwrap(), Some(ack(0)));
    ready.update().unwrap();
    let mut sender = Sender::new(ready.clone(), ct.clone(), cp.clone()).unwrap();
    sender.heartbeat();
    emit(&mut sender);
    assert!(ready.update().is_err());
    dispatch(Epoch::Data, Frame::Ack(ack(0)), &cp).unwrap();
    ready.update().unwrap();
    let accept_bi = client.accept_bi_stream();
    let accept_uni = client.accept_uni_stream();
    tokio::pin!(accept_bi, accept_uni);
    assert!(futures::poll!(&mut accept_bi).is_pending());
    assert!(futures::poll!(&mut accept_uni).is_pending());
    let close = ConnectionCloseFrame::from(Error::from(AppError::new(7u32.into(), "peer closed")));
    dispatch(Epoch::Data, Frame::Close(close.clone()), &cp).unwrap();
    assert!(closing.load(Ordering::Acquire));
    assert!(accept_bi.await.is_err());
    assert!(accept_uni.await.is_err());
    assert_eq!(close_seen.await.unwrap(), Some(close));
}

#[tokio::test]
async fn stream_assembly_packs_small_streams_and_uses_remaining_datagram_capacity() {
    use tokio::io::AsyncWriteExt;
    let [(client, ct, cp), (_server, st, sp)] = pair(8);
    let mut writers = Vec::new();
    for _ in 0..3 {
        let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
        writer.write_all(&[7; 250]).await.unwrap();
        writers.push(writer);
    }
    let mut sender = Sender::new(keys(&ct), ct.clone(), cp).unwrap();
    let bytes = emit(&mut sender);
    let (_, frames) = st
        .data
        .keys
        .clone()
        .now_or_never()
        .unwrap()
        .unwrap()
        .open(
            parse(&bytes),
            |pn| st.data.rcvd_journal.decode_pn(pn),
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
    let lengths: Vec<_> = frames
        .map(Result::unwrap)
        .filter_map(|(frame, _)| match frame {
            Frame::Stream(_, bytes) => Some(bytes.len()),
            _ => None,
        })
        .collect();
    assert_eq!(lengths, [250, 250, 250]);
    receive(&st, &sp, &bytes).unwrap();

    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write_all(&[9; 2048]).await.unwrap();
    let bytes = emit(&mut sender);
    assert!(bytes.len() >= 1100, "bulk data should fill the datagram");
    receive(&st, &sp, &bytes).unwrap();
}

#[test]
fn a_large_frame_that_fits_is_assembled_before_later_sources() {
    let mut recorded = Vec::new();
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    let bytes = [Bytes::from(vec![1; 800])];
    let mut crypto = (
        qbase::frame::CryptoFrame::new(VarInt::from_u32(0), VarInt::from_u32(800)),
        bytes.as_slice(),
    );
    packet
        .assemble(
            &Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            &mut recorded,
            [&mut crypto, &mut PingFrame],
        )
        .unwrap();
    assert!(matches!(recorded.as_slice(), [GuaranteedFrame::Crypto(frame)] if frame.len() == 800));
}

#[test]
fn earlier_sources_fill_the_packet_and_remaining_frames_stay_queued() {
    use qbase::frame::{MaxDataFrame, ReliableFrame, io::SendFrame};

    let mut reliable = ReliableFrames::with_capacity_and_wakers(600, Default::default());
    reliable.send_frame(
        (0..600).map(|i| ReliableFrame::MaxData(MaxDataFrame::new(VarInt::from_u32(1000 + i)))),
    );
    let bytes = [Bytes::from_static(b"later")];
    let mut crypto = (
        qbase::frame::CryptoFrame::new(0u32.into(), 5u32.into()),
        bytes.as_slice(),
    );
    let mut sent = Vec::new();
    for pn in 0..2 {
        let mut recorded = Vec::new();
        let mut packet = SendingPacket::new(
            BytesMut::zeroed(1200),
            OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
            16,
        )
        .unwrap();
        packet
            .assemble(
                &Constraints {
                    capacity: 1200,
                    congestion: 1200,
                    anti_amplification: 1200,
                },
                &mut recorded,
                [&mut reliable, &mut crypto],
            )
            .unwrap();
        for frame in recorded.as_slice() {
            if let GuaranteedFrame::Reliable(qbase::frame::ReliableFrame::MaxData(frame)) = frame {
                sent.push(frame.max_data());
            }
        }
        if pn == 0 {
            assert!(
                sent.len() > 300,
                "the earlier queue must not stop at 512 bytes"
            );
            assert!(
                !recorded
                    .as_slice()
                    .iter()
                    .any(|frame| matches!(frame, GuaranteedFrame::Crypto(..)))
            );
        } else {
            assert!(matches!(
                recorded.as_slice().last(),
                Some(GuaranteedFrame::Crypto(..))
            ));
        }
    }
    assert_eq!(sent, (1000..1600).collect::<Vec<_>>());
}

#[tokio::test(start_paused = true)]
async fn sender_assembles_ack_crypto_path_reliable_then_streams() {
    use qbase::frame::{MaxDataFrame, PathChallengeFrame, ReliableFrame, io::SendFrame};
    use tokio::io::AsyncWriteExt;

    let [(client, ct, cp), (_server, st, _sp)] = pair(1);
    receive(&ct, &cp, &ping(&keys(&st), 0)).unwrap();
    tokio::time::advance(Duration::from_millis(100)).await;
    ct.data.crypto.writer().write_all(b"crypto").await.unwrap();
    cp.recv_frame(PathChallengeFrame::random()).unwrap();
    ct.reliable_frames
        .send_frame([ReliableFrame::MaxData(MaxDataFrame::new(4096u32.into()))]);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write_all(b"stream").await.unwrap();
    let mut sender = Sender::new(keys(&ct), ct.clone(), cp).unwrap();
    let bytes = emit(&mut sender);
    let (_, frames) = keys(&st)
        .open(
            parse(&bytes),
            |pn| st.data.rcvd_journal.decode_pn(pn),
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
    let frames: Vec<_> = frames
        .map(|frame| frame.unwrap().0)
        .filter(|frame| !matches!(frame, Frame::Padding(_)))
        .collect();
    assert!(matches!(
        frames.as_slice(),
        [
            Frame::Ack(_),
            Frame::Crypto(..),
            Frame::PathResponse(_),
            Frame::MaxData(_),
            Frame::Stream(..),
        ]
    ));
}

#[tokio::test]
async fn real_tls_keys_stream_roundtrip_and_ack_complete_shutdown() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let [(client, ct, cp), (server, st, sp)] = pair(8);
    assert_eq!(client.alpn(), b"ssh");
    assert_eq!(server.alpn(), client.alpn());
    let (_, (mut reply, mut request)) = client.open_bi_stream().await.unwrap().unwrap();
    request.write_all(b"request").await.unwrap();
    let mut shutdown = Box::pin(request.shutdown());
    assert!(futures::poll!(&mut shutdown).is_pending());
    let mut cs = Sender::new(keys(&ct), ct.clone(), cp.clone()).unwrap();
    let mut ss = Sender::new(keys(&st), st.clone(), sp.clone()).unwrap();
    let bytes = emit(&mut cs);
    let pn = receive(&st, &sp, &bytes).unwrap();
    acknowledge(&ct, &ack(pn), &cp).unwrap();
    shutdown.await.unwrap();
    let (_, (mut request, mut response)) = server.accept_bi_stream().await.unwrap();
    let mut input = String::new();
    request.read_to_string(&mut input).await.unwrap();
    assert_eq!(input, "request");
    response.write_all(b"response").await.unwrap();
    let mut shutdown = Box::pin(response.shutdown());
    assert!(futures::poll!(&mut shutdown).is_pending());
    receive(&ct, &cp, &emit(&mut ss));
    let mut input = String::new();
    reply.read_to_string(&mut input).await.unwrap();
    assert_eq!(input, "response");
}

#[tokio::test]
async fn close_wakes_both_accepts_and_blocked_opens_without_changing_parameters() {
    let [(client, _transport, _), _] = pair(0);
    let mut bi = Box::pin(client.accept_bi_stream());
    let mut uni = Box::pin(client.accept_uni_stream());
    let mut open_bi = Box::pin(client.open_bi_stream());
    let mut open_uni = Box::pin(client.open_uni_stream());
    assert!(futures::poll!(&mut bi).is_pending());
    assert!(futures::poll!(&mut uni).is_pending());
    assert!(futures::poll!(&mut open_bi).is_pending());
    assert!(futures::poll!(&mut open_uni).is_pending());
    client.clone().close(VarInt::from_u32(42), "stop");
    let expected = AppError::new(VarInt::from_u32(42), "stop").into();
    assert!(matches!(bi.await, Err(error) if error == expected));
    assert!(matches!(uni.await, Err(error) if error == expected));
    assert!(open_bi.await.is_err());
    assert!(open_uni.await.is_err());
    assert_eq!(
        client
            .parameters()
            .remote::<u64>(ParameterId::InitialMaxStreamsUni),
        Some(0)
    );
    assert_eq!(client.alpn(), b"ssh");
    client.clone().close(VarInt::from_u32(99), "later");
    assert!(matches!(client.accept_uni_stream().await, Err(error) if error == expected));
}

#[tokio::test]
async fn cancelling_open_and_accept_does_not_consume_streams() {
    let [(client, transport, _), _] = pair(0);
    let mut opening = Box::pin(client.open_uni_stream());
    assert!(futures::poll!(&mut opening).is_pending());
    drop(opening);
    transport
        .streams
        .recv_frame(StreamCtlFrame::MaxStreams(MaxStreamsFrame::Uni(
            VarInt::from_u32(1),
        )))
        .unwrap();
    let (sid, _) = client.open_uni_stream().await.unwrap().unwrap();
    assert_eq!(sid, StreamId::new(Role::Client, Dir::Uni, 0));
    let mut accept = Box::pin(client.accept_uni_stream());
    assert!(futures::poll!(&mut accept).is_pending());
    drop(accept);
}

#[tokio::test]
async fn clone_drop_and_explicit_close_have_connection_wide_semantics() {
    let [(client, _transport, _), _] = pair(1);
    drop(client.clone());
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    drop(client);
    assert!(writer.write(Bytes::from_static(b"late")).is_err());
}

#[tokio::test]
async fn duplicate_skips_authentication_and_forgery_is_not_committed() {
    let [(_client, ct, _), (_server, st, sp)] = pair(1);
    let bytes = ping(&keys(&ct), 0);
    assert_eq!(receive(&st, &sp, &bytes), Some(0));
    assert_eq!(receive(&st, &sp, &bytes), None);
    let mut forged = ping(&keys(&ct), 1);
    let index = forged.len() - 1;
    forged[index] ^= 1;
    assert!(
        st.data
            .keys
            .clone()
            .now_or_never()
            .unwrap()
            .unwrap()
            .open(
                parse(&forged),
                |pn| st.data.rcvd_journal.decode_pn(pn),
                Duration::from_secs(1)
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        st.data.rcvd_journal.decode_pn(PacketNumber::encode(1, 0)),
        Ok(1)
    );
}

#[tokio::test]
async fn packet_constraints_keep_ack_only_outside_cwnd_but_inside_amplification_budget() {
    let (materials, _) = handshake();
    let [client, _] = materials;
    let transport = transport(Role::Client, client, 1);
    let mut recorded = Vec::new();
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    let constraints = Constraints {
        capacity: 1200,
        congestion: 0,
        anti_amplification: 1200,
    };
    packet
        .assemble(&constraints, &mut recorded, [&mut ack(0), &mut PingFrame])
        .unwrap();
    assert!(packet.pad_to(1200, &constraints).is_err());
    let packet = seal_packet(
        packet,
        &keys(&transport),
        &transport.data.send_journal,
        &mut recorded,
    )
    .unwrap();
    assert!(!packet.in_flight);
    assert_eq!(constraints.congestion, 0);
    let mut recorded = Vec::new();
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    assert!(matches!(
        packet.assemble(
            &Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 10
            },
            &mut recorded,
            [&mut ack(0)]
        ),
        Err(PacketError::Blocked(_))
    ));
}

#[test]
fn packet_assembly_uses_fixed_limits_across_ack_data_and_padding() {
    let mut recorded = Vec::new();
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    let mut constraints = Constraints {
        capacity: 100,
        congestion: 0,
        anti_amplification: 100,
    };
    packet
        .assemble(&constraints, &mut recorded, [&mut ack(0)])
        .unwrap();
    assert_eq!(constraints.capacity, 100);
    assert_eq!(constraints.anti_amplification, 100);
    assert!(
        packet
            .assemble(&constraints, &mut recorded, [&mut PingFrame])
            .is_err()
    );
    assert!(packet.pad_to(100, &constraints).is_err());

    constraints.congestion = 100;
    packet
        .assemble(&constraints, &mut recorded, [&mut PingFrame])
        .unwrap();
    packet.pad_to(100, &constraints).unwrap();
    assert_eq!(constraints.congestion, 100);
    assert!(
        packet
            .assemble(&constraints, &mut recorded, [&mut PingFrame])
            .is_err()
    );
    assert!(packet.pad_to(101, &constraints).is_err());
    assert!(recorded.as_slice().is_empty());
    assert_eq!(constraints.capacity, 100);
    assert_eq!(constraints.anti_amplification, 100);
    assert_eq!(constraints.congestion, 100);
}

#[tokio::test]
async fn data_sources_respect_each_limit_without_consuming_unsent_bytes() {
    use qbase::packet::{Package, io::Repeat};
    use tokio::io::AsyncWriteExt;

    for limited in 0..3 {
        let [(client, ct, _), (_server, st, _)] = pair(1);
        let crypto_data = vec![0x63; 200];
        let stream_data = vec![0x73; 200];
        ct.data
            .crypto
            .writer()
            .write_all(&crypto_data)
            .await
            .unwrap();
        let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
        writer.write_all(&stream_data).await.unwrap();
        let mut crypto = ct.data.crypto.outgoing().package(Epoch::Data);
        let mut streams = Repeat(ct.streams.package(ct.flow.sender.clone(), false));
        let mut crypto_received = Vec::new();
        let mut stream_received = Vec::new();
        let mut constraints = Constraints {
            capacity: 1200,
            congestion: 1200,
            anti_amplification: 1200,
        };
        let sealing = keys(&ct);
        let opening = keys(&st);
        for pn in 0..32 {
            let mut recorded = Vec::new();
            let mut packet = SendingPacket::new(
                BytesMut::zeroed(1200),
                OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
                16,
            )
            .unwrap();
            let limit = match limited {
                0 => &mut constraints.capacity,
                1 => &mut constraints.congestion,
                _ => &mut constraints.anti_amplification,
            };
            *limit = if pn == 0 { 24 } else { 80 };
            if pn == 0 {
                // Direct sources use the same constrained, recording writer as assemble.
                let mut target = PacketWriter::new(&mut packet, &constraints, &mut recorded);
                assert!(crypto.dump(&mut target).is_err());
                assert!(streams.dump(&mut target).is_err());
                assert!(recorded.as_slice().is_empty());
                continue;
            }
            if pn % 2 == 0 {
                packet
                    .assemble(&constraints, &mut recorded, [&mut crypto, &mut streams])
                    .unwrap();
            } else {
                let mut target = PacketWriter::new(&mut packet, &constraints, &mut recorded);
                let crypto_result = crypto.dump(&mut target);
                let stream_result = streams.dump(&mut target);
                assert!(crypto_result.is_ok() || stream_result.is_ok());
            }
            assert!(!recorded.is_empty());
            let pending = seal_packet(
                packet,
                &sealing,
                &send::records::ArcSendJournal::starting_at(pn),
                &mut recorded,
            )
            .unwrap();
            assert!(pending.bytes().len() <= 80);
            let (_, frames) = opening
                .open(parse(pending.bytes()), |_| Ok(pn), Duration::from_secs(1))
                .unwrap()
                .unwrap();
            for frame in frames {
                match frame.unwrap().0 {
                    Frame::Crypto(frame, bytes) => {
                        assert_eq!(frame.range().start, crypto_received.len() as u64);
                        crypto_received.extend_from_slice(&bytes);
                    }
                    Frame::Stream(frame, bytes) => {
                        assert_eq!(frame.range().start, stream_received.len() as u64);
                        stream_received.extend_from_slice(&bytes);
                    }
                    Frame::Padding(_) => {}
                    frame => panic!("unexpected frame: {frame:?}"),
                }
            }
            if crypto_received.len() == crypto_data.len()
                && stream_received.len() == stream_data.len()
            {
                break;
            }
        }
        assert_eq!(crypto_received, crypto_data);
        assert_eq!(stream_received, stream_data);
    }
}

#[tokio::test]
async fn empty_assembly_does_not_allocate_packet_numbers() {
    let [(_client, ct, cp), (_server, st, sp)] = pair(1);
    let mut sender = Sender::new(keys(&ct), ct.clone(), cp).unwrap();
    for _ in 0..5 {
        assert!(!sender.prepare().unwrap());
    }
    sender.heartbeat();
    assert_eq!(receive(&st, &sp, &emit(&mut sender)), Some(0));
}

#[tokio::test]
async fn pending_packet_on_a_slow_path_keeps_its_number_and_key_generation() {
    let [(client, ct, cp), (_server, st, sp)] = pair(4);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"retained")).unwrap();
    let mut slow = Sender::new(keys(&ct), ct.clone(), cp.clone()).unwrap();
    assert!(slow.prepare().unwrap());
    assert!(
        slow.poll_send_with(
            &mut Context::from_waker(futures::task::noop_waker_ref()),
            |_, _, _| Poll::Pending
        )
        .is_pending()
    );
    keys(&ct).update().unwrap();
    let other = path(&ct, 1);
    let mut fast = Sender::new(keys(&ct), ct.clone(), other).unwrap();
    fast.heartbeat();
    let fast_bytes = emit(&mut fast);
    assert_eq!(receive(&st, &sp, &fast_bytes), Some(1));
    let bytes = emit(&mut slow);
    assert_eq!(receive(&st, &sp, &bytes), Some(0));
    acknowledge(&ct, &ack(0), &cp).unwrap();
    let (_, mut reader) = st.streams.accept_uni().await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut output = [0; 8];
    reader.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"retained");
}

#[tokio::test]
async fn close_fails_business_apis_and_preserves_data_keys() {
    let [(client, ct, _), _] = pair(1);
    client.clone().close(VarInt::from_u32(0), "closed");
    assert!(matches!(ct.data.keys.try_get(), Ok(Some(_))));
    assert!(client.open_uni_stream().await.is_err());
}

#[tokio::test(start_paused = true)]
async fn peer_key_update_is_authenticated_before_installing_and_old_keys_expire() {
    let [(_client, ct, cp), (_server, st, sp)] = pair(1);
    let old = ping(&keys(&ct), 0);
    let later_old = ping(&keys(&ct), 1);
    keys(&ct).on_ack(0);
    keys(&ct).update().unwrap();
    let next = ping(&keys(&ct), 2);
    let mut forged = next.clone();
    let index = forged.len() - 1;
    forged[index] ^= 1;
    assert!(receive(&st, &sp, &forged).is_none());
    assert_eq!(receive(&st, &sp, &old), Some(0));
    assert_eq!(receive(&st, &sp, &next), Some(2));
    // Independent sealing cursor responds to the peer's generation without reusing a PN.
    let response = ping(&keys(&st), 0);
    assert_eq!(receive(&ct, &cp, &response), Some(0));
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(receive(&st, &sp, &later_old).is_none());
}

#[tokio::test]
async fn receiving_waits_for_keys_without_a_command_queue() {
    let (materials, _) = handshake();
    let [client, server] = materials;
    let ct = transport(Role::Client, client, 1);
    let cp = path(&ct, 0);
    let space = Arc::new(Space::<ArcOneRttKeys>::new(
        Epoch::Data,
        Default::default(),
        |_| {},
    ));
    let opening = space.keys.clone();
    let (inbox, rcvd_pkt) = channel::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let journal = space.rcvd_journal.clone();
    let task = tokio::spawn(run_receive(
        rcvd_pkt.one_rtt,
        space.clone(),
        move |_, _| Some(cp.clone()),
        move |keys: &OneRttKeys, packet, pto| {
            keys.open_packet(packet, |pn| journal.decode_pn(pn), pto)
        },
        Arc::default(),
        move |_, _, _, _| {
            seen.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        |_, _| Ok(()),
        |_| panic!("receive failed"),
    ));
    assert!(enqueue(&inbox, Packet::Data(parse(&ping(&keys(&ct), 0)))));
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    opening.install(server).unwrap();
    drop(inbox);
    task.await.unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn pipeline_rejection_does_not_ack_and_close_bypasses_business_delivery() {
    let [(_client, ct, _), (_server, st, sp)] = pair(1);
    let bytes = ping(&keys(&ct), 0);
    let (pn, frames) = st
        .data
        .keys
        .clone()
        .now_or_never()
        .unwrap()
        .unwrap()
        .open(
            parse(&bytes),
            |pn| st.data.rcvd_journal.decode_pn(pn),
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
    assert!(
        receive_packet(
            pn,
            frames,
            &st.data,
            &sp,
            &AtomicBool::new(false),
            |_, _, _| Err(QuicError::with_default_fty(ErrorKind::Internal, "pipe full").into()),
            |_, _| Ok(())
        )
        .is_err()
    );
    assert_eq!(
        st.data.rcvd_journal.decode_pn(PacketNumber::encode(pn, 0)),
        Ok(pn)
    );
    let mut recorded = Vec::new();
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    let mut close = qbase::frame::ConnectionCloseFrame::from(Error::from(AppError::new(
        VarInt::from_u32(7),
        "peer",
    )));
    packet
        .assemble(
            &Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            &mut recorded,
            [&mut PingFrame, &mut close],
        )
        .unwrap();
    let bytes = seal_packet(packet, &keys(&ct), &ct.data.send_journal, &mut recorded).unwrap();
    let (pn, frames) = st
        .data
        .keys
        .clone()
        .now_or_never()
        .unwrap()
        .unwrap()
        .open(
            parse(bytes.bytes()),
            |pn| st.data.rcvd_journal.decode_pn(pn),
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
    receive_packet(
        pn,
        frames,
        &st.data,
        &sp,
        &AtomicBool::new(false),
        |_, frame, _| {
            assert!(matches!(frame, Frame::Close(_)));
            Ok(())
        },
        |_, _| Ok(()),
    )
    .unwrap();
}

#[tokio::test]
async fn loss_returns_frames_to_sources_before_the_sender_runs() {
    use qbase::frame::{MaxDataFrame, io::SendFrame};
    use tokio::io::AsyncWriteExt;

    let [(client, ct, cp), _] = pair(1);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"stream")).unwrap();
    ct.data.crypto.writer().write_all(b"crypto").await.unwrap();
    ct.reliable_frames
        .send_frame([MaxDataFrame::new(123u32.into())]);
    let mut sender = Sender::new(keys(&ct), ct.clone(), cp).unwrap();
    emit(&mut sender);
    drop(sender);

    crate::space::ArcFeedback::from(ct.data.send_journal.clone()).may_loss(
        qevent::quic::recovery::PacketLostTrigger::TimeThreshold,
        &mut [0, 0].into_iter(),
    );
    // Read the components directly: no Sender or timer may extract journal work first.
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    let mut frames = Vec::new();
    let mut crypto = ct.data.crypto.outgoing().package(Epoch::Data);
    let mut reliable = ct.reliable_frames.clone();
    let mut streams = ct.streams.package(ct.flow.sender.clone(), false);
    packet
        .assemble(
            &Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            &mut frames,
            [&mut crypto, &mut reliable, &mut streams],
        )
        .unwrap();
    assert!(matches!(frames.as_slice(),
        [GuaranteedFrame::Crypto(_), GuaranteedFrame::Reliable(qbase::frame::ReliableFrame::MaxData(f)), GuaranteedFrame::Stream(_)]
        if f.max_data() == 123));
}

#[tokio::test]
async fn late_ack_clears_requeued_stream_and_crypto_before_the_sender_runs() {
    use tokio::io::AsyncWriteExt;

    let [(client, ct, cp), _] = pair(1);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"stream")).unwrap();
    ct.data.crypto.writer().write_all(b"crypto").await.unwrap();
    let mut sender = Sender::new(keys(&ct), ct.clone(), cp.clone()).unwrap();
    emit(&mut sender);
    crate::space::ArcFeedback::from(ct.data.send_journal.clone()).may_loss(
        qevent::quic::recovery::PacketLostTrigger::TimeThreshold,
        &mut [0].into_iter(),
    );
    acknowledge(&ct, &ack(0), &cp).unwrap();
    assert!(!sender.prepare().unwrap());
}

#[tokio::test]
async fn loss_requeues_stream_ranges_without_charging_flow_credit_twice() {
    let [(client, ct, cp), (server, st, sp)] = pair(2);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"lost once")).unwrap();
    let mut sender = Sender::new(keys(&ct), ct.clone(), cp.clone()).unwrap();
    let dropped = emit(&mut sender);
    let credit = ct.flow.sender.credit(usize::MAX).unwrap().available();
    crate::space::ArcFeedback::from(ct.data.send_journal.clone()).may_loss(
        qevent::quic::recovery::PacketLostTrigger::TimeThreshold,
        &mut [0].into_iter(),
    );
    let retry = emit(&mut sender);
    assert_eq!(
        ct.flow.sender.credit(usize::MAX).unwrap().available(),
        credit
    );
    assert_eq!(receive(&st, &sp, &retry), Some(1));
    acknowledge(&ct, &ack(1), &cp).unwrap();
    let (_, mut reader) = server.accept_uni_stream().await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut bytes = [0; 9];
    reader.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"lost once");
    // Late arrival and ACK of the original packet do not deliver/credit the bytes twice.
    assert_eq!(receive(&st, &sp, &dropped), Some(0));
    acknowledge(&ct, &ack(0), &cp).unwrap();
}

#[tokio::test]
async fn retired_path_replacement_has_its_own_sender_and_waiter() {
    let [(_client, ct, cp), _] = pair(1);
    let old_sender = Sender::new(keys(&ct), ct.clone(), cp.clone()).unwrap();
    cp.retire();
    let replacement = path(&ct, 0);
    let mut sender = Sender::new(keys(&ct), ct.clone(), replacement.clone()).unwrap();
    drop(old_sender);
    assert_eq!(cp.state(), crate::path::PathState::Retired);
    assert!(!Arc::ptr_eq(&cp, &replacement));
    sender.heartbeat();
    assert!(!emit(&mut sender).is_empty());
}

#[tokio::test(start_paused = true)]
async fn connection_tick_recovers_after_the_original_path_and_sender_are_dropped() {
    use qcongestion::Transport as _;

    let [(client, transport, original), (server, peer, peer_path)] = pair(1);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"retired path")).unwrap();
    let (retransmit_after, _) = original.cc.retransmit_and_expire_time(Epoch::Data);
    let mut sender = Sender::new(keys(&transport), transport.clone(), original.clone()).unwrap();
    emit(&mut sender);
    let credit = transport
        .flow
        .sender
        .credit(usize::MAX)
        .unwrap()
        .available();
    original.retire();
    drop(sender);
    drop(original);
    // Path retirement alone must not make the stream range available again.
    let mut streams = transport
        .streams
        .package(transport.flow.sender.clone(), false);
    use qbase::packet::Package;
    let mut packet = SendingPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        16,
    )
    .unwrap();
    let constraints = Constraints {
        capacity: 1200,
        congestion: 1200,
        anti_amplification: 1200,
    };
    let mut frames = Vec::new();
    let mut target = PacketWriter::new(&mut packet, &constraints, &mut frames);
    assert!(streams.dump(&mut target).is_err());
    transport.on_tick(tokio::time::Instant::now());
    assert!(streams.dump(&mut target).is_err());

    tokio::time::advance(retransmit_after).await;
    transport.on_tick(tokio::time::Instant::now());
    let replacement = path(&transport, 1);
    let mut sender = Sender::new(keys(&transport), transport.clone(), replacement.clone()).unwrap();
    assert_eq!(receive(&peer, &peer_path, &emit(&mut sender)), Some(1));
    assert_eq!(
        transport
            .flow
            .sender
            .credit(usize::MAX)
            .unwrap()
            .available(),
        credit
    );
    transport.on_tick(tokio::time::Instant::now());
    assert!(
        !sender.prepare().unwrap(),
        "a second tick must not duplicate recovery"
    );
    acknowledge(&transport, &ack(0), &replacement).unwrap();
    acknowledge(&transport, &ack(1), &replacement).unwrap();
    let (_, mut reader) = server.accept_uni_stream().await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut body = [0; 12];
    reader.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"retired path");
}

#[tokio::test]
async fn connection_close_preserves_completed_streams_and_errors_active_streams() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let [(client, ct, cp), (server, st, sp)] = pair(3);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write_all(b"unread").await.unwrap();
    let mut shutdown = Box::pin(writer.shutdown());
    assert!(futures::poll!(&mut shutdown).is_pending());
    let mut sender = Sender::new(keys(&ct), ct.clone(), cp.clone()).unwrap();
    let pn = receive(&st, &sp, &emit(&mut sender)).unwrap();
    acknowledge(&ct, &ack(pn), &cp).unwrap();
    shutdown.await.unwrap();
    let (_, mut reader) = server.accept_uni_stream().await.unwrap();

    let (_, mut active_writer) = client.open_uni_stream().await.unwrap().unwrap();
    active_writer.write_all(b"partial").await.unwrap();
    receive(&st, &sp, &emit(&mut sender)).unwrap();
    let (_, mut active_reader) = server.accept_uni_stream().await.unwrap();
    active_reader.read_exact(&mut [0; 7]).await.unwrap();
    let mut buf = [0; 1];
    let mut reading = Box::pin(active_reader.read(&mut buf));
    assert!(futures::poll!(&mut reading).is_pending());

    server.clone().close(0u32.into(), "peer close");
    assert!(reading.await.is_err());
    let mut unread = Vec::new();
    reader.read_to_end(&mut unread).await.unwrap();
    assert_eq!(unread, b"unread");
    client.clone().close(0u32.into(), "local close");
    assert!(active_writer.flush().await.is_err());
    writer.flush().await.unwrap();
    writer.shutdown().await.unwrap();
    assert!(matches!(
        writer.write(Bytes::from_static(b"late")),
        Err(StreamError::Finished)
    ));
}

#[tokio::test]
async fn close_wakers_are_independent_and_fire_without_repolling() {
    use futures::task::{ArcWake, waker};
    struct Count(AtomicUsize);
    impl ArcWake for Count {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let [(client, _transport, _), _] = pair(0);
    let counts: [_; 4] = std::array::from_fn(|_| Arc::new(Count(AtomicUsize::new(0))));
    let wakers = counts.each_ref().map(|counter| waker(counter.clone()));
    let mut bi = Box::pin(client.accept_bi_stream());
    let mut uni = Box::pin(client.accept_uni_stream());
    let mut open_bi = Box::pin(client.open_bi_stream());
    let mut open_uni = Box::pin(client.open_uni_stream());
    use std::future::Future;
    assert!(
        bi.as_mut()
            .poll(&mut Context::from_waker(&wakers[0]))
            .is_pending()
    );
    assert!(
        uni.as_mut()
            .poll(&mut Context::from_waker(&wakers[1]))
            .is_pending()
    );
    assert!(
        open_bi
            .as_mut()
            .poll(&mut Context::from_waker(&wakers[2]))
            .is_pending()
    );
    assert!(
        open_uni
            .as_mut()
            .poll(&mut Context::from_waker(&wakers[3]))
            .is_pending()
    );
    client.clone().close(0u32.into(), "wake all");
    assert!(
        counts
            .iter()
            .all(|count| count.0.load(Ordering::Relaxed) != 0)
    );
}

#[tokio::test]
async fn udp_submission_delivers_an_encrypted_stream() {
    use qprotocol::{protocol::quic::QuicProtocol, socket::UdpSocket};
    let [(client, ct, _), (server, st, sp)] = pair(1);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    let pathway = Pathway::new(local, EndpointAddr::direct(remote.local_addr().unwrap()));
    let protocol = QuicProtocol::new();
    protocol.register(local, &socket).unwrap();
    let status = Arc::new(HandshakeStatus::new(false));
    status.handshake_confirmed();
    let feedback: Arc<dyn Feedback> = Arc::new(crate::space::ArcFeedback::from(
        ct.data.send_journal.clone(),
    ));
    let path = Arc::new(Path::new(
        pathway,
        ConnectionId::from_slice(b"original"),
        status,
        Duration::from_millis(25),
        path_idle(),
        [feedback.clone(), feedback.clone(), feedback],
    ));
    path.validate();
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"udp payload")).unwrap();
    let mut sender = Sender::new(keys(&ct), ct.clone(), path).unwrap();
    assert!(sender.prepare().unwrap());
    assert!(
        std::future::poll_fn(|cx| sender.poll_send(cx, &protocol))
            .await
            .unwrap()
    );
    let mut bytes = [0; 1200];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), remote.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    receive(&st, &sp, &bytes[..len]);
    let (_, mut reader) = server.accept_uni_stream().await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut body = [0; 11];
    reader.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"udp payload");
}

#[tokio::test]
async fn ack_between_socket_submission_and_accounting_waits_for_commit() {
    let [(_client, transport, path), _] = pair(1);
    let mut sender = Sender::new(keys(&transport), transport.clone(), path.clone()).unwrap();
    sender.heartbeat();
    assert!(sender.prepare().unwrap());
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let (done, acknowledged) = std::sync::mpsc::channel();
    let worker = {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            done.send(acknowledge(&transport, &ack(0), &path)).unwrap();
        })
    };
    assert!(matches!(
        sender.poll_send_with(
            &mut Context::from_waker(futures::task::noop_waker_ref()),
            |_, _, bytes| {
                barrier.wait();
                assert!(matches!(
                    acknowledged.recv_timeout(Duration::from_millis(30)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ));
                Poll::Ready(Ok(bytes.len()))
            }
        ),
        Poll::Ready(Ok(true))
    ));
    worker.join().unwrap();
    assert!(acknowledged.recv().unwrap().is_ok());
}

#[tokio::test]
async fn path_validation_replies_on_ingress_and_withholds_stream_data_until_validated() {
    let [(client, ct, cp), (server, st, sp)] = pair(2);
    let paths = [(&ct, cp.pathway), (&st, sp.pathway)].map(|(transport, pathway)| {
        let status = Arc::new(HandshakeStatus::new(
            transport.parameters.role() == Role::Server,
        ));
        status.handshake_confirmed();
        let feedback: Arc<dyn Feedback> = Arc::new(crate::space::ArcFeedback::from(
            transport.data.send_journal.clone(),
        ));
        Arc::new(Path::new(
            pathway,
            ConnectionId::from_slice(b"original"),
            status,
            Duration::from_millis(25),
            path_idle(),
            [feedback.clone(), feedback.clone(), feedback],
        ))
    });
    let [cp, sp] = paths;
    cp.grant_amplification();
    cp.start_validation();
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"validated")).unwrap();
    let mut cs = Sender::new(keys(&ct), ct.clone(), cp.clone()).unwrap();
    let mut ss = Sender::new(keys(&st), st.clone(), sp.clone()).unwrap();
    let challenge = emit(&mut cs);
    assert_eq!(challenge.len(), 1200);
    assert_eq!(sp.amplification_credit(), 0);
    sp.on_datagram_received(challenge.len());
    receive(&st, &sp, &challenge);
    let mut accepting = Box::pin(server.accept_uni_stream());
    assert!(futures::poll!(&mut accepting).is_pending());
    let response = emit(&mut ss);
    assert_eq!(response.len(), 1200);
    assert_eq!(sp.amplification_credit(), 2400);
    receive(&ct, &cp, &response);
    assert!(cp.is_validated());
    receive(&st, &sp, &emit(&mut cs));
    let (_, mut reader) = accepting.await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut body = [0; 9];
    reader.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"validated");
}

#[tokio::test(start_paused = true)]
async fn exhausted_amplification_credit_suspends_pto_until_another_datagram() {
    use qcongestion::Transport as _;
    let [(_client, transport, original), _] = pair(1);
    let handshake = Arc::new(HandshakeStatus::new(false));
    handshake.handshake_confirmed();
    let feedback: Arc<dyn Feedback> = Arc::new(crate::space::ArcFeedback::from(
        transport.data.send_journal.clone(),
    ));
    let path = Arc::new(Path::new(
        original.pathway,
        original.dcid(),
        handshake,
        Duration::from_millis(25),
        path_idle(),
        [feedback.clone(), feedback.clone(), feedback],
    ));
    path.on_datagram_received(400);
    path.start_validation();
    let mut sender = Sender::new(keys(&transport), transport, path.clone()).unwrap();
    assert_eq!(emit(&mut sender).len(), 1200);
    assert_eq!(path.amplification_credit(), 0);

    tokio::time::advance(path.cc.get_pto(Epoch::Data) + Duration::from_millis(1)).await;
    path.cc.do_tick().unwrap();
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Data), 0);

    path.on_datagram_received(400);
    path.cc.do_tick().unwrap();
    assert!(path.cc.need_send_ack_eliciting(Epoch::Data) > 0);
}

#[tokio::test(start_paused = true)]
async fn shared_ack_only_updates_the_receiving_paths_congestion_control() {
    use qcongestion::Transport as _;
    let [(_client, transport, first), _] = pair(1);
    let second = path(&transport, 1);
    let mut first_sender = Sender::new(keys(&transport), transport.clone(), first.clone()).unwrap();
    let mut second_sender =
        Sender::new(keys(&transport), transport.clone(), second.clone()).unwrap();
    first_sender.heartbeat();
    emit(&mut first_sender);
    second_sender.heartbeat();
    emit(&mut second_sender);
    let first_pto = first.cc.pto_base(Epoch::Data);
    let second_pto = second.cc.pto_base(Epoch::Data);
    tokio::time::advance(Duration::from_millis(5)).await;
    let ack = AckFrame::new(1u32.into(), 0u32.into(), 1u32.into(), vec![], None);
    acknowledge(&transport, &ack, &second).unwrap();
    assert_eq!(first.cc.pto_base(Epoch::Data), first_pto);
    assert_ne!(second.cc.pto_base(Epoch::Data), second_pto);
    tokio::time::advance(first.cc.get_pto(Epoch::Data)).await;
    first.cc.do_tick().unwrap();
    assert!(first.cc.need_send_ack_eliciting(Epoch::Data) > 0);
}

#[tokio::test]
async fn resetting_one_stream_does_not_close_the_connection() {
    let [(client, ct, cp), (server, st, sp)] = pair(2);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.cancel(17);
    let mut sender = Sender::new(keys(&ct), ct.clone(), cp).unwrap();
    receive(&st, &sp, &emit(&mut sender));
    let (_, mut reader) = server.accept_uni_stream().await.unwrap();
    assert!(matches!(
        futures::StreamExt::next(&mut reader).await,
        Some(Err(StreamError::Reset(_)))
    ));
    assert!(client.open_uni_stream().await.unwrap().is_some());
    assert!(server.open_uni_stream().await.unwrap().is_some());
}

pub(crate) fn fixed_keys() -> qtls::BidirectionalKeys {
    tls_server(Arc::new(qtls::default_provider()), vec![b"h3".to_vec()])
        .initial_keys(qtls::QuicVersion::V1, b"original")
        .unwrap()
}

#[tokio::test]
async fn empty_inbox_wait_ends_when_channel_closes() {
    let (retained, rcvd_pkt) = channel::new();
    let space = Arc::new(Space::<crate::keys::ArcKeys>::new(
        Epoch::Initial,
        Default::default(),
        |_| {},
    ));
    let mut task = tokio::spawn(run_receive(
        rcvd_pkt.initial,
        space.clone(),
        |_, _| unreachable!(),
        |_: &Arc<qtls::BidirectionalKeys>, _, _| unreachable!(),
        Arc::default(),
        |_, _, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| unreachable!(),
    ));
    tokio::task::yield_now().await;
    space.retire();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut task)
            .await
            .is_err()
    );
    drop(retained);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}
