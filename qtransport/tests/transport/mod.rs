use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::FutureExt;
use qbase::{
    Epoch,
    cid::{ConnectionId, RetireCid},
    error::{AppError, ErrorKind, QuicError},
    frame::{AckFrame, Frame, MaxStreamsFrame, PingFrame, StreamCtlFrame, io::ReceiveFrame},
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
    },
    packet::{
        DataHeader, DataPacket, OneRttHeader, Packet, PacketNumber, PacketReader, assemble::Package,
    },
    param::{ClientParameters, ParameterId, ServerParameters},
    sid::{Dir, handy::DemandConcurrency},
    time::heartbeat::ArcHeartbeat,
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::{Resend, Transport as _};
use qrecovery::streams::DataStreams;
use tls_backend::pki_types::pem::PemObject;

use crate::{
    keys::{ArcOneRttKeys, KeyRetired, Open, Seal},
    packet::{channel, encrypt::Packet as SendingPacket},
    path::Path,
    space::{DataSpace, Space},
    *,
};

/// Test wiring for packet components; application connections only retain streams.
pub(crate) struct Transport {
    pub(crate) data: Arc<DataSpace>,
    pub(crate) parameters: ArcParameters,
}

impl Transport {
    fn close(&self, error: Error) {
        self.data.crypto.on_error(&error);
        self.data.streams.on_error(&error);
    }
}

pub(crate) fn take_frames(
    source: &mut impl for<'b> qbase::packet::Package<bytes::buf::Limit<&'b mut BytesMut>>,
) -> Vec<Frame> {
    use qbase::packet::{GetType, PacketBuffer};
    let mut bytes = BytesMut::with_capacity(1200);
    let mut frames = Vec::new();
    let limits_quota = 1200;
    let limits_length = 1200;
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
    let result = source.poll_dump(
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
        &mut PacketBuffer::new(&mut writer_0, limits_quota, &mut frames, ty, 0, 0),
    );
    assert!(!matches!(result, std::task::Poll::Ready(Err(_))));
    frames.into_iter().map(Into::into).collect()
}

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

mod receive;
use receive::receive_packets;

pub(crate) mod sender;
pub(crate) use sender::Sender;

const CERT: &[u8] = include_bytes!("../keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("../keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../keychain/localhost/ca.cert");
const OCSP: &[u8] = include_bytes!("../keychain/localhost/server.ocsp");

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
        authority: local,
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
        authority: None,
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
                    qtls::TlsEvent::WriteCrypto {
                        epoch: level,
                        bytes,
                    } => peers[1 - i].receive_crypto(level, &bytes).unwrap(),
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
    let mut client = ClientParameters::default();
    let mut server = ServerParameters::default();
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
    let reliable = ArcReliableFrames::with_capacity(0);
    let streams = DataStreams::new(
        params.clone(),
        Box::new(DemandConcurrency),
        reliable.clone(),
        Default::default(),
    );
    let data = Arc::new(DataSpace::new(
        Default::default(),
        ArcOneRttKeys::from(keys),
        streams,
        reliable,
        params.local::<u64>(qbase::param::ParameterId::AckDelayExponent) as u32,
        params.remote::<u64>(qbase::param::ParameterId::AckDelayExponent) as u32,
        confirmed_handshake(role),
    ));
    data.keys.allow_update();
    Arc::new(Transport {
        data,
        parameters: params,
    })
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
        let terminator = qtransport::terminate::ArcTerminator::no_error();
        terminator.register(Arc::new(transport.data.streams.clone()));
        let conn = ArcConnection::new(
            summary.alpn.unwrap(),
            transport.data.streams.clone(),
            terminator,
        );
        (conn, transport, path)
    })
    .collect::<Vec<_>>()
    .try_into()
    .ok()
    .unwrap()
}
pub(crate) fn keys(transport: &Transport) -> ArcOneRttKeys {
    transport.data.keys.clone()
}

fn data_trackers(transport: &Transport) -> ArcIndexDeque<Arc<dyn Resend>, 2> {
    let mut trackers = IndexDeque::<Arc<dyn Resend>, 2>::with_capacity(1);
    trackers.reset_offset(Epoch::Data as u64);
    trackers.push_back(transport.data.clone()).unwrap();
    ArcIndexDeque::from(trackers)
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
    let path = Arc::new(Path::new(
        pathway,
        confirmed_handshake(transport.parameters.role()),
        path_heartbeat(),
        data_trackers(transport),
        qbase::cid::ArcRemoteCids::client(
            Default::default(),
            qtransport::ArcReliableFrames::with_capacity(0),
        )
        .apply_dcid(),
    ));
    path.validation.enter_validated().unwrap();
    path
}

fn path_heartbeat() -> ArcHeartbeat {
    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO)
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
    match frame {
        Frame::Stream(frame, bytes) => {
            transport.data.streams.recv_frame((frame, bytes))?;
        }
        Frame::StreamCtl(frame) => {
            transport.data.streams.recv_frame(frame)?;
        }
        Frame::Ack(frame) => acknowledge(transport, &frame, path)?,
        Frame::PathChallenge(frame) => path.validation.recv_frame(frame)?,
        Frame::PathResponse(frame) => path.validation.recv_frame(frame)?,
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
    let (inbox, packets) = channel::new();
    assert!(enqueue(&inbox, Packet::Data(parse(bytes))));
    drop(inbox);
    let mut received = None;
    receive_packets(
        packets.one_rtt,
        Epoch::Data,
        {
            let keys = transport.data.keys.clone();
            move || (!keys.is_retired()).then(|| keys.clone())
        },
        transport.data.rcvd_journal.clone(),
        |_, _| Some(path.clone()),
        |keys, packet, _| {
            let opened = keys.open_packet(
                packet,
                |pn| transport.data.rcvd_journal.decode_pn(pn),
                Duration::from_secs(1),
            )?;
            received = opened.as_ref().map(|packet| packet.pn());
            Ok(opened)
        },
        |_, _| Ok(()),
        |_, _, frame, path, _| dispatch(transport, path, frame),
        |error| panic!("receive failed: {error}"),
    )
    .now_or_never()
    .expect("queued packet and closed inbox must complete immediately");
    received
}
fn acknowledge(transport: &Transport, ack: &AckFrame, path: &Arc<Path>) -> Result<(), Error> {
    let keys = keys(transport);
    crate::recv::acknowledge(&transport.data, ack, path, |generation| {
        keys.on_ack(generation)
    })
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
// Receive tests encode explicit packet numbers without constructing recovery history.
fn encode_packet<const N: usize>(
    keys: &ArcOneRttKeys,
    pn: u64,
    quota: usize,
    length: usize,
    frames: &mut Vec<GuaranteedFrame>,
    sources: [&mut dyn for<'b> Package<&'b mut [u8]>; N],
) -> BytesMut {
    let key = keys.get().unwrap();
    let mut packet = SendingPacket::new(
        DataHeader::Short(OneRttHeader::new(
            Default::default(),
            ConnectionId::from_slice(b"original"),
        )),
        (pn, PacketNumber::encode(pn, 0)),
        key.as_ref(),
    );
    let mut bytes = BytesMut::zeroed(length);
    let result = packet.assemble(
        &mut Context::from_waker(std::task::Waker::noop()),
        &mut std::io::Cursor::new(bytes.as_mut()),
        quota,
        frames,
        &mut sources.map(|source| source as &mut dyn Package<&mut [u8]>),
    );
    match result {
        Poll::Ready((size, min_size)) if size > 0 => {
            bytes.resize(size.max(min_size), 0);
            packet.padding(&mut bytes, min_size.saturating_sub(size));
            packet.seal(&mut bytes);
        }
        _ => bytes.clear(),
    }
    bytes
}

fn ping(keys: &ArcOneRttKeys, pn: u64) -> BytesMut {
    encode_packet(keys, pn, 1200, 1200, &mut Vec::new(), [&mut PingFrame])
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

#[tokio::test]
async fn zero_rtt_and_one_rtt_share_numbers_but_only_one_rtt_ack_confirms_keys() {
    use qbase::{frame::DatagramFrame, packet::LongHeaderBuilder};
    use qtransport::keys::Keys;

    let [(_client, ct, cp), (_server, st, sp)] = pair(1);
    let material = Arc::new(fixed_keys());
    let header = LongHeaderBuilder::with_cid(
        ConnectionId::from_slice(b"original"),
        ConnectionId::from_slice(b"clientid"),
    )
    .zero_rtt();
    let pn = ct.data.sent_journal.next_pn().unwrap();
    let mut packet = SendingPacket::new(
        DataHeader::Long(header.into()),
        pn,
        Keys::Long(material.clone()),
    );
    let mut bytes = BytesMut::zeroed(1200);
    let mut frames = Vec::new();
    let mut datagram = (
        DatagramFrame::new(true, 5u32.into()),
        Bytes::from_static(b"hello"),
    );

    assert!(matches!(packet.assemble(
        &mut Context::from_waker(std::task::Waker::noop()), &mut std::io::Cursor::new(bytes.as_mut()), 1200,
        &mut frames, &mut [&mut datagram, &mut PingFrame],
    ), Poll::Ready((n, _)) if n > 0));
    bytes.resize(packet.len(), 0);
    let generation = packet.seal(&mut bytes);
    assert_eq!(generation, None);
    assert_eq!(packet.meta.epoch(), Epoch::Data);
    let (_, received) = material
        .sealing
        .open(parse(&bytes), |_| Ok(pn.0), Duration::ZERO)
        .unwrap()
        .unwrap();
    let received: Vec<_> = received.map(|frame| frame.unwrap().0).collect();
    assert!(
        matches!(received.as_slice(), [Frame::Datagram(_, body), Frame::Ping(_)] if body.as_ref() == b"hello")
    );
    ct.data
        .sent_journal
        .on_sealed(pn.0, generation, bytes.len(), packet.meta, frames.drain(..));
    ct.data.sent_journal.on_sent(
        pn.0,
        packet.meta.in_flight,
        Duration::from_secs(1),
        Duration::from_secs(3),
    );

    let mut sender = Sender::new(ct.clone(), cp);
    sender.heartbeat();
    assert_eq!(receive(&st, &sp, &emit(&mut sender)), Some(1));
    assert_eq!(
        ct.data.sent_journal.on_acked(&ack(0), |_| {}).unwrap(),
        None
    );
    assert_eq!(
        ct.data.sent_journal.on_acked(&ack(1), |_| {}).unwrap(),
        Some(0)
    );
}

#[test]
fn header_protection_padding_obeys_quota_and_the_write_window() {
    use qbase::packet::HeaderSize;
    let ([client, _], _) = handshake();
    let keys = ArcOneRttKeys::from(client);
    let header = OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original"));
    let minimum = header.size() + 20;
    for (quota, length) in [(minimum - 1, minimum), (minimum, minimum - 1)] {
        let mut recorded = Vec::new();
        assert!(encode_packet(&keys, 0, quota, length, &mut recorded, [&mut PingFrame]).is_empty());
        assert_eq!(
            encode_packet(&keys, 0, minimum, minimum, &mut recorded, [&mut PingFrame]).len(),
            minimum
        );
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

fn close_packet(keys: &ArcOneRttKeys, pn: u64) -> BytesMut {
    let mut close = qbase::frame::ConnectionCloseFrame::from(Error::from(AppError::new(
        VarInt::from_u32(7),
        "peer closed",
    )));
    encode_packet(
        keys,
        pn,
        1200,
        1200,
        &mut Vec::new(),
        [&mut PingFrame, &mut close],
    )
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
        let facts = Arc::new(qbase::handshake::HandshakeFacts::with_role(Role::Server));
        facts.quit_mp_handshaking();
        let space = Arc::new(Space::new(
            epoch,
            Default::default(),
            ArcKeys::new(Arc::new(material)),
            facts,
        ));
        let ready = space.keys.get().unwrap();
        assert!(Arc::ptr_eq(&space.keys.get().unwrap(), &ready));
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
                  _: &Arc<Path>,
                  _: Link| {
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
            receive_packets(
                rcvd_pkt.initial,
                space.epoch,
                {
                    let keys = space.keys.clone();
                    move || keys.get().ok()
                },
                space.rcvd_journal.clone(),
                move |_, _| Some(received_path.clone()),
                |keys: &Arc<qtls::BidirectionalKeys>, packet, _| {
                    packet
                        .decrypt_long_packet(&keys.opening, |pn| space.rcvd_journal.decode_pn(pn))
                        .transpose()
                        .map_err(Into::into)
                },
                |_, _| Ok(()),
                dispatch,
                |_| panic!("receive failed"),
            )
            .await;
        } else {
            let received_path = path.clone();
            receive_packets(
                rcvd_pkt.handshake,
                space.epoch,
                {
                    let keys = space.keys.clone();
                    move || keys.get().ok()
                },
                space.rcvd_journal.clone(),
                move |_, _| Some(received_path.clone()),
                |keys: &Arc<qtls::BidirectionalKeys>, packet, _| {
                    packet
                        .decrypt_long_packet(&keys.opening, |pn| space.rcvd_journal.decode_pn(pn))
                        .transpose()
                        .map_err(Into::into)
                },
                |_, _| Ok(()),
                dispatch,
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
        assert!(matches!(space.keys.get(), Err(KeyRetired)));
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
    let original = router.insert(cid.into(), inbox.clone(), ());
    let alias_route = router.insert(alias.into(), inbox.clone(), ());
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
    original.retire_cid(cid);
    alias_route.retire_cid(alias);
    drop(original);
    drop(alias_route);
    drop(inbox);
    assert!(rcvd_pkt.initial.recv().await.is_none());
}

#[tokio::test]
async fn router_and_receive_deliver_streams_and_keep_close_receiving() {
    use qbase::net::route::Link;
    use tokio::io::AsyncReadExt;

    use crate::router::QuicRouter;
    let [(client, ct, cp), (_old_server, st, sp)] = pair(2);
    let close = qtransport::terminate::ArcTerminator::no_error();
    close.register(Arc::new(st.data.streams.clone()));
    let server = ArcConnection::new(
        Bytes::from_static(b"h3"),
        st.data.streams.clone(),
        close.clone(),
    );
    let close_seen = qbase::ArcReceiving::default();
    let close_sink = close_seen.clone();
    let streams_seen = Arc::new(AtomicUsize::new(0));
    let seen = streams_seen.clone();
    let router = Arc::new(QuicRouter::new());
    let (inbox, rcvd_pkt) = channel::new();
    let link = Link::new(
        "127.0.0.1:5500".parse().unwrap(),
        "127.0.0.1:4400".parse().unwrap(),
    );
    let cid = ConnectionId::from_slice(b"original");
    let route = router.insert(cid.into(), inbox.clone(), ());
    let journal = st.data.rcvd_journal.clone();
    let received = st.clone();
    let task = tokio::spawn(receive_packets(
        rcvd_pkt.one_rtt,
        Epoch::Data,
        {
            let keys = st.data.keys.clone();
            move || (!keys.is_retired()).then(|| keys.clone())
        },
        st.data.rcvd_journal.clone(),
        {
            let sp = sp.clone();
            move |_, _| Some(sp.clone())
        },
        move |keys: &ArcOneRttKeys, packet, _| {
            keys.open_packet(
                packet,
                |pn| journal.decode_pn(pn),
                sp.cc.get_pto(Epoch::Data),
            )
        },
        |_, _| Ok(()),
        move |_, epoch, frame, path, _| {
            if matches!(frame, Frame::Stream(_, _)) {
                seen.fetch_add(1, Ordering::Relaxed);
            }
            assert_eq!(epoch, Epoch::Data);
            if let Frame::Close(frame) = &frame {
                close_sink.recv_frame(frame.clone())?;
            }
            dispatch(&received, path, frame)
        },
        |_| panic!("receive failed"),
    ));
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"wired stream")).unwrap();
    let bytes = emit(&mut Sender::new(ct.clone(), cp));
    router.receive(bytes.clone(), link.into(), link, 8);
    router.receive(bytes, link.into(), link, 8);
    let (_, mut reader) = tokio::time::timeout(Duration::from_secs(2), server.accept_uni_stream())
        .await
        .unwrap()
        .unwrap();
    let mut body = [0; 12];
    reader.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"wired stream");
    // Application streams stop immediately; the receive engine still reports packets.
    server.close(VarInt::from_u32(0), "done");
    assert!(matches!(
        st.data.streams.accept_uni().await,
        Err(crate::Error::App(_))
    ));
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
    assert!(
        st.data
            .rcvd_journal
            .decode_pn(PacketNumber::encode(1, 0))
            .is_err()
    );
    route.retire_cid(cid);
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
    assert!(enqueue(
        &inbox,
        Packet::Data(parse(&close_packet(&keys(&ct), 3)))
    ));
    drop(inbox);
    let mut errors = 0;
    let mut ordinary = 0;
    let mut closes = 0;
    let mut processed = 0;
    receive_packets(
        rcvd_pkt.one_rtt,
        Epoch::Data,
        {
            let keys = st.data.keys.clone();
            move || (!keys.is_retired()).then(|| keys.clone())
        },
        st.data.rcvd_journal.clone(),
        |_, _| Some(sp.clone()),
        |keys: &ArcOneRttKeys, packet, _| {
            keys.open_packet(
                packet,
                |pn| st.data.rcvd_journal.decode_pn(pn),
                sp.cc.get_pto(Epoch::Data),
            )
        },
        |_, _| {
            processed += 1;
            Ok(())
        },
        |_, _, frame, _, _| {
            if matches!(frame, Frame::Close(_)) {
                closes += 1;
                Ok(())
            } else {
                ordinary += 1;
                Err(QuicError::with_default_fty(ErrorKind::Internal, "component failed").into())
            }
        },
        |error| {
            errors += 1;
            st.close(error);
        },
    )
    .await;
    assert_eq!((errors, ordinary, closes, processed), (2, 2, 2, 4));
    assert!(server.accept_uni_stream().await.is_err());
    assert_eq!(
        st.data.rcvd_journal.decode_pn(PacketNumber::encode(0, 0)),
        Ok(0)
    );
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
    let mut sender = Sender::new(ct.clone(), cp);
    let bytes = emit(&mut sender);
    let (_, frames) = st
        .data
        .keys
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
    let ([client, _], _) = handshake();
    let keys = ArcOneRttKeys::from(client);
    let mut recorded = Vec::new();
    let bytes = [Bytes::from(vec![1; 800])];
    let mut crypto = (
        qbase::frame::CryptoFrame::new(0u32.into(), 800u32.into()),
        bytes.as_slice(),
    );
    assert!(
        !encode_packet(
            &keys,
            0,
            1200,
            1200,
            &mut recorded,
            [&mut crypto, &mut PingFrame]
        )
        .is_empty()
    );
    assert!(matches!(recorded.as_slice(), [GuaranteedFrame::Crypto(frame)] if frame.len() == 800));
}

#[test]
fn earlier_sources_fill_the_packet_and_remaining_frames_stay_queued() {
    use qbase::frame::{MaxDataFrame, ReliableFrame, io::SendFrame};

    let mut reliable = ArcReliableFrames::with_capacity(600);
    reliable.send_frame((0..600).map(|i| {
        ReliableFrame::StreamCtl(StreamCtlFrame::MaxData(MaxDataFrame::new(
            VarInt::from_u32(1000 + i),
        )))
    }));
    let bytes = [Bytes::from_static(b"later")];
    let mut crypto = (
        qbase::frame::CryptoFrame::new(0u32.into(), 5u32.into()),
        bytes.as_slice(),
    );
    let ([client, _], _) = handshake();
    let keys = ArcOneRttKeys::from(client);
    let mut sent = Vec::new();
    for pn in 0..2 {
        let mut recorded = Vec::new();
        encode_packet(
            &keys,
            pn,
            1200,
            1200,
            &mut recorded,
            [&mut reliable, &mut crypto],
        );
        for frame in recorded.as_slice() {
            if let GuaranteedFrame::Reliable(qbase::frame::ReliableFrame::StreamCtl(
                StreamCtlFrame::MaxData(frame),
            )) = frame
            {
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
                    .iter()
                    .any(|frame| matches!(frame, GuaranteedFrame::Crypto(..)))
            );
        } else {
            assert!(matches!(recorded.last(), Some(GuaranteedFrame::Crypto(..))));
        }
    }
    assert_eq!(sent, (1000..1600).collect::<Vec<_>>());
}

#[tokio::test(start_paused = true)]
async fn sender_assembles_ack_path_crypto_reliable_then_streams() {
    use qbase::frame::{MaxDataFrame, PathChallengeFrame, ReliableFrame, io::SendFrame};
    use tokio::io::AsyncWriteExt;

    let [(client, ct, cp), (_server, st, _sp)] = pair(1);
    receive(&ct, &cp, &ping(&keys(&st), 0)).unwrap();
    tokio::time::advance(Duration::from_millis(100)).await;
    ct.data.crypto.writer().write_all(b"crypto").await.unwrap();
    cp.validation
        .recv_frame(PathChallengeFrame::random())
        .unwrap();
    ct.data
        .reliable_frames
        .send_frame([ReliableFrame::StreamCtl(StreamCtlFrame::MaxData(
            MaxDataFrame::new(4096u32.into()),
        ))]);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write_all(b"stream").await.unwrap();
    let mut sender = Sender::new(ct.clone(), cp);
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
            Frame::PathResponse(_),
            Frame::Crypto(..),
            Frame::StreamCtl(StreamCtlFrame::MaxData(_)),
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
    let mut cs = Sender::new(ct.clone(), cp.clone());
    let mut ss = Sender::new(st.clone(), sp.clone());
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
    let [(client, transport, _), _] = pair(0);
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
        transport
            .parameters
            .remote::<u64>(ParameterId::InitialMaxStreamsUni),
        0
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
        .data
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
    let [(_client, transport, _), (_server, peer, _)] = pair(1);
    let mut quota = 0;
    let mut length = 1200;
    let mut recorded = Vec::new();
    let bytes = encode_packet(
        &keys(&transport),
        0,
        quota,
        length,
        &mut recorded,
        [&mut ack(0), &mut PingFrame],
    );
    let (_, frames) = keys(&peer)
        .open(parse(&bytes), |_| Ok(0), Duration::ZERO)
        .unwrap()
        .unwrap();
    let frames: Vec<_> = frames.map(|frame| frame.unwrap().0).collect();
    assert!(matches!(frames.as_slice(), [Frame::Ack(_)]));
    quota = 1200;
    length = 10;
    assert!(
        encode_packet(
            &keys(&transport),
            1,
            quota,
            length,
            &mut recorded,
            [&mut ack(0)]
        )
        .is_empty()
    );
}

#[tokio::test]
async fn data_sources_respect_each_limit_without_consuming_unsent_bytes() {
    use tokio::io::AsyncWriteExt;

    for limited in 0..2 {
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
        let mut crypto = ct.data.crypto.outgoing();
        let mut streams = ct.data.streams.clone();
        let mut crypto_received = Vec::new();
        let mut stream_received = Vec::new();
        let sealing = keys(&ct);
        let opening = keys(&st);
        for pn in 0..32 {
            let mut recorded = Vec::new();
            let limit = if pn == 0 { 24 } else { 80 };
            let (quota, length) = if limited == 0 {
                (1200, limit)
            } else {
                (limit, 1200)
            };
            let bytes = encode_packet(
                &sealing,
                pn,
                quota,
                length,
                &mut recorded,
                [&mut crypto, &mut streams],
            );
            if pn == 0 {
                assert!(bytes.is_empty());
                assert!(recorded.is_empty());
                continue;
            }
            assert!(!recorded.is_empty());
            assert!(bytes.len() <= 80);
            let (_, frames) = opening
                .open(parse(&bytes), |_| Ok(pn), Duration::from_secs(1))
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
async fn empty_assembly_cancels_packet_reservations() {
    let [(_client, ct, cp), (_server, st, sp)] = pair(1);
    let mut sender = Sender::new(ct.clone(), cp);
    for _ in 0..5 {
        assert!(!sender.prepare().unwrap());
    }
    for pn in 0..5 {
        assert!(
            ct.data
                .sent_journal
                .on_acked(&ack(pn), |_| panic!("empty packet has recovery frames"))
                .is_err()
        );
    }
    sender.heartbeat();
    assert_eq!(receive(&st, &sp, &emit(&mut sender)), Some(5));
}

#[tokio::test]
async fn pending_packet_on_a_slow_path_keeps_its_number_and_key_generation() {
    let [(client, ct, cp), (_server, st, sp)] = pair(4);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"retained")).unwrap();
    let mut slow = Sender::new(ct.clone(), cp.clone());
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
    let mut fast = Sender::new(ct.clone(), other);
    fast.heartbeat();
    let fast_bytes = emit(&mut fast);
    assert_eq!(receive(&st, &sp, &fast_bytes), Some(1));
    let bytes = emit(&mut slow);
    assert_eq!(receive(&st, &sp, &bytes), Some(0));
    acknowledge(&ct, &ack(0), &cp).unwrap();
    let (_, mut reader) = st.data.streams.accept_uni().await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut output = [0; 8];
    reader.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"retained");
}

#[tokio::test]
async fn close_fails_business_apis_and_preserves_data_keys() {
    let [(client, ct, _), _] = pair(1);
    client.clone().close(VarInt::from_u32(0), "closed");
    assert!(ct.data.keys.get().is_ok());
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
async fn receiving_starts_with_ready_keys() {
    let (materials, _) = handshake();
    let [client, server] = materials;
    let ct = transport(Role::Client, client, 1);
    let cp = path(&ct, 0);
    let data = transport(Role::Server, server, 1).data.clone();
    let (inbox, rcvd_pkt) = channel::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let journal = data.rcvd_journal.clone();
    let task = tokio::spawn(receive_packets(
        rcvd_pkt.one_rtt,
        Epoch::Data,
        {
            let keys = data.keys.clone();
            move || (!keys.is_retired()).then(|| keys.clone())
        },
        data.rcvd_journal.clone(),
        {
            let cp = cp.clone();
            move |_, _| Some(cp.clone())
        },
        move |keys: &ArcOneRttKeys, packet, _| {
            keys.open_packet(
                packet,
                |pn| journal.decode_pn(pn),
                cp.cc.get_pto(Epoch::Data),
            )
        },
        |_, _| Ok(()),
        move |_, _, _, _, _| {
            seen.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        |_| panic!("receive failed"),
    ));
    assert!(enqueue(&inbox, Packet::Data(parse(&ping(&keys(&ct), 0)))));
    drop(inbox);
    task.await.unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn pipeline_rejection_does_not_ack_and_close_bypasses_business_delivery() {
    let [(_client, ct, _), (_server, st, sp)] = pair(1);
    let (inbox, packets) = channel::new();
    assert!(enqueue(&inbox, Packet::Data(parse(&ping(&keys(&ct), 0)))));
    assert!(enqueue(
        &inbox,
        Packet::Data(parse(&close_packet(&keys(&ct), 1)))
    ));
    assert!(enqueue(&inbox, Packet::Data(parse(&ping(&keys(&ct), 2)))));
    drop(inbox);
    let inspected = std::cell::Cell::new(0);
    let mut dispatched = 0;
    let mut errors = 0;
    receive_packets(
        packets.one_rtt,
        Epoch::Data,
        {
            let keys = st.data.keys.clone();
            move || (!keys.is_retired()).then(|| keys.clone())
        },
        st.data.rcvd_journal.clone(),
        |_, _| Some(sp.clone()),
        |keys, packet, _| {
            keys.open_packet(
                packet,
                |pn| st.data.rcvd_journal.decode_pn(pn),
                sp.cc.get_pto(Epoch::Data),
            )
        },
        |_, _| {
            inspected.set(inspected.get() + 1);
            Ok(())
        },
        |_, _, frame, _, _| {
            dispatched += 1;
            assert_eq!(inspected.get(), dispatched);
            match dispatched {
                1 => {
                    assert!(matches!(frame, Frame::Ping(_)));
                    return Err(
                        QuicError::with_default_fty(ErrorKind::Internal, "pipe full").into(),
                    );
                }
                2 => assert!(matches!(frame, Frame::Close(_))),
                3 => assert!(matches!(frame, Frame::Ping(_))),
                _ => panic!("frames carried over from a previous packet"),
            }
            Ok(())
        },
        |_| errors += 1,
    )
    .await;
    assert_eq!(dispatched, 3);
    assert_eq!(errors, 1);
    for pn in [0, 1] {
        assert_eq!(
            st.data.rcvd_journal.decode_pn(PacketNumber::encode(pn, 0)),
            Ok(pn)
        );
    }
    assert!(
        st.data
            .rcvd_journal
            .decode_pn(PacketNumber::encode(2, 0))
            .is_err()
    );
}

#[tokio::test]
async fn loss_returns_frames_to_sources_before_the_sender_runs() {
    use qbase::frame::{MaxDataFrame, io::SendFrame};
    use tokio::io::AsyncWriteExt;

    let [(client, ct, cp), _] = pair(1);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"stream")).unwrap();
    ct.data.crypto.writer().write_all(b"crypto").await.unwrap();
    ct.data
        .reliable_frames
        .send_frame([StreamCtlFrame::MaxData(MaxDataFrame::new(123u32.into()))]);
    let mut sender = Sender::new(ct.clone(), cp);
    emit(&mut sender);
    drop(sender);

    ct.data.resend(
        qevent::quic::recovery::PacketLostTrigger::TimeThreshold,
        &mut [0, 0].into_iter(),
    );
    // Read the components directly: no Sender or timer may extract journal work first.
    let mut frames = Vec::new();
    let mut crypto = ct.data.crypto.outgoing();
    let mut reliable = ct.data.reliable_frames.clone();
    let mut streams = ct.data.streams.clone();
    encode_packet(
        &keys(&ct),
        1,
        1200,
        1200,
        &mut frames,
        [&mut crypto, &mut reliable, &mut streams],
    );
    assert!(matches!(frames.as_slice(),
        [GuaranteedFrame::Crypto(_), GuaranteedFrame::Reliable(qbase::frame::ReliableFrame::StreamCtl(StreamCtlFrame::MaxData(f))), GuaranteedFrame::Stream(_)]
        if f.max_data() == 123));
}

#[tokio::test]
async fn late_ack_clears_requeued_stream_and_crypto_before_the_sender_runs() {
    use tokio::io::AsyncWriteExt;

    let [(client, ct, cp), _] = pair(1);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"stream")).unwrap();
    ct.data.crypto.writer().write_all(b"crypto").await.unwrap();
    let mut sender = Sender::new(ct.clone(), cp.clone());
    emit(&mut sender);
    ct.data.resend(
        qevent::quic::recovery::PacketLostTrigger::TimeThreshold,
        &mut [0].into_iter(),
    );
    acknowledge(&ct, &ack(0), &cp).unwrap();
    assert!(!sender.prepare().unwrap());
}

#[tokio::test]
async fn loss_requeues_stream_ranges_and_late_ack_does_not_duplicate_delivery() {
    let [(client, ct, cp), (server, st, sp)] = pair(2);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"lost once")).unwrap();
    let mut sender = Sender::new(ct.clone(), cp.clone());
    let dropped = emit(&mut sender);
    ct.data.resend(
        qevent::quic::recovery::PacketLostTrigger::TimeThreshold,
        &mut [0].into_iter(),
    );
    let retry = emit(&mut sender);
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
    let old_sender = Sender::new(ct.clone(), cp.clone());
    cp.close();
    let replacement = path(&ct, 0);
    let mut sender = Sender::new(ct.clone(), replacement.clone());
    drop(old_sender);
    assert!(cp.validation.is_cancelled());
    assert!(!Arc::ptr_eq(&cp, &replacement));
    sender.heartbeat();
    assert!(!emit(&mut sender).is_empty());
}

#[tokio::test(start_paused = true)]
async fn connection_tick_recovers_after_the_original_path_and_sender_are_dropped() {
    use qcongestion::Transport as _;

    use crate::space::Recover as _;

    let [(client, transport, original), (server, peer, peer_path)] = pair(1);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"retired path")).unwrap();
    let (retransmit_after, _) = original.cc.retransmit_and_expire_time(Epoch::Data);
    let mut sender = Sender::new(transport.clone(), original.clone());
    emit(&mut sender);
    original.close();
    drop(sender);
    drop(original);
    // Path retirement alone must not make the stream range available again.
    let mut streams = transport.data.streams.clone();
    assert!(take_frames(&mut streams).is_empty());
    transport.data.on_tick(tokio::time::Instant::now());
    assert!(take_frames(&mut streams).is_empty());

    tokio::time::advance(retransmit_after).await;
    transport.data.on_tick(tokio::time::Instant::now());
    let replacement = path(&transport, 1);
    let mut sender = Sender::new(transport.clone(), replacement.clone());
    assert_eq!(receive(&peer, &peer_path, &emit(&mut sender)), Some(1));
    transport.data.on_tick(tokio::time::Instant::now());
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
    let mut sender = Sender::new(ct.clone(), cp.clone());
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
    let mut bi = std::pin::pin!(client.accept_bi_stream());
    let mut uni = std::pin::pin!(client.accept_uni_stream());
    let mut open_bi = std::pin::pin!(client.open_bi_stream());
    let mut open_uni = std::pin::pin!(client.open_uni_stream());
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
    let path = Arc::new(Path::new(
        pathway,
        confirmed_handshake(Role::Client),
        path_heartbeat(),
        data_trackers(&ct),
        qbase::cid::ArcRemoteCids::client(
            Default::default(),
            qtransport::ArcReliableFrames::with_capacity(0),
        )
        .apply_dcid(),
    ));
    path.validation.enter_validated().unwrap();
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"udp payload")).unwrap();
    let mut sender = Sender::new(ct.clone(), path);
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
    let mut sender = Sender::new(transport.clone(), path.clone());
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
async fn path_validation_replies_on_ingress_and_allows_data_within_credit() {
    let [(client, ct, cp), (server, st, sp)] = pair(2);
    let paths = [(&ct, cp.pathway), (&st, sp.pathway)].map(|(transport, pathway)| {
        Arc::new(Path::new(
            pathway,
            confirmed_handshake(transport.parameters.role()),
            path_heartbeat(),
            data_trackers(transport),
            qbase::cid::ArcRemoteCids::client(
                Default::default(),
                qtransport::ArcReliableFrames::with_capacity(0),
            )
            .apply_dcid(),
        ))
    });
    let [cp, sp] = paths;
    cp.validation.on_received(400);
    let challenge_frame = qbase::frame::PathChallengeFrame::random();
    cp.validation.challenge(challenge_frame).unwrap();
    let waiting = cp.validation.respond();
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"validated")).unwrap();
    let mut cs = Sender::new(ct.clone(), cp.clone());
    let mut ss = Sender::new(st.clone(), sp.clone());
    let challenge = emit(&mut cs);
    assert_eq!(challenge.len(), 1200);
    assert_eq!(sp.validation.credit().unwrap().unwrap(), 0);
    receive(&st, &sp, &challenge);
    let (_, mut reader) = server.accept_uni_stream().await.unwrap();
    let response = emit(&mut ss);
    assert_eq!(response.len(), 1200);
    assert_eq!(sp.validation.credit().unwrap().unwrap(), 2400);
    receive(&ct, &cp, &response);
    assert_eq!(waiting.await.unwrap(), Some(challenge_frame.into()));
    cp.validation.enter_validated().unwrap();
    assert!(cp.validation.is_validated());
    use tokio::io::AsyncReadExt;
    let mut body = [0; 9];
    reader.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"validated");
}

#[tokio::test(start_paused = true)]
async fn shared_ack_only_updates_the_receiving_paths_congestion_control() {
    use qcongestion::Transport as _;
    let [(_client, transport, first), _] = pair(1);
    let second = path(&transport, 1);
    let mut first_sender = Sender::new(transport.clone(), first.clone());
    let mut second_sender = Sender::new(transport.clone(), second.clone());
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
    let mut sender = Sender::new(ct.clone(), cp);
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
        crate::keys::ArcKeys::new(Arc::new(fixed_keys())),
        Arc::new(qbase::handshake::HandshakeFacts::with_role(Role::Server)),
    ));
    let mut task = tokio::spawn(receive_packets(
        rcvd_pkt.initial,
        space.epoch,
        {
            let keys = space.keys.clone();
            move || keys.get().ok()
        },
        space.rcvd_journal.clone(),
        |_, _| unreachable!(),
        |_: &Arc<qtls::BidirectionalKeys>, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_, _, _, _, _| unreachable!(),
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

#[tokio::test]
async fn sealing_does_not_wait_for_socket_submission() {
    let [(_client, transport, path), _] = pair(1);
    let keys = transport.data.keys.clone();
    let mut sender = Sender::new(transport, path);
    sender.heartbeat();
    assert!(sender.prepare().unwrap());
    let (start, started) = std::sync::mpsc::channel();
    let (sealed, completed) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        started.recv().unwrap();
        ping(&keys, 1);
        sealed.send(()).unwrap();
    });
    assert!(matches!(
        sender.poll_send_with(
            &mut Context::from_waker(futures::task::noop_waker_ref()),
            |_, _, bytes| {
                start.send(()).unwrap();
                completed.recv_timeout(Duration::from_secs(1)).unwrap();
                Poll::Ready(Ok(bytes.len()))
            },
        ),
        Poll::Ready(Ok(true))
    ));
    worker.join().unwrap();
}

fn confirmed_handshake(role: Role) -> Arc<qbase::handshake::HandshakeFacts> {
    let handshake = Arc::new(qbase::handshake::HandshakeFacts::with_role(role));
    handshake.on_handshake_done();
    handshake.quit_mp_handshaking();
    handshake
}
