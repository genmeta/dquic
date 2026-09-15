use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{AppError, ErrorKind},
    flow::FlowController,
    frame::{AckFrame, Frame, MaxStreamsFrame, PingFrame, StreamCtlFrame, io::ReceiveFrame},
    net::{addr::EndpointAddr, route::Pathway, tx::ArcSendWakers},
    packet::{DataPacket, OneRttHeader, Packet, PacketNumber, PacketReader},
    param::{
        ParameterId,
        handy::{client_parameters, server_parameters},
    },
    sid::{Dir, handy::DemandConcurrency},
};
use qcongestion::{Feedback, HandshakeStatus};
use qrecovery::streams::DataStreams;
use tls_backend::pki_types::pem::PemObject;

use crate::{
    control::Control,
    keys::ArcOneRttKeys,
    path::{Path, Paths},
    recv::{open_packet, receive_packet, run_receive},
    send::{
        Sender,
        constraints::Constraints,
        packet::{OneRttPacket, PacketError},
    },
    space::Space,
    transport::Transport,
    *,
};

const CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

#[derive(Debug)]
struct Authority(Option<qtls::LocalAuthority>);
impl qtls::ResolveServerAuthority for Authority {
    fn resolve(&self, _: qtls::ServerCredentialRequest<'_>) -> Option<qtls::LocalAuthority> {
        self.0.clone()
    }
}
impl qtls::ResolveClientAuthority for Authority {
    fn resolve(&self, _: qtls::ClientCertificateRequest<'_>) -> Option<qtls::LocalAuthority> {
        None
    }
    fn has_authority(&self) -> bool {
        false
    }
}
#[derive(Debug)]
struct Pinned;
impl qtls::VerifyIdentity for Pinned {
    fn verify(
        &self,
        expected: Option<&str>,
        certificates: &[qtls::CertificateDer<'_>],
        _: Option<&[u8]>,
        _: qtls::UnixTime,
    ) -> Result<Option<Arc<str>>, qtls::CertificateError> {
        if expected != Some("localhost")
            || certificates != [qtls::CertificateDer::from_pem_slice(CERT).unwrap()]
        {
            return Err(qtls::CertificateError::ApplicationVerificationFailure);
        }
        Ok(Some("localhost".into()))
    }
}

pub(crate) fn handshake() -> ([qtls::OneRttKeyMaterial; 2], [qtls::HandshakeSummary; 2]) {
    let provider = Arc::new(tls_backend::crypto::ring::default_provider());
    let server = qtls::LocalAuthority::new(
        &provider,
        "localhost".into(),
        vec![qtls::CertificateDer::from_pem_slice(CERT).unwrap()],
        qtls::PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        None,
    )
    .unwrap();
    let client = qtls::ClientTlsEndpoint::new(qtls::ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec(), b"ssh".to_vec()],
        resolve_local: Arc::new(Authority(None)),
        verify_server: Arc::new(Pinned),
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let server = qtls::ServerTlsEndpoint::new(qtls::ServerTlsConfig {
        provider,
        alpn: vec![b"ssh".to_vec(), b"h3".to_vec()],
        resolve_local: Arc::new(Authority(Some(server))),
        verify_client: None,
        resumption: qtls::ServerResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
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
    let control = Arc::new(Control::new(Arc::new(Mutex::new(()))));
    let material = ArcOneRttKeys::new_pending(control.clone());
    material.install(keys).unwrap();
    material.confirm_handshake();
    let data = Arc::new(Space::new(
        Epoch::Data,
        material,
        control.clone(),
        wakers.clone(),
    ));
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
    let flow = FlowController::new(
        params.remote(ParameterId::InitialMaxData).unwrap(),
        params.local(ParameterId::InitialMaxData).unwrap(),
        reliable.clone(),
        wakers,
    );
    control.enable_receiving();
    control.enable_sending();
    Arc::new(Transport::new(
        data,
        params,
        streams,
        flow,
        reliable,
        Arc::new(Paths::default()),
    ))
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
        let conn = ArcConnection::new(transport.clone(), summary.alpn.unwrap()).unwrap();
        (conn, transport, path)
    })
    .collect::<Vec<_>>()
    .try_into()
    .ok()
    .unwrap()
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
    let feedback: Arc<dyn Feedback> = transport.data.clone();
    let path = Arc::new(Path::new(
        pathway,
        ConnectionId::from_slice(b"original"),
        status,
        Duration::from_millis(25),
        [feedback.clone(), feedback.clone(), feedback],
        transport.data.control.submission.clone(),
    ));
    path.validate();
    assert!(transport.paths.insert(path.clone()));
    path
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
            return Err(crate::error(
                ErrorKind::ProtocolViolation,
                "unexpected test frame",
            ));
        }
    }
    Ok(())
}
fn receive(transport: &Arc<Transport>, path: &Arc<Path>, bytes: &[u8]) -> Option<u64> {
    let (pn, frames) = open_packet(
        parse(bytes),
        &transport.data.keys,
        &transport.data.rcvd_packets,
        Duration::from_secs(1),
    )
    .unwrap()?;
    receive_packet(
        pn,
        frames,
        &transport.data,
        path,
        |_, frame, path| dispatch(transport, path, frame),
        |_, _| Ok(()),
    )
    .unwrap();
    Some(pn)
}
fn acknowledge(transport: &Transport, ack: &AckFrame, path: &Arc<Path>) -> Result<(), Error> {
    send::acknowledge(
        &transport.data,
        &transport.streams,
        &transport.parameters,
        ack,
        path,
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
fn ping(keys: &ArcOneRttKeys, pn: u64) -> BytesMut {
    let mut packet = OneRttPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        pn,
        16,
    )
    .unwrap();
    packet
        .assemble(
            &mut Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            [&mut PingFrame],
        )
        .unwrap();
    packet.seal(keys).unwrap().bytes
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
    let mut sender = Sender::new(ct.clone(), cp).unwrap();
    let bytes = emit(&mut sender);
    let (_, frames) = open_packet(
        parse(&bytes),
        &st.data.keys,
        &st.data.rcvd_packets,
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
fn source_quota_does_not_starve_a_single_frame_that_fits_the_packet() {
    let mut packet = OneRttPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        0,
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
            &mut Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            [&mut crypto, &mut PingFrame],
        )
        .unwrap();
    assert!(matches!(packet.frames(), [Frame::Crypto(frame, ())] if frame.len() == 800));
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
    let mut cs = Sender::new(ct.clone(), cp.clone()).unwrap();
    let mut ss = Sender::new(st.clone(), sp.clone()).unwrap();
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
async fn missing_alpn_and_unready_keys_cannot_be_delivered() {
    let [(_client, transport, _), _] = pair(1);
    assert!(ArcConnection::new(transport.clone(), Bytes::new()).is_err());
    transport.data.keys.invalid();
    assert!(ArcConnection::new(transport, Bytes::from_static(b"h3")).is_err());
}

#[tokio::test]
async fn duplicate_skips_authentication_and_forgery_is_not_committed() {
    let [(_client, ct, _), (_server, st, sp)] = pair(1);
    let bytes = ping(&ct.data.keys, 0);
    assert_eq!(receive(&st, &sp, &bytes), Some(0));
    assert_eq!(receive(&st, &sp, &bytes), None);
    let mut forged = ping(&ct.data.keys, 1);
    let index = forged.len() - 1;
    forged[index] ^= 1;
    assert!(
        open_packet(
            parse(&forged),
            &st.data.keys,
            &st.data.rcvd_packets,
            Duration::from_secs(1)
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        st.data.rcvd_packets.decode_pn(PacketNumber::encode(1, 0)),
        Ok(1)
    );
    let ([client, server], _) = handshake();
    let ct = transport(Role::Client, client, 1);
    let bytes = ping(&ct.data.keys, 0);
    let journal = qrecovery::journal::ArcRcvdJournal::with_capacity(0, None);
    journal.on_rcvd_pn(0, true, Duration::ZERO);
    let called = AtomicUsize::new(0);
    let opened = crate::recv::open_with(
        parse(&bytes),
        &server.opening_header,
        &journal,
        |pn, _, header, body| {
            called.fetch_add(1, Ordering::Relaxed);
            Ok(server
                .opening
                .current()
                .open(pn, header, body)
                .ok()
                .map(|plain| plain.len()))
        },
    )
    .unwrap();
    assert!(opened.is_none());
    assert_eq!(called.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn packet_constraints_keep_ack_only_outside_cwnd_but_inside_amplification_budget() {
    let (keys, _) = handshake();
    let [client, _] = keys;
    let transport = transport(Role::Client, client, 1);
    let mut packet = OneRttPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        0,
        16,
    )
    .unwrap();
    let mut constraints = Constraints {
        capacity: 1200,
        congestion: 0,
        anti_amplification: 1200,
    };
    packet
        .assemble(&mut constraints, [&mut ack(0), &mut PingFrame])
        .unwrap();
    assert!(packet.pad_to(1200, &mut constraints).is_err());
    let packet = packet.seal(&transport.data.keys).unwrap();
    assert!(!packet.in_flight);
    assert_eq!(constraints.congestion, 0);
    let mut packet = OneRttPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        1,
        16,
    )
    .unwrap();
    assert!(matches!(
        packet.assemble(
            &mut Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 10
            },
            [&mut ack(0)]
        ),
        Err(PacketError::Blocked(_))
    ));
}

#[tokio::test]
async fn pending_packet_overtaken_on_another_path_is_requeued_with_a_new_number() {
    let [(client, ct, cp), (_server, st, sp)] = pair(4);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"retained")).unwrap();
    let mut slow = Sender::new(ct.clone(), cp.clone()).unwrap();
    assert!(slow.prepare().unwrap());
    assert!(
        slow.poll_send_with(
            &mut Context::from_waker(futures::task::noop_waker_ref()),
            |_, _, _| Poll::Pending
        )
        .is_pending()
    );
    let other = path(&ct, 1);
    let mut fast = Sender::new(ct.clone(), other).unwrap();
    fast.heartbeat();
    let fast_bytes = emit(&mut fast);
    assert_eq!(receive(&st, &sp, &fast_bytes), Some(1));
    assert!(matches!(
        slow.poll_send_with(
            &mut Context::from_waker(futures::task::noop_waker_ref()),
            |_, _, _| panic!("obsolete packet submitted")
        ),
        Poll::Ready(Ok(false))
    ));
    let bytes = emit(&mut slow);
    assert_eq!(receive(&st, &sp, &bytes), Some(2));
    assert!(
        acknowledge(&ct, &ack(0), &cp).is_err(),
        "unsent PN must not be ACKed"
    );
    let (_, mut reader) = st.streams.accept_uni().await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut output = [0; 8];
    reader.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"retained");
}

#[tokio::test]
async fn close_and_key_retirement_reject_pending_socket_submission() {
    let [(client, ct, cp), _] = pair(1);
    let mut sender = Sender::new(ct.clone(), cp).unwrap();
    sender.heartbeat();
    assert!(sender.prepare().unwrap());
    client.close(VarInt::from_u32(0), "closed");
    assert!(matches!(
        sender.poll_send_with(
            &mut Context::from_waker(futures::task::noop_waker_ref()),
            |_, _, _| panic!("sent after close")
        ),
        Poll::Ready(Ok(false))
    ));
}

#[tokio::test(start_paused = true)]
async fn peer_key_update_is_authenticated_before_installing_and_old_keys_expire() {
    let [(_client, ct, cp), (_server, st, sp)] = pair(1);
    let old = ping(&ct.data.keys, 0);
    let later_old = ping(&ct.data.keys, 1);
    ct.data.keys.on_ack(0);
    ct.data.keys.update().unwrap();
    let next = ping(&ct.data.keys, 2);
    let mut forged = next.clone();
    let index = forged.len() - 1;
    forged[index] ^= 1;
    assert!(receive(&st, &sp, &forged).is_none());
    assert_eq!(receive(&st, &sp, &old), Some(0));
    assert_eq!(receive(&st, &sp, &next), Some(2));
    // Independent sealing cursor responds to the peer's generation without reusing a PN.
    let response = ping(&st.data.keys, 0);
    assert_eq!(receive(&ct, &cp, &response), Some(0));
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(receive(&st, &sp, &later_old).is_none());
}

#[tokio::test]
async fn receiving_waits_for_keys_and_gate_without_a_command_queue() {
    let (keys, _) = handshake();
    let [client, server] = keys;
    let ct = transport(Role::Client, client, 1);
    let cp = path(&ct, 0);
    let control = Arc::new(Control::new(Arc::new(Mutex::new(()))));
    let opening = ArcOneRttKeys::new_pending(control.clone());
    let space = Arc::new(Space::new(
        Epoch::Data,
        opening.clone(),
        control.clone(),
        Default::default(),
    ));
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let task = tokio::spawn(run_receive(
        rx,
        space,
        move |_, _, _| {
            seen.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        |_, _| Ok(()),
        |_| panic!("receive failed"),
    ));
    tx.send((parse(&ping(&ct.data.keys, 0)), cp)).await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    opening.install(server).unwrap();
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    control.enable_receiving();
    drop(tx);
    task.await.unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    control.stop_receiving();
    control.enable_receiving();
    assert!(!control.receiving().await);
}

#[tokio::test]
async fn pipeline_rejection_does_not_ack_and_close_bypasses_business_delivery() {
    let [(_client, ct, _), (_server, st, sp)] = pair(1);
    let bytes = ping(&ct.data.keys, 0);
    let (pn, frames) = open_packet(
        parse(&bytes),
        &st.data.keys,
        &st.data.rcvd_packets,
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
            |_, _, _| Err(crate::error(ErrorKind::Internal, "pipe full")),
            |_, _| Ok(())
        )
        .is_err()
    );
    assert_eq!(
        st.data.rcvd_packets.decode_pn(PacketNumber::encode(pn, 0)),
        Ok(pn)
    );
    let mut packet = OneRttPacket::new(
        BytesMut::zeroed(1200),
        OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
        1,
        16,
    )
    .unwrap();
    let mut close = qbase::frame::ConnectionCloseFrame::from(Error::from(AppError::new(
        VarInt::from_u32(7),
        "peer",
    )));
    packet
        .assemble(
            &mut Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            [&mut PingFrame, &mut close],
        )
        .unwrap();
    let bytes = packet.seal(&ct.data.keys).unwrap();
    let (pn, frames) = open_packet(
        parse(bytes.bytes()),
        &st.data.keys,
        &st.data.rcvd_packets,
        Duration::from_secs(1),
    )
    .unwrap()
    .unwrap();
    receive_packet(
        pn,
        frames,
        &st.data,
        &sp,
        |_, frame, _| {
            assert!(matches!(frame, Frame::Close(_)));
            Ok(())
        },
        |_, _| Ok(()),
    )
    .unwrap();
}

#[tokio::test]
async fn loss_requeues_stream_ranges_without_charging_flow_credit_twice() {
    let [(client, ct, cp), (server, st, sp)] = pair(2);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"lost once")).unwrap();
    let mut sender = Sender::new(ct.clone(), cp.clone()).unwrap();
    let dropped = emit(&mut sender);
    let credit = ct.flow.sender.credit(usize::MAX).unwrap().available();
    ct.data.may_loss(
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
    let old_sender = Sender::new(ct.clone(), cp.clone()).unwrap();
    assert!(Sender::new(ct.clone(), cp.clone()).is_err());
    assert!(ct.paths.remove(&cp));
    let replacement = path(&ct, 0);
    let mut sender = Sender::new(ct.clone(), replacement.clone()).unwrap();
    assert!(!ct.paths.remove(&cp));
    drop(old_sender);
    assert!(Arc::ptr_eq(
        &ct.paths.get(&replacement.pathway).unwrap(),
        &replacement
    ));
    sender.heartbeat();
    assert!(!emit(&mut sender).is_empty());
}

#[tokio::test]
async fn connection_close_preserves_completed_streams_and_errors_active_streams() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let [(client, ct, cp), (server, st, sp)] = pair(3);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write_all(b"unread").await.unwrap();
    let mut shutdown = Box::pin(writer.shutdown());
    assert!(futures::poll!(&mut shutdown).is_pending());
    let mut sender = Sender::new(ct.clone(), cp.clone()).unwrap();
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
    let feedback: Arc<dyn Feedback> = ct.data.clone();
    let path = Arc::new(Path::new(
        pathway,
        ConnectionId::from_slice(b"original"),
        status,
        Duration::from_millis(25),
        [feedback.clone(), feedback.clone(), feedback],
        ct.data.control.submission.clone(),
    ));
    path.validate();
    ct.paths.insert(path.clone());
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"udp payload")).unwrap();
    let mut sender = Sender::new(ct.clone(), path).unwrap();
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
    let mut sender = Sender::new(transport.clone(), path.clone()).unwrap();
    sender.heartbeat();
    assert!(sender.prepare().unwrap());
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let worker = {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            acknowledge(&transport, &ack(0), &path)
        })
    };
    assert!(matches!(
        sender.poll_send_with(
            &mut Context::from_waker(futures::task::noop_waker_ref()),
            |_, _, bytes| {
                barrier.wait();
                Poll::Ready(Ok(bytes.len()))
            }
        ),
        Poll::Ready(Ok(true))
    ));
    assert!(worker.join().unwrap().is_ok());
}

#[tokio::test]
async fn path_validation_replies_on_ingress_and_withholds_stream_data_until_validated() {
    let [(client, ct, cp), (server, st, sp)] = pair(2);
    let paths = [(&ct, cp.pathway), (&st, sp.pathway)].map(|(transport, pathway)| {
        let status = Arc::new(HandshakeStatus::new(
            transport.parameters.role() == Role::Server,
        ));
        status.handshake_confirmed();
        let feedback: Arc<dyn Feedback> = transport.data.clone();
        Arc::new(Path::new(
            pathway,
            ConnectionId::from_slice(b"original"),
            status,
            Duration::from_millis(25),
            [feedback.clone(), feedback.clone(), feedback],
            transport.data.control.submission.clone(),
        ))
    });
    let [cp, sp] = paths;
    cp.grant_amplification();
    cp.start_validation();
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.write(Bytes::from_static(b"validated")).unwrap();
    let mut cs = Sender::new(ct.clone(), cp.clone()).unwrap();
    let mut ss = Sender::new(st.clone(), sp.clone()).unwrap();
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
    let feedback: Arc<dyn Feedback> = transport.data.clone();
    let path = Arc::new(Path::new(
        original.pathway,
        original.dcid(),
        handshake,
        Duration::from_millis(25),
        [feedback.clone(), feedback.clone(), feedback],
        transport.data.control.submission.clone(),
    ));
    path.on_datagram_received(400);
    path.start_validation();
    let mut sender = Sender::new(transport, path.clone()).unwrap();
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
async fn shared_ack_keeps_its_largest_pn_for_path_rtt_sampling() {
    let [(_client, transport, first), _] = pair(1);
    let second = path(&transport, 1);
    let mut first_sender = Sender::new(transport.clone(), first.clone()).unwrap();
    let mut second_sender = Sender::new(transport.clone(), second.clone()).unwrap();
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
}

#[tokio::test]
async fn resetting_one_stream_does_not_close_the_connection() {
    let [(client, ct, cp), (server, st, sp)] = pair(2);
    let (_, mut writer) = client.open_uni_stream().await.unwrap().unwrap();
    writer.cancel(17);
    let mut sender = Sender::new(ct.clone(), cp).unwrap();
    receive(&st, &sp, &emit(&mut sender));
    let (_, mut reader) = server.accept_uni_stream().await.unwrap();
    assert!(matches!(
        futures::StreamExt::next(&mut reader).await,
        Some(Err(StreamError::Reset(_)))
    ));
    assert!(client.open_uni_stream().await.unwrap().is_some());
    assert!(server.open_uni_stream().await.unwrap().is_some());
}
