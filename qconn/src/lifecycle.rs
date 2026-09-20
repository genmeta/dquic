use std::{
    collections::BTreeMap,
    future::{pending, poll_fn},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use qbase::{
    ArcReceiving, Epoch,
    cid::{ArcCidCell, ArcLocalCids, ArcRemoteCids, ConnectionId},
    error::{Error, ErrorKind, QuicError},
    flow::{ArcRecvController, ArcSendControler, FlowController},
    frame::{
        AckFrame, ConnectionCloseFrame, Frame, HandshakeDoneFrame, PingFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
        tx::{ArcSendWakers, Signals},
    },
    packet::{
        DataHeader, GetScid, LongHeaderBuilder, OneRttHeader, PacketContent, io::Repeat, long,
    },
    param::{ClientParameters, ParameterId, ServerParameters},
    role::Role,
    sid::handy::ConsistentConcurrency,
    time::ArcConnIdle,
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
    varint::VarInt,
};
use qcongestion::{HandshakeStatus, Transport as _};
use qrecovery::{crypto::CryptoStream, streams::DataStreams};
use qtransport::{
    ArcConnection, ArcParameters, CloseReason, GuaranteedFrame, ReliableFrames,
    keys::{ArcKeys, ArcOneRttKeys, OneRttKeys, OpenPacket},
    path::{Path, PathState, Paths},
    recv,
    router::{PACKET_QUEUE_CAPACITY, ReceivedPacket},
    send::{Sender, constraints::Constraints, write::PendingPacket},
    space::{ArcFeedback, Space},
    transport::Transport,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    Connected, Endpoint, LocalAuthority, RemoteAuthority,
    connection::Connection,
    handshake::{IssuedCids, connect::connect_initial, incoming::Incoming, tls_error},
    network::Network,
};

fn remote_authority(remote: qtls::RemoteAuthority) -> RemoteAuthority {
    RemoteAuthority::new(
        &rustls::crypto::ring::default_provider(),
        remote.name(),
        remote.certificates().to_vec(),
        None,
    )
}

pub(crate) async fn run_client(
    network: Arc<Network>,
    endpoint: Option<Endpoint>,
    name: String,
    cancel: CancellationToken,
    reply: oneshot::Sender<Result<Connected, Error>>,
) {
    let local_cid = ConnectionId::random_gen(8);
    let original_dcid = ConnectionId::random_gen(8);
    let prepared = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(crate::internal("connect cancelled")),
        _ = network.stop.cancelled() => Err(crate::internal("network stopped")),
        prepared = connect_initial(&network, endpoint.as_ref(), &name, local_cid, original_dcid) => prepared,
    };
    let (connecting, keys, paths, timeout, started) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = reply.send(Err(error));
            return;
        }
    };
    let (packets, inbox) = mpsc::channel(PACKET_QUEUE_CAPACITY);
    if !network.router.insert(local_cid, packets.clone()) {
        let _ = reply.send(Err(crate::internal("local connection ID collision")));
        return;
    }
    let mut reply = Some(reply);
    let outcome = drive(
        network.clone(),
        Connection::Connecting(Box::new(connecting)),
        Role::Client,
        keys,
        local_cid,
        original_dcid,
        packets.clone(),
        inbox,
        paths,
        timeout,
        started,
        cancel,
        endpoint,
        &mut reply,
        None,
    );
    let result = std::panic::AssertUnwindSafe(outcome).catch_unwind().await;
    network.router.remove_connection(&packets);
    if let Some(reply) = reply {
        let error = match result {
            Ok(error) => error,
            Err(_) => crate::internal("connection task panicked"),
        };
        let _ = reply.send(Err(error));
    }
}

pub(crate) async fn run_server(
    network: Arc<Network>,
    original_dcid: ConnectionId,
    inbox: mpsc::Receiver<ReceivedPacket>,
    received_at: Instant,
    matured: mpsc::Sender<tokio::task::Id>,
) {
    let packets = network
        .router
        .get(&original_dcid)
        .expect("queued Initial owns its route");
    let keys = match network
        .initial
        .initial_keys(qtls::QuicVersion::V1, &original_dcid)
    {
        Ok(keys) => keys,
        Err(_) => {
            network.router.remove_connection(&packets);
            return;
        }
    };
    let local_cid = loop {
        let cid = ConnectionId::random_gen(8);
        if network.router.insert(cid, packets.clone()) {
            break cid;
        }
    };
    let timeout = network.listener.idle_timeout();
    let mut reply = None;
    let outcome = drive(
        network.clone(),
        Connection::Incoming(Incoming::default()),
        Role::Server,
        keys,
        local_cid,
        original_dcid,
        packets.clone(),
        inbox,
        Vec::new(),
        timeout,
        received_at,
        CancellationToken::new(),
        None,
        &mut reply,
        Some(matured),
    );
    let _ = std::panic::AssertUnwindSafe(outcome).catch_unwind().await;
    network.router.remove_connection(&packets);
}

/// One owner advances phases. All cross-phase components below outlive the TLS variant.
#[allow(clippy::too_many_arguments)]
async fn drive(
    network: Arc<Network>,
    mut connection: Connection,
    role: Role,
    initial_keys: qtls::BidirectionalKeys,
    local_cid: ConnectionId,
    original_dcid: ConnectionId,
    packets: mpsc::Sender<ReceivedPacket>,
    inbox: mpsc::Receiver<ReceivedPacket>,
    candidates: Vec<Pathway>,
    timeout: Duration,
    received_at: Instant,
    cancel: CancellationToken,
    endpoint: Option<Endpoint>,
    reply: &mut Option<oneshot::Sender<Result<Connected, Error>>>,
    matured: Option<mpsc::Sender<tokio::task::Id>>,
) -> Error {
    let wakers = ArcSendWakers::new();
    let crypto = Epoch::EPOCHS.map(|_| CryptoStream::new(wakers.clone()));
    let initial = long_space(Epoch::Initial, crypto[0].clone(), wakers.clone());
    initial
        .keys
        .install(Arc::new(initial_keys))
        .expect("new Initial keys");
    let handshake = long_space(Epoch::Handshake, crypto[1].clone(), wakers.clone());
    let data_keys = ArcOneRttKeys::new_pending();
    let initial_feedback = ArcFeedback::from(initial.send_journal.clone());
    let handshake_feedback = ArcFeedback::from(handshake.send_journal.clone());
    let data_feedback = ArcFeedback::default();
    let reliable = ReliableFrames::with_capacity_and_wakers(0, wakers.clone());
    let send_flow = ArcSendControler::new(0, reliable.clone(), wakers.clone());
    let paths = Arc::new(Paths::default());
    let selected = Arc::new(OnceLock::<Pathway>::new());
    let peer_cid = Arc::new(OnceLock::<ConnectionId>::new());
    let routes = Arc::new(Mutex::new(BTreeMap::<Pathway, Link>::new()));
    let status = Arc::new(HandshakeStatus::new(role == Role::Server));
    let idle = ArcConnIdle::new_at(timeout, Duration::ZERO, Duration::ZERO, received_at);
    let activity = Arc::new(idle.timer());
    let closing = Arc::new(AtomicBool::new(false));
    let confirmed = Arc::new(AtomicBool::new(false));
    let tls_complete = Arc::new(AtomicBool::new(false));
    let stop = CancellationToken::new();
    let _stop_on_exit = stop.clone().drop_guard();
    let send_stop = CancellationToken::new();
    let close = ArcReceiving::<CloseReason>::default();
    // The first close reason is consumed once; a later peer CLOSE completes Closing.
    let mut peer_closed = ArcReceiving::default();
    let (close_packets, _) = watch::channel(None::<Error>);
    let (close_received, _) = watch::channel(0u64);
    // Construction handoff, not receive commands: only complete Transport values are published.
    let (ready, ready_rx) = watch::channel(None::<Arc<Transport>>);
    let (scope, scope_rx) = watch::channel(None::<crate::Scope>);
    let (new_paths, mut path_queue) = mpsc::channel(4);
    let (crypto_tx, mut crypto_rx) = mpsc::channel(32);
    let (handshake_done, mut done_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let local_cids = ArcLocalCids::new(
        local_cid,
        IssuedCids {
            router: network.router.clone(),
            packets,
            reliable: reliable.clone(),
        },
    );
    let remote_limit = match &connection {
        Connection::Connecting(connecting) => connecting
            .parameters
            .get_local(ParameterId::ActiveConnectionIdLimit)
            .unwrap(),
        _ => 2,
    };
    let remote_cids = ArcRemoteCids::new(remote_limit, reliable.clone());
    let initial_dcid = remote_cids.apply_dcid();

    // Path creation remains connection policy; congestion, validation and buffers are qtransport's.
    let path_for = {
        let paths = paths.clone();
        let status = status.clone();
        let feedback: [Arc<dyn qcongestion::Feedback>; 3] = [
            Arc::new(initial_feedback.clone()),
            Arc::new(handshake_feedback.clone()),
            Arc::new(data_feedback.clone()),
        ];
        let wakers = wakers.clone();
        let peer_cid = peer_cid.clone();
        let routes = routes.clone();
        let closing = closing.clone();
        move |pathway: Pathway, link: Link| {
            if scope_rx
                .borrow()
                .is_some_and(|scope| !scope.allows(pathway, link))
            {
                return None;
            }
            if let Some(path) = paths.get(&pathway) {
                return Some(path);
            }
            if closing.load(Ordering::Acquire) || paths.snapshot().len() >= 4 {
                return None;
            }
            let slot = new_paths.try_reserve().ok()?;
            let path = Arc::new(Path::new(
                pathway,
                peer_cid.get().copied().unwrap_or(original_dcid),
                status.clone(),
                Duration::from_millis(25),
                feedback.clone(),
            ));
            if role == Role::Client {
                path.grant_amplification();
            }
            wakers.replace(pathway, &path.send_waker);
            paths.insert(path.clone());
            routes.lock().unwrap().insert(pathway, link);
            slot.send(path.clone());
            Some(path)
        }
    };
    let path_for = Arc::new(path_for);
    let mut address_changes = FuturesUnordered::new();
    address_changes.push(address_changed(network.addresses.subscribe_ddns()));
    let mut peers = Vec::new();
    let mut bounds = Vec::new();
    for pathway in &candidates {
        if !peers.contains(&pathway.remote()) {
            peers.push(pathway.remote());
        }
        if let EndpointAddr::Direct { addr } = pathway.local()
            && !bounds.contains(&addr)
        {
            bounds.push(addr);
            address_changes.push(address_changed(network.addresses.subscribe_mdns(addr)));
        }
    }
    for pathway in candidates {
        if let (
            qbase::net::addr::EndpointAddr::Direct { addr: local },
            qbase::net::addr::EndpointAddr::Direct { addr: remote },
        ) = (pathway.local(), pathway.remote())
        {
            path_for(pathway, Link::new(local, remote));
        }
    }

    // All receiving nodes and CRYPTO pipes run in this single task, across every phase.
    let receive = {
        let initial_feedback = initial_feedback.clone();
        let path_for = path_for.clone();
        let initial = initial.clone();
        let handshake = handshake.clone();
        let crypto = crypto.clone();
        let closing = closing.clone();
        let selected = selected.clone();
        let paths = paths.clone();
        let peer_cid = peer_cid.clone();
        let status = status.clone();
        let remote_cids = remote_cids.clone();
        let initial_dcid = initial_dcid.clone();
        let local_cids = local_cids.clone();
        let activity = activity.clone();
        let close = close.clone();
        let peer_closed = peer_closed.clone();
        let mut ready = ready_rx.clone();
        let stop = stop.clone();
        let close_received = close_received.clone();
        let confirmed = confirmed.clone();
        let handshake_done = handshake_done.clone();
        let token_name = match &connection {
            Connection::Connecting(c) => c.name.clone(),
            _ => String::new(),
        };
        async move {
            let (initial_entry, initial_packets) = mpsc::channel(PACKET_QUEUE_CAPACITY);
            let (handshake_entry, handshake_packets) = mpsc::channel(PACKET_QUEUE_CAPACITY);
            let (data_entry, data_packets) = mpsc::channel(PACKET_QUEUE_CAPACITY);
            let on_error = |error: Error| {
                closing.store(true, Ordering::Release);
                close.obtain(error.into());
            };
            let on_close = |_: Epoch, frame: ConnectionCloseFrame, _: &Arc<Path>| {
                closing.store(true, Ordering::Release);
                close.obtain(CloseReason::Peer(frame));
                peer_closed.obtain(());
                Ok(())
            };
            let on_processed = |epoch, path: &Arc<Path>| {
                if closing.load(Ordering::Acquire) {
                    close_received.send_modify(|serial| *serial = serial.wrapping_add(1));
                    return Ok(());
                }
                activity.on_rcvd(PacketContent::default());
                if epoch == Epoch::Data && confirmed.load(Ordering::Acquire) && !path.is_validated()
                {
                    path.start_validation();
                }
                if let Some(dcid) = peer_cid.get()
                    && selected.set(path.pathway).is_ok()
                {
                    remote_cids.apply_initial_dcid(*dcid, &initial_dcid);
                    for candidate in paths.snapshot() {
                        candidate.set_dcid(*dcid);
                    }
                }
                if role == Role::Server && epoch == Epoch::Handshake {
                    path.validate();
                    initial.retire();
                    initial_feedback.retire();
                    for candidate in paths.snapshot() {
                        candidate.cc.discard_epoch(Epoch::Initial);
                    }
                }
                Ok(())
            };
            let dispatch_long = |epoch, frame: Frame<Bytes>, path: &Arc<Path>| {
                let space = if epoch == Epoch::Initial {
                    &initial
                } else {
                    &handshake
                };
                match frame {
                    Frame::Padding(_) | Frame::Ping(_) => Ok(()),
                    Frame::Crypto(frame, bytes) => {
                        space.crypto.incoming().recv_frame((frame, bytes))
                    }
                    Frame::Ack(frame) => {
                        let mut cc = path.cc.lock();
                        space.send_journal.acknowledge(&frame, |frame| {
                            if let GuaranteedFrame::Crypto(frame) = frame {
                                space.crypto.outgoing().on_data_acked(frame);
                            }
                        })?;
                        cc.on_ack_rcvd(epoch, &frame, Instant::now());
                        if epoch == Epoch::Handshake {
                            status.received_handshake_ack();
                        }
                        Ok(())
                    }
                    Frame::Close(frame) => on_close(epoch, frame, path),
                    _ => Err(QuicError::with_default_fty(
                        ErrorKind::ProtocolViolation,
                        "unexpected handshake frame",
                    )
                    .into()),
                }
            };
            let open_initial =
                |keys: &Arc<qtls::BidirectionalKeys>, packet: qbase::packet::DataPacket, pto| {
                    let scid = match &packet.header {
                        DataHeader::Long(long::DataHeader::Initial(header)) => *header.scid(),
                        _ => unreachable!(),
                    };
                    let opened =
                        keys.opening
                            .open(packet, |pn| initial.rcvd_journal.decode_pn(pn), pto)?;
                    if opened.is_some() {
                        if peer_cid.get().is_some_and(|cid| *cid != scid) {
                            return Ok(None);
                        }
                        let _ = peer_cid.set(scid);
                    }
                    Ok(opened)
                };
            let data_receive = async {
                let transport = ready
                    .wait_for(Option::is_some)
                    .await
                    .ok()?
                    .as_ref()?
                    .clone();
                let tokens = if role == Role::Client {
                    ArcTokenRegistry::with_sink(token_name, Arc::new(NoopTokenRegistry))
                } else {
                    ArcTokenRegistry::with_provider(Arc::new(NoopTokenRegistry))
                };
                let dispatch = recv::frame_dispatcher(
                    transport.data.clone(),
                    transport.parameters.clone(),
                    transport.streams.clone(),
                    transport.flow.clone(),
                    crypto.clone(),
                    local_cids,
                    remote_cids.clone(),
                    tokens,
                    closing.clone(),
                    on_close,
                    |_, frame, _| match frame {
                        Frame::HandshakeDone(_) if role == Role::Client => {
                            handshake_done.send_replace(true);
                            Ok(())
                        }
                        _ => Err(QuicError::with_default_fty(
                            ErrorKind::ProtocolViolation,
                            "unnegotiated frame",
                        )
                        .into()),
                    },
                );
                recv::run_receive(
                    data_packets,
                    transport.data.clone(),
                    |keys: &OneRttKeys, packet, pto| {
                        keys.open(packet, |pn| transport.data.rcvd_journal.decode_pn(pn), pto)
                    },
                    closing.clone(),
                    |keys, epoch, frame, path| {
                        dispatch(epoch, frame, path, &|generation| keys.on_ack(generation))
                    },
                    &on_processed,
                    &on_error,
                )
                .await;
                Some(())
            };
            let pipes = async {
                tokio::join!(
                    crypto_pipe(Epoch::Initial, crypto[0].clone(), crypto_tx.clone()),
                    crypto_pipe(Epoch::Handshake, crypto[1].clone(), crypto_tx.clone()),
                    crypto_pipe(Epoch::Data, crypto[2].clone(), crypto_tx)
                );
            };
            tokio::select! {
                _ = stop.cancelled() => {},
                _ = async {
                    tokio::join!(
                        recv::route_packets(
                            inbox,
                            [initial_entry, handshake_entry, data_entry],
                            |pathway, link| {
                                if role == Role::Client {
                                    paths.get(&pathway)
                                } else {
                                    path_for(pathway, link)
                                }
                            },
                            |_, _, _| {}
                        ),
                        recv::run_receive(
                            initial_packets,
                            initial.clone(),
                            open_initial,
                            closing.clone(),
                            |_, epoch, frame, path| dispatch_long(epoch, frame, path),
                            &on_processed,
                            &on_error
                        ),
                        recv::run_receive(
                            handshake_packets,
                            handshake.clone(),
                            |keys: &Arc<qtls::BidirectionalKeys>, packet, pto| keys.opening.open(
                                packet,
                                |pn| handshake.rcvd_journal.decode_pn(pn),
                                pto
                            ),
                            closing.clone(),
                            |_, epoch, frame, path| dispatch_long(epoch, frame, path),
                            &on_processed,
                            &on_error
                        ),
                        data_receive,
                        pipes,
                    );
                } => {},
            }
            (None, Ok(()))
        }
    };
    tasks.spawn(receive);

    let mut registration = None::<Arc<crate::listener::Registration>>;
    let mut delivery = None;
    let mut transport = None::<Arc<Transport>>;
    let mut ending = None::<Error>;
    let mut stopping = false;
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let outcome = async {
        loop {
            let grace = || {
                paths
                    .snapshot()
                    .iter()
                    .map(|path| path.cc.pto_base(Epoch::Data) * 3)
                    .max()
                    .unwrap_or(Duration::ZERO)
            };
            let live = matches!(
                connection,
                Connection::Incoming(_) | Connection::Connecting(_) | Connection::Active { .. }
            );
            // Terminal inputs have priority. Ordinary work is selected fairly inside the last branch.
            let registration_stop = registration.as_ref().map(|r| r.stop.clone());
            let work: Result<(), Error> = tokio::select! {
                biased;
                _ = network.stop.cancelled() => {
                    ending.get_or_insert_with(|| crate::internal("network stopped"));
                    connection = Connection::Terminated;
                    Ok(())
                }
                Ok(Some(reason)) = close.clone(), if live => {
                    match reason {
                        CloseReason::App(error) => connection.close(error.into(), grace()),
                        CloseReason::Internal(error) => connection.close(error.into(), grace()),
                        CloseReason::Peer(frame) => {
                            ending.get_or_insert_with(|| frame.into());
                            connection.drain(grace());
                        }
                    }
                    Ok(())
                }
                Ok(Some(())) = &mut peer_closed, if matches!(connection, Connection::Closing { .. }) => {
                    connection.drain(grace());
                    Ok(())
                }
                _ = cancel.cancelled(), if live => Err(crate::internal("connect cancelled")),
                _ = async {
                    if let Some(stop) = &registration_stop {
                        stop.cancelled().await;
                    } else {
                        pending::<()>().await;
                    }
                }, if matches!(connection, Connection::Connecting(_)) => Err(crate::internal("endpoint stopped listening")),
                result = async {
                    tokio::select! {
                        changed = address_changes.next(), if live => {
                            if let Some(mut addresses) = changed {
                                let added = addresses.borrow_and_update().clone();
                                address_changes.push(address_changed(addresses));
                                for path in paths.snapshot() {
                                    let local = path.pathway.local();
                                    let listed = network.addresses.ddns_endpoints().contains(&local)
                                        || matches!(local, EndpointAddr::Direct { addr } if network.addresses.mdns_endpoints(addr).contains(&local));
                                    if !listed || network.protocol.find_socket(local).is_none() {
                                        paths.remove(&path);
                                    }
                                }
                                if role == Role::Client {
                                    for local in added.iter().copied() {
                                        for remote in peers.iter().copied() {
                                            if let (EndpointAddr::Direct { addr: src }, EndpointAddr::Direct { addr: dst }) =
                                                (local, remote)
                                                && src.is_ipv4() == dst.is_ipv4()
                                                && network.protocol.find_socket(local).is_some()
                                                && let Some(path) =
                                                    path_for(Pathway::new(local, remote), Link::new(src, dst))
                                                && confirmed.load(Ordering::Acquire)
                                            {
                                                path.start_validation();
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(())
                        }
                        path = path_queue.recv() => {
                            if let Some(path) = path {
                                let task_path = path.clone();
                                let initial = initial.clone();
                                let initial_feedback = initial_feedback.clone();
                                let handshake = handshake.clone();
                                let flow = send_flow.clone();
                                let protocol = network.protocol.clone();
                                let ready = ready_rx.clone();
                                let closing = closing.clone();
                                let close = close_packets.subscribe();
                                let close_received = close_received.subscribe();
                                let stop = stop.clone();
                                let send_stop = send_stop.clone();
                                let selected = selected.clone();
                                let paths = paths.clone();
                                let activity = activity.clone();
                                let confirmed = confirmed.clone();
                                let tls_complete = tls_complete.clone();
                                let remote_cids = remote_cids.clone();
                                let initial_dcid = initial_dcid.clone();
                                tasks.spawn(async move {
                                    let result = send_path(
                                        protocol,
                                        task_path.clone(),
                                        role,
                                        local_cid,
                                        initial,
                                        initial_feedback,
                                        handshake,
                                        ready,
                                        flow,
                                        selected,
                                        paths,
                                        confirmed,
                                        tls_complete,
                                        remote_cids,
                                        initial_dcid,
                                        closing,
                                        close,
                                        close_received,
                                        stop,
                                        send_stop,
                                        activity,
                                    )
                                    .await;
                                    (Some(task_path), result)
                                });
                            }
                            Ok(())
                        }
                        result = tasks.join_next(), if !tasks.is_empty() => {
                            match result {
                                Some(Ok((Some(path), result))) => {
                                    paths.remove(&path);
                                    wakers.remove_if(&path.pathway, &path.send_waker);
                                    if !stopping {
                                        if let Err(error) = result
                                            && error.kind() != ErrorKind::NoViablePath
                                        {
                                            return Err(error);
                                        }
                                        if paths.snapshot().is_empty() {
                                            return Err(QuicError::with_default_fty(
                                                ErrorKind::NoViablePath,
                                                "all paths failed",
                                            )
                                            .into());
                                        }
                                    }
                                    Ok(())
                                }
                                Some(Ok((None, _))) if !stopping => Err(crate::internal("receive task stopped")),
                                Some(Err(error)) => Err(crate::internal(format!("connection task failed: {error}"))),
                                _ => Ok(()),
                            }
                        }
                        _ = tick.tick() => {
                            let now = Instant::now();
                            match connection {
                                Connection::Closing { until, .. } | Connection::Draining { until } if now >= until => {
                                    connection = Connection::Terminated
                                }
                                Connection::Incoming(_) | Connection::Connecting(_) | Connection::Active { .. } => {
                                    initial.on_tick(now);
                                    handshake.on_tick(now);
                                    match &connection {
                                        Connection::Active { transport, .. } => transport.on_tick(now),
                                        _ => {
                                            if let Some(transport) = &transport {
                                                transport.on_tick(now);
                                            }
                                        }
                                    }
                                    if activity.timed_out(now, grace() / 3) {
                                        ending = Some(
                                            QuicError::with_default_fty(ErrorKind::None, "connection idle timeout").into(),
                                        );
                                        connection = Connection::Terminated;
                                    }
                                }
                                _ => {}
                            }
                            Ok(())
                        }
                        _ = done_rx.changed(), if matches!(connection, Connection::Active { .. }) && role == Role::Client && !confirmed.load(Ordering::Acquire) => {
                            confirm_handshake(
                                &status, &confirmed, &data_keys, &handshake, &handshake_feedback, &paths, &selected,
                            );
                            Ok(())
                        },
                        message = crypto_rx.recv(), if live => {
                            let (epoch, bytes) = message.ok_or_else(|| crate::internal("CRYPTO pipe stopped"))?;
                            match &mut connection {
                                Connection::Incoming(incoming) => {
                                    let pathway = *selected
                                        .get()
                                        .expect("authenticated Initial precedes CRYPTO delivery");
                                    let link = *routes.lock().unwrap().get(&pathway).unwrap();
                                    if let Some((connecting, selected_endpoint, permit)) =
                                        incoming.receive(bytes, &network, local_cid, original_dcid, (pathway, link))?
                                    {
                                        idle.negotiate_max_idle_timeout(
                                            selected_endpoint
                                                .parameters
                                                .get(ParameterId::MaxIdleTimeout)
                                                .unwrap(),
                                        );
                                        scope.send_replace(Some(selected_endpoint.scope));
                                        registration = Some(selected_endpoint);
                                        delivery = Some(permit);
                                        connection = Connection::Connecting(Box::new(connecting));
                                    }
                                    Ok(())
                                }
                                Connection::Connecting(connecting) => connecting
                                    .tls
                                    .receive_crypto(level(epoch), &bytes)
                                    .map_err(tls_error),
                                Connection::Active { tls, .. } => {
                                    if epoch != Epoch::Data {
                                        return Err(QuicError::with_default_fty(
                                            ErrorKind::ProtocolViolation,
                                            "unexpected post-handshake CRYPTO level",
                                        )
                                        .into());
                                    }
                                    tls.receive_post_handshake(&bytes).map_err(tls_error)
                                }
                                _ => Ok(()),
                            }
                        }
                        result = async {
                            let Connection::Connecting(connecting) = &mut connection else {
                                return pending().await;
                            };
                            if let Some((epoch, bytes)) = &mut connecting.writing {
                                let count = crypto[*epoch]
                                    .writer()
                                    .write(bytes)
                                    .await
                                    .map_err(|error| crate::internal(error.to_string()))?;
                                bytes.advance(count);
                                if bytes.is_empty() {
                                    connecting.writing = None;
                                }
                                return Ok(false);
                            }
                            let Some(event) = connecting.tls.next_event() else {
                                if connecting.summary.is_some() {
                                    return Ok(true);
                                }
                                return pending().await;
                            };
                            match event {
                                qtls::TlsEvent::WriteCrypto { level, bytes } => {
                                    connecting.writing = Some((epoch(level), bytes));
                                }
                                qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::Handshake(keys)) => {
                                    handshake.keys.install(Arc::new(keys))?;
                                    status.got_handshake_key();
                                    wakers.wake_all_by(Signals::KEYS);
                                }
                                qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(keys)) => {
                                    data_keys.install(keys)?;
                                    wakers.wake_all_by(Signals::KEYS);
                                }
                                qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::ZeroRtt(_)) => {
                                    return Err(crate::internal("0-RTT is not enabled"));
                                }
                                qtls::TlsEvent::ClientHello {
                                    server_name,
                                    transport_parameters,
                                } => {
                                    if server_name.as_deref() != Some(connecting.name.as_str()) {
                                        return Err(QuicError::with_default_fty(
                                            ErrorKind::ProtocolViolation,
                                            "TLS SNI changed after endpoint selection",
                                        )
                                        .into());
                                    }
                                    connecting
                                        .parameters
                                        .recv_remote_params(ClientParameters::parse_from_bytes(&transport_parameters)?)?;
                                }
                                qtls::TlsEvent::ServerTransportParameters(bytes) => {
                                    let remote = ServerParameters::parse_from_bytes(&bytes)?;
                                    if remote.contains(ParameterId::RetrySourceConnectionId) {
                                        return Err(QuicError::with_default_fty(
                                            ErrorKind::TransportParameter,
                                            "unexpected Retry source CID",
                                        )
                                        .into());
                                    }
                                    connecting.parameters.recv_remote_params(remote)?;
                                }
                                qtls::TlsEvent::HandshakeComplete(summary) => connecting.summary = Some(summary),
                                qtls::TlsEvent::Alert(alert) => {
                                    return Err(QuicError::with_default_fty(
                                        ErrorKind::Crypto(alert.description()),
                                        "TLS alert",
                                    )
                                    .into());
                                }
                            }
                            if transport.is_none() && connecting.parameters.is_remote_params_received() {
                                connecting
                                    .parameters
                                    .initial_scid_from_peer_need_equal(*peer_cid.get().expect("authenticated peer CID"))?;
                                let parameters = ArcParameters::new(
                                    role,
                                    connecting.parameters.client().unwrap().clone(),
                                    connecting.parameters.server().unwrap().clone(),
                                );
                                idle.negotiate_max_idle_timeout(parameters.remote(ParameterId::MaxIdleTimeout).unwrap());
                                remote_cids.set_limit(
                                    parameters
                                        .local(ParameterId::ActiveConnectionIdLimit)
                                        .unwrap(),
                                );
                                // Four candidate paths need at most four simultaneously issued CIDs.
                                local_cids.set_limit(
                                    parameters
                                        .remote::<u64>(ParameterId::ActiveConnectionIdLimit)
                                        .unwrap()
                                        .min(4),
                                )?;
                                let built = make_transport(
                                    parameters,
                                    crypto[2].clone(),
                                    data_keys.clone(),
                                    reliable.clone(),
                                    send_flow.clone(),
                                    wakers.clone(),
                                    paths.clone(),
                                );
                                data_feedback.start(built.data.send_journal.clone());
                                ready.send_replace(Some(built.clone()));
                                transport = Some(built);
                                wakers.wake_all_by(Signals::TRANSPORT);
                            }
                            Ok(false)
                        }, if matches!(connection, Connection::Connecting(_)) => {
                            if result? {
                                // Check the already published terminal facts again before committing delivery.
                                if closing.load(Ordering::Acquire) {
                                    return Ok(());
                                }
                                let Connection::Connecting(mut connecting) =
                                    std::mem::replace(&mut connection, Connection::Terminated)
                                else {
                                    unreachable!()
                                };
                                let summary = connecting.summary.take().unwrap();
                                let alpn = summary
                                    .alpn
                                    .ok_or_else(|| crate::internal("TLS completed without ALPN"))?;
                                let tls = connecting
                                    .tls
                                    .finish()
                                    .map_err(|error| crate::internal(error.to_string()))?;
                                let data = transport
                                    .as_ref()
                                    .expect("parameters precede TLS completion")
                                    .clone();
                                let conn = ArcConnection::new(data.clone(), alpn, close.clone());
                                connection = Connection::Active {
                                    tls: Box::new(tls),
                                    transport: data,
                                };
                                tls_complete.store(true, Ordering::Release);
                                wakers.wake_all_by(Signals::TRANSPORT);
                                if role == Role::Server {
                                    let registration = registration.as_ref().unwrap();
                                    if summary
                                        .local
                                        .as_ref()
                                        .is_none_or(|local| local.name() != registration.endpoint.name())
                                    {
                                        return Err(crate::internal("TLS selected a different endpoint"));
                                    }
                                    let live = registration.live.lock().unwrap();
                                    if !*live {
                                        return Err(crate::internal("endpoint stopped listening"));
                                    }
                                    confirm_handshake(
                                        &status, &confirmed, &data_keys, &handshake, &handshake_feedback, &paths, &selected,
                                    );
                                    reliable.send_frame([HandshakeDoneFrame]);
                                    delivery.take().unwrap().send((
                                        registration.clone(),
                                        (
                                            summary.remote.map(remote_authority),
                                            LocalAuthority::from(registration.endpoint.identity.clone()),
                                            conn,
                                        ),
                                    ));
                                    if let Some(matured) = &matured {
                                        let _ = matured.try_send(tokio::task::id());
                                    }
                                } else {
                                    let remote = summary
                                        .remote
                                        .ok_or_else(|| crate::internal("TLS did not authenticate the server"))?;
                                    reply
                                        .take()
                                        .unwrap()
                                        .send(Ok((
                                            endpoint
                                                .as_ref()
                                                .map(|ep| LocalAuthority::from(ep.identity.clone())),
                                            remote_authority(remote),
                                            conn,
                                        )))
                                        .map_err(|_| crate::internal("connect result was abandoned"))?;
                                }
                            }
                            Ok(())
                        }
                    }
                } => result,
            };
            if let Err(error) = work {
                close.obtain(error.into());
            }
            if !matches!(
                connection,
                Connection::Incoming(_) | Connection::Connecting(_) | Connection::Active { .. }
            ) {
                if !stopping {
                    stopping = true;
                    closing.store(true, Ordering::Release);
                    if let Connection::Closing { error, .. } = &connection {
                        ending.get_or_insert(error.clone());
                    }
                    let error = ending
                        .get_or_insert_with(|| crate::internal("connection terminated"))
                        .clone();
                    initial.stop_sending();
                    handshake.stop_sending();
                    initial_feedback.retire();
                    handshake_feedback.retire();
                    data_feedback.retire();
                    if let Some(transport) = &transport {
                        transport.close(error.clone());
                    }
                    send_flow.on_error(&error);
                    if let Some(reply) = reply.take() {
                        let _ = reply.send(Err(error));
                    }
                    delivery.take();
                }
                match &connection {
                    Connection::Closing { error, .. } => {
                        if close_packets.borrow().is_none() {
                            close_packets.send_replace(Some(error.clone()));
                        }
                    }
                    Connection::Draining { .. } => send_stop.cancel(),
                    Connection::Terminated => break,
                    _ => {}
                }
                wakers.wake_all_by(Signals::all());
            }
        }
    };
    let outcome = std::panic::AssertUnwindSafe(outcome).catch_unwind().await;
    if outcome.is_err() {
        let error = crate::internal("connection driver panicked");
        closing.store(true, Ordering::Release);
        if let Some(transport) = &transport {
            transport.close(error.clone());
        }
        if let Some(reply) = reply.take() {
            let _ = reply.send(Err(error.clone()));
        }
        ending.get_or_insert(error);
    }
    stop.cancel();
    send_stop.cancel();
    while tasks.join_next().await.is_some() {}
    initial.retire();
    handshake.retire();
    data_keys.retire();
    initial_feedback.retire();
    handshake_feedback.retire();
    data_feedback.retire();
    if let Some(transport) = &transport {
        transport.data.stop_receiving();
    }
    for path in paths.snapshot() {
        paths.remove(&path);
        wakers.remove_if(&path.pathway, &path.send_waker);
    }
    local_cids.clear();
    ending.unwrap_or_else(|| crate::internal("connection terminated"))
}

fn confirm_handshake(
    status: &HandshakeStatus,
    confirmed: &AtomicBool,
    keys: &ArcOneRttKeys,
    handshake: &Space<ArcKeys>,
    feedback: &ArcFeedback,
    paths: &Paths,
    selected: &OnceLock<Pathway>,
) {
    status.handshake_confirmed();
    confirmed.store(true, Ordering::Release);
    keys.try_get()
        .expect("Data keys not retired during confirmation")
        .expect("TLS installed Data keys")
        .allow_update();
    handshake.retire();
    feedback.retire();
    for path in paths.snapshot() {
        path.cc.discard_epoch(Epoch::Handshake);
        if selected.get() == Some(&path.pathway) {
            path.validate();
        } else {
            path.start_validation();
        }
    }
}

async fn address_changed(
    mut addresses: watch::Receiver<Arc<[EndpointAddr]>>,
) -> watch::Receiver<Arc<[EndpointAddr]>> {
    let _ = addresses.changed().await;
    addresses
}

fn epoch(level: qtls::CryptoLevel) -> Epoch {
    match level {
        qtls::CryptoLevel::Initial => Epoch::Initial,
        qtls::CryptoLevel::Handshake => Epoch::Handshake,
        qtls::CryptoLevel::OneRtt => Epoch::Data,
    }
}

fn level(epoch: Epoch) -> qtls::CryptoLevel {
    match epoch {
        Epoch::Initial => qtls::CryptoLevel::Initial,
        Epoch::Handshake => qtls::CryptoLevel::Handshake,
        Epoch::Data => qtls::CryptoLevel::OneRtt,
    }
}

fn long_space(epoch: Epoch, crypto: CryptoStream, wakers: ArcSendWakers) -> Arc<Space<ArcKeys>> {
    let outgoing = crypto.outgoing();
    Arc::new(Space::new(
        epoch,
        ArcKeys::new_pending(),
        crypto,
        wakers,
        move |frame| {
            if let GuaranteedFrame::Crypto(frame) = frame {
                outgoing.may_loss_data(frame);
            }
        },
    ))
}

async fn crypto_pipe(epoch: Epoch, stream: CryptoStream, output: mpsc::Sender<(Epoch, Bytes)>) {
    let mut reader = stream.reader();
    loop {
        let Ok(slot) = output.reserve().await else {
            break;
        };
        let mut bytes = vec![0; 16 * 1024];
        let Ok(length) = reader.read(&mut bytes).await else {
            break;
        };
        if length == 0 {
            break;
        }
        bytes.truncate(length);
        slot.send((epoch, bytes.into()));
    }
}

#[allow(clippy::too_many_arguments)]
fn make_transport(
    parameters: ArcParameters,
    crypto: CryptoStream,
    keys: ArcOneRttKeys,
    reliable: ReliableFrames,
    sender: ArcSendControler<ReliableFrames>,
    wakers: ArcSendWakers,
    paths: Arc<Paths>,
) -> Arc<Transport> {
    let concurrency = Box::new(ConsistentConcurrency::new(
        parameters
            .local(ParameterId::InitialMaxStreamsBidi)
            .unwrap(),
        parameters.local(ParameterId::InitialMaxStreamsUni).unwrap(),
    ));
    let streams = match parameters.role() {
        Role::Client => {
            let streams = DataStreams::new(
                Role::Client,
                parameters.client(),
                parameters.server(),
                concurrency,
                reliable.clone(),
                wakers.clone(),
                None,
            );
            streams.revise_params(false, parameters.server());
            streams
        }
        Role::Server => {
            let streams = DataStreams::new(
                Role::Server,
                parameters.server(),
                parameters.client(),
                concurrency,
                reliable.clone(),
                wakers.clone(),
                None,
            );
            streams.revise_params(false, parameters.client());
            streams
        }
    };
    sender.revise_max_data(
        false,
        parameters.remote(ParameterId::InitialMaxData).unwrap(),
    );
    let flow = FlowController {
        sender,
        recver: ArcRecvController::new(
            parameters.local(ParameterId::InitialMaxData).unwrap(),
            reliable.clone(),
        ),
    };
    let recover_streams = streams.clone();
    let recover_reliable = reliable.clone();
    let outgoing = crypto.outgoing();
    let data = Arc::new(Space::new(
        Epoch::Data,
        keys,
        crypto,
        wakers,
        move |frame| match frame {
            GuaranteedFrame::Crypto(frame) => outgoing.may_loss_data(frame),
            GuaranteedFrame::Stream(frame) => recover_streams.may_loss_data(frame),
            GuaranteedFrame::Reliable(frame) => recover_reliable.send_frame([frame.clone()]),
        },
    ));
    Arc::new(Transport::new(
        data, parameters, streams, flow, reliable, paths,
    ))
}

/// Each path owns exactly one Sender, retained when switching to CLOSE-only traffic.
#[allow(clippy::too_many_arguments)]
async fn send_path(
    protocol: Arc<qprotocol::QuicProtocol>,
    path: Arc<Path>,
    role: Role,
    local_cid: ConnectionId,
    initial: Arc<Space<ArcKeys>>,
    initial_feedback: ArcFeedback,
    handshake: Arc<Space<ArcKeys>>,
    ready: watch::Receiver<Option<Arc<Transport>>>,
    flow: ArcSendControler<ReliableFrames>,
    selected: Arc<OnceLock<Pathway>>,
    paths: Arc<Paths>,
    confirmed: Arc<AtomicBool>,
    tls_complete: Arc<AtomicBool>,
    remote_cids: ArcRemoteCids<ReliableFrames>,
    initial_dcid: ArcCidCell<ReliableFrames>,
    closing: Arc<AtomicBool>,
    mut close: watch::Receiver<Option<Error>>,
    mut close_received: watch::Receiver<u64>,
    stop: CancellationToken,
    send_stop: CancellationToken,
    activity: Arc<qbase::time::PathIdleTimer>,
) -> Result<(), Error> {
    let mut sender = Sender::new(
        protocol,
        path.pathway,
        path.cc.clone(),
        flow,
        path.anti_amplifier.clone(),
        path.send_waker.clone(),
    );
    let mut initial_crypto = initial.crypto.outgoing().package(Epoch::Initial);
    let mut handshake_crypto = handshake.crypto.outgoing().package(Epoch::Handshake);
    let started_during_handshake = !tls_complete.load(Ordering::Acquire);
    let cid = OnceLock::new();
    let mut borrowed_cid = None;
    let mut closing_mode = false;
    let mut close_epochs = 0u8;
    let mut next_reply = Instant::now();
    let outcome = async {
        loop {
            if stop.is_cancelled() || send_stop.is_cancelled() || path.state() == PathState::Retired {
                return Ok(());
            }
            let error = close.borrow_and_update().clone();
            if let Some(error) = error {
                if !closing_mode {
                    sender.cancel_pending();
                    // The sole sender has finished normal submission. Release handshake
                    // flight accounting before assembling a padded Initial CLOSE.
                    for epoch in [Epoch::Initial, Epoch::Handshake] {
                        path.cc.discard_epoch(epoch);
                    }
                    closing_mode = true;
                }
                if close_received.has_changed().unwrap_or(false) && Instant::now() >= next_reply {
                    close_received.borrow_and_update();
                    close_epochs = 0;
                }
                let transport = ready.borrow().clone();
                sender.burst(|sender, constraints| {
                    for epoch in [Epoch::Data, Epoch::Handshake, Epoch::Initial] {
                        if close_epochs & (1 << epoch as usize) != 0 {
                            continue;
                        }
                        let mut frame: ConnectionCloseFrame = if epoch != Epoch::Data
                            && matches!(error, Error::App(_))
                        {
                            Error::from(QuicError::with_default_fty(ErrorKind::Application, "")).into()
                        } else {
                            error.clone().into()
                        };
                        let packet = match epoch {
                            Epoch::Data => {
                                let Some(transport) = &transport else {
                                    continue;
                                };
                                let Ok(Some(keys)) = transport.data.keys.try_get() else {
                                    continue;
                                };
                                sender.assemble_1rtt_packet(
                                    &keys,
                                    OneRttHeader::new(Default::default(), path.dcid()),
                                    &transport.data.send_journal,
                                    constraints,
                                    [&mut frame],
                                )?
                            }
                            epoch => {
                                let space = if epoch == Epoch::Initial {
                                    &initial
                                } else {
                                    &handshake
                                };
                                let Ok(Some(keys)) = space.keys.try_get() else {
                                    continue;
                                };
                                let builder = LongHeaderBuilder::with_cid(path.dcid(), local_cid);
                                if epoch == Epoch::Initial {
                                    sender.assemble_initial_packet(
                                        &keys.sealing,
                                        builder.initial(vec![]),
                                        &space.send_journal,
                                        constraints,
                                        [&mut frame],
                                    )?
                                } else {
                                    sender.assemble_handshake_packet(
                                        &keys.sealing,
                                        builder.handshake(),
                                        &space.send_journal,
                                        constraints,
                                        [&mut frame],
                                    )?
                                }
                            }
                        };
                        if packet.is_some() {
                            close_epochs |= 1 << epoch as usize;
                            return Ok(packet);
                        }
                    }
                    Ok(None)
                })?;
            } else if !closing.load(Ordering::Acquire) {
                if confirmed.load(Ordering::Acquire) && borrowed_cid.is_none() {
                    let cell = cid.get_or_init(|| {
                        if started_during_handshake && selected.get() == Some(&path.pathway) {
                            initial_dcid.clone()
                        } else {
                            remote_cids.apply_dcid()
                        }
                    });
                    match cell.borrow_cid(path.send_waker.clone()) {
                        Ok(Some(borrowed)) => {
                            path.set_dcid(*borrowed);
                            borrowed_cid = Some(borrowed);
                        }
                        Ok(None) => return Ok(()),
                        Err(signals) => {
                            tokio::select! {
                                _ = stop.cancelled() => return Ok(()),
                                _ = send_stop.cancelled() => return Ok(()),
                                _ = close.changed() => {},
                                _ = path.send_waker.wait_for(signals) => {},
                            }
                            continue;
                        }
                    }
                }
                path.cc.do_tick().map_err(|error| {
                    QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
                })?;
                let transport = ready.borrow().clone();
                let preferred = selected.get().and_then(|way| paths.get(way)).or_else(|| {
                    paths
                        .snapshot()
                        .into_iter()
                        .find(|candidate| candidate.is_validated())
                });
                let preferred = preferred
                    .as_ref()
                    .is_none_or(|candidate| candidate.pathway == path.pathway);
                sender.burst(|sender, constraints| {
                    if preferred {
                        for space in [&initial, &handshake] {
                            if !space.can_send() {
                                continue;
                            }
                            let Ok(Some(keys)) = space.keys.try_get() else {
                                continue;
                            };
                            let mut ack = ack_frame(space, &path, 0);
                            let mut ping = (path.cc.need_send_ack_eliciting(space.epoch) != 0)
                                .then_some(PingFrame);
                            let header = LongHeaderBuilder::with_cid(path.dcid(), local_cid);
                            let packet = if space.epoch == Epoch::Initial {
                                sender.assemble_initial_packet(
                                    &keys.sealing,
                                    header.initial(vec![]),
                                    &space.send_journal,
                                    constraints,
                                    [&mut ack, &mut initial_crypto, &mut ping],
                                )?
                            } else {
                                sender.assemble_handshake_packet(
                                    &keys.sealing,
                                    header.handshake(),
                                    &space.send_journal,
                                    constraints,
                                    [&mut ack, &mut handshake_crypto, &mut ping],
                                )?
                            };
                            if packet.is_some() {
                                return Ok(packet);
                            }
                        }
                    }
                    if let Some(transport) = &transport
                        && tls_complete.load(Ordering::Acquire)
                        && transport.data.can_send()
                        && (preferred || confirmed.load(Ordering::Acquire))
                        && let Ok(Some(keys)) = transport.data.keys.try_get()
                    {
                        return assemble_data(sender, constraints, &keys, transport, &path, preferred);
                    }
                    Ok(None)
                })?;
            } else {
                sender.cancel_pending();
            }
            if sender.pending().next().is_some() {
                let sent = tokio::select! {
                    biased;
                    _ = stop.cancelled() => return Ok(()),
                    _ = send_stop.cancelled() => return Ok(()),
                    _ = close.changed(), if !closing_mode => continue,
                    result = poll_fn(|cx| sender.poll_send(cx,
                        |packet_type| {
                            if send_stop.is_cancelled() || (!closing_mode && closing.load(Ordering::Acquire)) { return false; }
                            use qbase::packet::r#type::long::{Type as Long, Ver1};
                            match packet_type {
                                qbase::packet::Type::Long(Long::V1(Ver1::INITIAL)) => initial.keys.try_get().is_ok() && (closing_mode || initial.can_send()),
                                qbase::packet::Type::Long(Long::V1(Ver1::HANDSHAKE)) => handshake.keys.try_get().is_ok() && (closing_mode || handshake.can_send()),
                                _ => closing_mode || ready.borrow().as_ref().is_some_and(|t| t.data.can_send()),
                            }
                        },
                        |packet| {
                            path.on_packet_sent(packet);
                            activity.on_sent(packet.content);
                            if !closing_mode && role == Role::Client && packet.epoch() == Epoch::Handshake {
                                if initial.can_receive() {
                                    initial.retire();
                                    initial_feedback.retire();
                                }
                                for candidate in paths.snapshot() { candidate.cc.discard_epoch(Epoch::Initial); }
                            }
                        })) => result?,
                };
                if sender.pending().next().is_none() {
                    borrowed_cid.take();
                }
                if sent != 0 && closing_mode {
                    next_reply = Instant::now() + path.cc.pto_base(Epoch::Data);
                }
                if sent != 0 {
                    tokio::task::yield_now().await;
                    continue;
                }
            }
            tokio::select! {
                _ = stop.cancelled() => return Ok(()),
                _ = send_stop.cancelled() => return Ok(()),
                _ = close.changed(), if !closing_mode => {},
                _ = sender.wait() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }.await;
    sender.cancel_pending();
    borrowed_cid.take();
    if let Some(cell) = cid.get() {
        cell.retire();
    }
    outcome
}

fn ack_frame<K>(space: &Space<K>, path: &Path, exponent: u32) -> Option<AckFrame> {
    path.cc
        .need_ack(space.epoch)
        .and_then(|(pn, time)| space.rcvd_journal.gen_ack_frame_util(pn, time, 400).ok())
        .map(|ack| {
            AckFrame::new(
                VarInt::from_u64(ack.largest()).unwrap(),
                VarInt::from_u64(ack.delay() >> exponent).unwrap(),
                VarInt::from_u64(ack.first_range()).unwrap(),
                ack.ranges().clone(),
                ack.ecn(),
            )
        })
}

fn assemble_data(
    sender: &mut Sender,
    constraints: &Constraints,
    keys: &OneRttKeys,
    transport: &Transport,
    path: &Path,
    preferred: bool,
) -> Result<Option<PendingPacket>, Error> {
    let mut ack = ack_frame(
        &transport.data,
        path,
        transport
            .parameters
            .local::<u64>(ParameterId::AckDelayExponent)
            .unwrap() as u32,
    );
    let mut crypto = transport.data.crypto.outgoing().package(Epoch::Data);
    let mut response = path.response();
    let mut challenge = path.challenge()?;
    let mut reliable = transport.reliable_frames.clone();
    let mut streams = Repeat(transport.streams.package(sender.flow.clone(), false));
    let mut ping = (path.cc.need_send_ack_eliciting(Epoch::Data) != 0).then_some(PingFrame);
    let header = OneRttHeader::new(Default::default(), path.dcid());
    if !path.is_validated() || !preferred {
        sender.assemble_1rtt_packet(
            keys,
            header,
            &transport.data.send_journal,
            constraints,
            [&mut ack, &mut response, &mut challenge, &mut ping],
        )
    } else {
        sender.assemble_1rtt_packet(
            keys,
            header,
            &transport.data.send_journal,
            constraints,
            [
                &mut ack,
                &mut crypto,
                &mut response,
                &mut challenge,
                &mut reliable,
                &mut ping,
                &mut streams,
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use qbase::{
        frame::CryptoFrame,
        packet::{Packet, PacketNumber, PacketReader},
    };
    use qtransport::send::write::{Packet as SendingPacket, PacketWriter};

    use super::*;

    fn initial_packet(
        keys: &qtls::DirectionalKeys,
        dcid: ConnectionId,
        pn: u64,
        source: &mut dyn for<'a> qbase::packet::Package<PacketWriter<'a>>,
    ) -> BytesMut {
        let header = LongHeaderBuilder::with_cid(dcid, ConnectionId::from_slice(b"testpeer"))
            .initial(vec![]);
        let mut packet =
            SendingPacket::new(BytesMut::zeroed(1200), header, keys.packet.tag_len()).unwrap();
        let constraints = Constraints {
            capacity: 1200,
            congestion: 1200,
            anti_amplification: 1200,
        };
        packet
            .assemble(&constraints, &mut Vec::new(), [source])
            .unwrap();
        packet.pad_to(1200, &constraints).unwrap();
        BytesMut::from(
            packet
                .seal_long(keys, pn, PacketNumber::U16(pn as u16))
                .unwrap()
                .bytes(),
        )
    }

    async fn incoming_close(local_error: bool) {
        let network = Network::new(
            crate::tls::tests::verifier(
                "localhost",
                include_bytes!("../../tests/keychain/localhost/server.cert"),
            ),
            None,
        )
        .unwrap();
        network.bind_scope(crate::Loopback).unwrap();
        // Resolve uses the same registered sockets as actual connections.
        let endpoint = crate::Endpoint::new(
            &rustls::crypto::ring::default_provider(),
            "localhost",
            vec![
                rustls::pki_types::CertificateDer::from_pem_slice(include_bytes!(
                    "../../tests/keychain/localhost/server.cert"
                ))
                .unwrap(),
            ],
            rustls::pki_types::PrivateKeyDer::from_pem_slice(include_bytes!(
                "../../tests/keychain/localhost/server.key"
            ))
            .unwrap(),
            None,
            qbase::param::ArcParameters::from(qbase::param::Parameters::new_server(
                qbase::param::handy::server_parameters(),
            )),
        )
        .unwrap();
        network
            .listener
            .register(
                Arc::new(endpoint),
                crate::Loopback,
                Arc::new(|_| panic!("failed handshake was delivered")),
            )
            .unwrap();
        let pathway = network.resolve("localhost").await.unwrap()[0];
        let (
            qbase::net::addr::EndpointAddr::Direct { addr: local },
            qbase::net::addr::EndpointAddr::Direct { addr: remote },
        ) = (pathway.local(), pathway.remote())
        else {
            unreachable!()
        };
        let link = Link::new(local, remote);
        let dcid = ConnectionId::from_slice(b"original");
        let keys = crate::tls::tests::initial_keys();
        let (sent, mut received) = mpsc::unbounded_channel();
        network.protocol.on_receive(move |bytes, _, _| {
            let _ = sent.send(bytes);
        });
        let mut close: ConnectionCloseFrame = Error::from(QuicError::with_default_fty(
            ErrorKind::None,
            "peer closed during Initial",
        ))
        .into();
        let bytes = if local_error {
            let bytes = [Bytes::from_static(&[2, 0, 0, 0])];
            initial_packet(
                &keys.opening,
                dcid,
                0,
                &mut (CryptoFrame::new(0u32.into(), 4u32.into()), bytes.as_slice()),
            )
        } else {
            initial_packet(&keys.opening, dcid, 0, &mut close)
        };
        network.router.receive(bytes, pathway, link, 8);
        if local_error {
            let bytes = tokio::time::timeout(Duration::from_secs(2), received.recv())
                .await
                .unwrap()
                .unwrap();
            let Packet::Data(packet) = PacketReader::new(bytes, 8).next().unwrap().unwrap() else {
                panic!("expected protected CLOSE");
            };
            let (_, frames) = keys
                .sealing
                .open(packet, |pn| Ok(pn.decode(0)), Duration::from_secs(1))
                .unwrap()
                .unwrap();
            assert!(
                frames
                    .into_iter()
                    .any(|frame| matches!(frame, Ok((Frame::Close(_), _))))
            );
            assert!(
                network.router.get(&dcid).is_some(),
                "Closing must retain its receive route"
            );
            // The same topology now receives a peer CLOSE and enters Draining.
            network.router.receive(
                initial_packet(&keys.opening, dcid, 1, &mut close),
                pathway,
                link,
                8,
            );
        }
        tokio::time::timeout(Duration::from_secs(4), async {
            while network.router.get(&dcid).is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("connection route survived termination");
        if !local_error {
            assert!(received.try_recv().is_err(), "Draining must never send");
        }
        network.stop.cancel();
    }

    use rustls::pki_types::pem::PemObject;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_error_sends_close_and_keeps_receiving_until_cleanup() {
        incoming_close(true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_peer_close_drains_without_allocating_tls_or_sending() {
        incoming_close(false).await;
    }
}
