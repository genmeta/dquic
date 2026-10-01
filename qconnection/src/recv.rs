//! Space nodes capture their pipes once; parameter completion only adds the Data node.
use std::sync::{Arc, Mutex, OnceLock};

use qbase::{
    ArcReceiving, Epoch,
    error::{ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, Frame, io::ReceiveFrame},
    net::route::{Pathway, Scopes},
    packet::{GetScid, GetType, OneRttHeader},
    param::Requirements,
    role::Role,
    token::ArcTokenRegistry,
};
use qtransport::{
    keys::{ArcKeys, OneRttKeys},
    packet::RcvdPacketHeader,
    path::Path,
    recv,
    space::Space,
};
use tokio::time::Instant;

#[cfg(test)]
use qbase::net::route::Link;

use crate::{ArcParameters, CloseReason, MaturePhase, Paths, terminate::Terminator};

pub type PacketReceiver<H> = qtransport::packet::channel::PacketReceiver<H>;

pub(crate) async fn recv_client_ih_pkt_and_deliver_frames<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
    requirements: Arc<Mutex<Requirements>>,
) where
    H: GetScid + GetType + qtransport::packet::RcvdPacketHeader,
{
    recv_ih_pkt_and_deliver_frames_if(packets, space, paths, closed, requirements, |_| true).await;
}

pub(crate) async fn recv_server_ih_pkt_and_deliver_frames<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
    requirements: Arc<Mutex<Requirements>>,
    scopes: Scopes,
) where
    H: GetScid + GetType + qtransport::packet::RcvdPacketHeader,
{
    recv_ih_pkt_and_deliver_frames_if(
        packets,
        space,
        paths,
        closed,
        requirements,
        move |pathway| pathway.belongs_to(scopes),
    )
    .await;
}

pub(crate) async fn recv_pending_server_initial(
    packets: PacketReceiver<qbase::packet::InitialHeader>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
    requirements: Arc<Mutex<Requirements>>,
    scopes: Arc<OnceLock<Scopes>>,
) {
    recv_ih_pkt_and_deliver_frames_if(
        packets,
        space,
        paths,
        closed,
        requirements,
        move |pathway| {
            scopes
                .get()
                .is_none_or(|scopes| pathway.belongs_to(*scopes))
        },
    )
    .await;
}

async fn recv_ih_pkt_and_deliver_frames_if<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
    requirements: Arc<Mutex<Requirements>>,
    belongs_to_scope: impl Fn(&Pathway) -> bool,
) where
    H: GetScid + GetType + RcvdPacketHeader,
{
    let role = paths.role();
    let ack_paths = paths.clone();
    let initial_scid = Arc::new(OnceLock::new());
    let close_paths = paths.clone();
    let inspect_paths = paths.clone();
    recv::run_receive(
        packets,
        space.epoch,
        space.keys.clone(),
        space.rcvd_journal.clone(),
        {
            let paths = paths.clone();
            move |pathway, _| paths.on_incoming_path(pathway).ok()
        },
        {
            let space = space.clone();
            let initial_scid = initial_scid.clone();
            move |keys: &Arc<qtls::BidirectionalKeys>, packet, pathway| {
                if !belongs_to_scope(&pathway) {
                    return Ok(None);
                }
                let scid = (space.epoch == Epoch::Initial).then(|| *packet.scid());
                let opened = packet
                    .decrypt_long_packet(&keys.opening, |pn| space.rcvd_journal.decode_pn(pn))
                    .transpose()?;
                if opened.is_some()
                    && let Some(scid) = scid
                {
                    if initial_scid.get().is_some_and(|cid| *cid != scid) {
                        return Ok(None);
                    }
                    let _ = initial_scid.set(scid);
                }
                Ok(opened)
            }
        },
        move |epoch, path| {
            inspect_paths.on_rcvd_packet();
            path.activity
                .on_rcvd(qbase::packet::PacketContent::default());
            if let Some(dcid) = initial_scid.get() {
                // This runs before CRYPTO delivery can wake the TLS consumer.
                requirements
                    .lock()
                    .unwrap()
                    .initial_scid_from_peer_need_equal(*dcid);
                inspect_paths.phase().set_dcid(*dcid);
            }
            if role == Role::Client || epoch == Epoch::Handshake {
                inspect_paths.select_path(path);
            }
            if epoch == Epoch::Handshake && inspect_paths.is_handshake_path(path) {
                path.validate();
            }
            Ok(())
        },
        {
            let space = space.clone();
            move |_, epoch, frame, path, _| match frame {
                Frame::Padding(_) | Frame::Ping(_) => Ok(()),
                Frame::Crypto(frame, bytes) => space.crypto.incoming().recv_frame((frame, bytes)),
                Frame::Ack(frame) => {
                    let mut cc = path.cc.lock();
                    let crypto_acked = space.on_acked(&frame)?;
                    cc.on_ack_rcvd(epoch, &frame, Instant::now());
                    drop(cc);
                    if role == Role::Server && epoch == Epoch::Initial && crypto_acked {
                        ack_paths.select_path(path);
                    }
                    Ok(())
                }
                Frame::Close(frame) => {
                    close_paths.on_rcvd_close(epoch, path, frame);
                    Ok(())
                }
                _ => Err(QuicError::with_default_fty(
                    ErrorKind::ProtocolViolation,
                    "unexpected handshake frame",
                )
                .into()),
            }
        },
        move |error| {
            closed.set(error.into());
        },
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn receive_client_data(
    packets: PacketReceiver<OneRttHeader>,
    sender: Arc<MaturePhase>,
    paths: Arc<Paths>,
    parameters: ArcParameters,
    cid_registry: crate::CidRegistry,
    tokens: ArcTokenRegistry,
    closed: ArcReceiving<CloseReason>,
    on_handshake_done: impl Fn() + Send + Sync,
) {
    let close_paths = paths.clone();
    let inspect_paths = paths.clone();
    receive_data(
        packets,
        sender,
        paths.clone(),
        |_| true,
        parameters,
        cid_registry,
        tokens,
        None,
        move |epoch, frame, path| close_paths.on_rcvd_close(epoch, path, frame),
        |_, path| {
            inspect_paths.on_rcvd_packet();
            path.activity
                .on_rcvd(qbase::packet::PacketContent::default());
        },
        on_handshake_done,
        move |error| closed.set(error.into()),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn receive_server_data(
    packets: PacketReceiver<OneRttHeader>,
    sender: Arc<MaturePhase>,
    paths: Arc<Paths>,
    parameters: ArcParameters,
    cid_registry: crate::CidRegistry,
    tokens: ArcTokenRegistry,
    closed: ArcReceiving<CloseReason>,
    scopes: Scopes,
) {
    let close_paths = paths.clone();
    let inspect_paths = paths.clone();
    receive_data(
        packets,
        sender,
        paths.clone(),
        move |pathway| pathway.belongs_to(scopes),
        parameters,
        cid_registry,
        tokens,
        None,
        move |epoch, frame, path| close_paths.on_rcvd_close(epoch, path, frame),
        |_, path| {
            inspect_paths.on_rcvd_packet();
            path.activity
                .on_rcvd(qbase::packet::PacketContent::default());
        },
        || {},
        move |error| closed.set(error.into()),
    )
    .await;
}

/// Constructed with complete sources; its one readiness consumer gates normal Data processing.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn receive_data(
    packets: PacketReceiver<OneRttHeader>,
    sender: Arc<MaturePhase>,
    paths: Arc<Paths>,
    belongs_to_scope: impl Fn(&Pathway) -> bool,
    parameters: ArcParameters,
    cid_registry: crate::CidRegistry,
    tokens: ArcTokenRegistry,
    ready: Option<ArcReceiving<bool>>,
    on_close: impl Fn(Epoch, ConnectionCloseFrame, &Arc<Path>) + Send + Sync,
    inspect: impl Fn(Epoch, &Arc<Path>),
    on_handshake_done: impl Fn() + Send + Sync,
    on_error: impl Fn(crate::Error),
) {
    if let Some(ready) = ready {
        let Ok(Some(true)) = ready.await else {
            return;
        };
    }
    let spaces = &sender.spaces;
    let role = parameters.role();
    let dispatch = recv::frame_dispatcher(
        sender.spaces.data.clone(),
        parameters,
        sender.flow.clone(),
        [
            spaces.initial.crypto.clone(),
            spaces.handshake.crypto.clone(),
            sender.spaces.data.crypto.clone(),
        ],
        cid_registry,
        tokens,
        |epoch, frame, path| {
            on_close(epoch, frame, path);
            Ok(())
        },
        |_, frame, path| match frame {
            Frame::PathResponse(frame) => {
                paths.on_path_response(path, frame);
                Ok(())
            }
            Frame::HandshakeDone(_) if role == Role::Client => {
                on_handshake_done();
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
        packets,
        Epoch::Data,
        sender.spaces.data.keys.clone(),
        sender.spaces.data.rcvd_journal.clone(),
        |pathway, _| paths.on_incoming_path(pathway).ok(),
        |keys: &OneRttKeys, packet, pathway| {
            if !belongs_to_scope(&pathway) {
                return Ok(None);
            }
            keys.open_packet(
                packet,
                |pn| sender.spaces.data.rcvd_journal.decode_pn(pn),
                paths.pto_for(&pathway, Epoch::Data),
            )
        },
        |epoch, path| {
            inspect(epoch, path);
            Ok(())
        },
        |keys, epoch, frame, path, link| {
            match frame {
                Frame::AddAddress(frame) => sender.puncher.recv_add_address(frame),
                Frame::RemoveAddress(frame) => {
                    // Unknown sequence numbers are ignored; do not truncate a
                    // wire VarInt into an existing 32-bit punch address ID.
                    if let Ok(seq) = u32::try_from(frame.seq_num.into_u64()) {
                        sender.puncher.recv_remove_address(seq);
                    }
                }
                Frame::PunchMeNow(frame) => sender.puncher.recv_punch_me_now(path.pathway, frame),
                Frame::PunchHello(frame) => {
                    sender.puncher.recv_punch_hello(path.pathway, link, frame);
                }
                Frame::PunchDone(frame) => sender.puncher.recv_punch_done(link, frame),
                frame => {
                    return dispatch(epoch, frame, path, &|generation| keys.on_ack(generation));
                }
            }
            Ok(())
        },
        |error| {
            sender.spaces.data.streams.on_conn_error(&error);
            sender.flow.on_conn_error(&error);
            on_error(error);
        },
    )
    .await;
}

/// Connection-level deadlines continue even when a path disappears.
#[expect(dead_code, reason = "started with the external path sender")]
pub(crate) async fn tick(
    phase: crate::ArcConnPhase,
    paths: Arc<Paths>,
    terminator: crate::terminate::ArcTerminator,
    closed: ArcReceiving<CloseReason>,
) {
    while matches!(&*terminator.lock_guard(), Terminator::NoError(_)) {
        let now = Instant::now();
        let snapshot = phase.get();
        match &snapshot {
            crate::ConnPhase::Initial(phase) => phase.initial.on_tick(now),
            crate::ConnPhase::Handshake(phase) => {
                phase.initial.on_tick(now);
                phase.handshake.on_tick(now);
            }
            crate::ConnPhase::Mature(phase) => {
                phase.spaces.initial.on_tick(now);
                phase.spaces.handshake.on_tick(now);
                phase.spaces.data.on_tick(now);
            }
        }
        let active_paths = paths.snapshot();
        for path in &active_paths {
            path.activity.on_tick(now);
        }
        let pto = active_paths
            .iter()
            .map(|p| p.cc.pto_base(Epoch::Data))
            .max()
            .unwrap_or(std::time::Duration::from_secs(1));
        if matches!(&*terminator.lock_guard(), Terminator::NoError(_))
            && active_paths
                .first()
                .is_some_and(|path| path.activity.timed_out(now, pto))
        {
            closed.set(CloseReason::Internal(QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                "connection idle timeout",
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
#[path = "recv/punch_tests.rs"]
mod punch_tests;

#[cfg(test)]
mod tests {
    use std::{task::Poll, time::Duration};

    use bytes::BytesMut;
    use qbase::{
        cid::ConnectionId,
        frame::{AckFrame, PingFrame},
        net::addr::EndpointAddr,
        packet::{DataHeader, LongHeaderBuilder, Packet, PacketReader, long},
        time::ArcConnIdle,
    };
    use qrecovery::journal::ArcSentJournal;
    use qtransport::packet::CipherPacket;

    use super::*;
    use crate::{ArcConnPhase, InitialPhase};

    pub(super) fn keys(server: bool) -> qtls::BidirectionalKeys {
        qtls::default_provider()
            .cipher_suites
            .iter()
            .find_map(|suite| suite.tls13().and_then(|suite| suite.quic_suite()))
            .unwrap()
            .keys(
                b"original",
                if server {
                    tls_backend::Side::Server
                } else {
                    tls_backend::Side::Client
                },
                tls_backend::quic::Version::V1,
            )
            .into()
    }

    fn seal<H, const N: usize>(
        header: H,
        keys: &qtls::DirectionalKeys,
        journal: &ArcSentJournal,
        sources: [&mut dyn for<'b> qbase::packet::assemble::Package<&'b mut BytesMut>; N],
    ) -> Result<BytesMut, crate::Error>
    where
        H: qbase::packet::HeaderSize + qbase::packet::GetType,
        for<'a> &'a mut BytesMut: qbase::packet::header::io::WriteHeader<H>,
    {
        use qbase::packet::assemble::Assemble;
        let mut buffer = BytesMut::with_capacity(1200);
        let pn = journal.next_pn().unwrap();
        let packet = crate::send::Packet::new(header, pn, &mut buffer)?;
        let mut limits = qbase::packet::assemble::Constraints {
            flow_ctrl: usize::MAX,
            send_quota: 1200,
            credit: 1200,
            min_size: 1200,
            max_size: 1200,
            ..Default::default()
        };
        let mut packet = crate::send::SendingPacket {
            packet,
            keys,
            limits: &mut limits,
        };
        let mut frames = Vec::new();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            matches!(packet.assemble(&mut cx, sources.map(|source| source as &mut dyn qbase::packet::Package<&mut BytesMut>), &mut frames), Poll::Ready(Ok(n)) if n > 0)
        );
        packet.seal()?;
        journal.on_assembled(pn.0, None, frames.drain(..));
        Ok(buffer)
    }

    async fn receive_ping(
        role: Role,
        epoch: Epoch,
        corrupt: bool,
        paths: &Arc<Paths>,
        path: &Arc<Path>,
    ) -> Requirements {
        let space = Arc::new(Space::<ArcKeys>::new(
            epoch,
            ArcKeys::new(Arc::new(keys(role == Role::Server))),
        ));
        let keys = keys(role != Role::Server);
        let header = LongHeaderBuilder::with_cid(
            ConnectionId::from_slice(b"localcid"),
            ConnectionId::from_slice(b"peercid0"),
        );
        let journal = ArcSentJournal::default();
        let mut ping = PingFrame;
        let packet = if epoch == Epoch::Initial {
            seal(header.initial(vec![]), &keys.sealing, &journal, [&mut ping])
        } else {
            seal(header.handshake(), &keys.sealing, &journal, [&mut ping])
        }
        .unwrap();
        let mut bytes = BytesMut::from(packet.as_ref());
        if corrupt {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        receive_bytes(bytes, space, paths, path).await
    }

    async fn receive_bytes(
        bytes: BytesMut,
        space: Arc<Space<ArcKeys>>,
        paths: &Arc<Paths>,
        path: &Arc<Path>,
    ) -> Requirements {
        let requirements = Arc::new(Mutex::new(match paths.role() {
            Role::Client => Requirements::new_client(ConnectionId::from_slice(b"original")),
            Role::Server => Requirements::new_server(),
        }));
        let Packet::Data(packet) = PacketReader::new(bytes, 8).next().unwrap().unwrap() else {
            panic!()
        };
        let link = Link::new(
            "127.0.0.1:30001".parse().unwrap(),
            "127.0.0.1:30002".parse().unwrap(),
        );
        match packet.header {
            DataHeader::Long(long::DataHeader::Initial(header)) => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                tx.try_send((
                    CipherPacket::new(header, packet.bytes, packet.offset),
                    path.pathway,
                    link,
                ))
                .unwrap();
                drop(tx);
                recv_ih_pkt_and_deliver_frames_if(
                    rx,
                    space,
                    paths.clone(),
                    paths.closed(),
                    requirements.clone(),
                    |_| true,
                )
                .await;
            }
            DataHeader::Long(long::DataHeader::Handshake(header)) => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                tx.try_send((
                    CipherPacket::new(header, packet.bytes, packet.offset),
                    path.pathway,
                    link,
                ))
                .unwrap();
                drop(tx);
                recv_ih_pkt_and_deliver_frames_if(
                    rx,
                    space,
                    paths.clone(),
                    paths.closed(),
                    requirements.clone(),
                    |_| true,
                )
                .await;
            }
            _ => panic!(),
        }
        *requirements.lock().unwrap()
    }

    fn paths(role: Role) -> (Arc<Paths>, Arc<Path>, Arc<Path>) {
        let phase = ArcConnPhase::initial(InitialPhase::new(
            ConnectionId::from_slice(b"localcid"),
            ConnectionId::from_slice(b"original"),
            keys(role == Role::Server),
        ));
        let paths = Paths::new(
            role,
            phase,
            ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO),
        );
        let local = EndpointAddr::direct("127.0.0.1:30001".parse().unwrap());
        let first = paths
            .add_path(Pathway::new(
                local,
                EndpointAddr::direct("127.0.0.1:30002".parse().unwrap()),
            ))
            .unwrap();
        let second = paths
            .add_path(Pathway::new(
                local,
                EndpointAddr::direct("127.0.0.1:30003".parse().unwrap()),
            ))
            .unwrap();
        (paths, first, second)
    }

    #[tokio::test]
    async fn handshake_reception_admits_unknown_paths_only_after_authentication() {
        for role in [Role::Client, Role::Server] {
            for epoch in [Epoch::Initial, Epoch::Handshake] {
                let (paths, first, _) = paths(role);
                for path in paths.snapshot() {
                    paths.remove(&path);
                }
                assert!(paths.snapshot().is_empty());

                receive_ping(role, epoch, true, &paths, &first).await;
                assert!(paths.snapshot().is_empty(), "forged packet admitted a path");

                receive_ping(role, epoch, false, &paths, &first).await;
                let admitted = paths.snapshot();
                assert_eq!(admitted.len(), 1);
                assert_eq!(admitted[0].pathway, first.pathway);
                assert!(!Arc::ptr_eq(&admitted[0], &first));
                if epoch == Epoch::Initial {
                    assert!(matches!(
                        admitted[0].state(),
                        qtransport::path::PathState::AmplifyGuard {
                            rcvd_bytes: 1200,
                            sent_bytes: 0,
                        }
                    ));
                }
                paths.retire_all();
            }
        }
    }

    #[tokio::test]
    async fn only_authenticated_initial_packets_fill_cid_requirements() {
        for role in [Role::Client, Role::Server] {
            for epoch in [Epoch::Initial, Epoch::Handshake] {
                for corrupt in [true, false] {
                    let (paths, first, _) = paths(role);
                    let requirements = receive_ping(role, epoch, corrupt, &paths, &first).await;
                    let initial_scid = match requirements {
                        Requirements::Client {
                            initial_scid,
                            origin_dcid,
                            retry_scid,
                        } => {
                            assert_eq!(origin_dcid, ConnectionId::from_slice(b"original"));
                            assert_eq!(retry_scid, None);
                            initial_scid
                        }
                        Requirements::Server { initial_scid } => initial_scid,
                    };
                    assert_eq!(
                        initial_scid,
                        (!corrupt && epoch == Epoch::Initial)
                            .then(|| ConnectionId::from_slice(b"peercid0"))
                    );
                    paths.retire_all();
                }
            }
        }
    }

    #[tokio::test]
    async fn client_selects_authenticated_initial_or_handshake_instead_of_first_added_path() {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            let (paths, first, second) = paths(Role::Client);
            let original_dcid = paths.phase().get().dcid();
            assert_eq!(
                (first.selected(), second.selected()),
                (Path::MP_INITIAL, Path::MP_INITIAL)
            );
            receive_ping(Role::Client, epoch, true, &paths, &first).await;
            assert_eq!(
                (first.selected(), second.selected()),
                (Path::MP_INITIAL, Path::MP_INITIAL)
            );
            assert_eq!(paths.phase().get().dcid(), original_dcid);
            receive_ping(Role::Client, epoch, false, &paths, &second).await;
            assert_eq!(
                (first.selected(), second.selected()),
                (Path::SUSPEND, Path::SELECTED)
            );
            if epoch == Epoch::Initial {
                assert_eq!(
                    paths.phase().get().dcid(),
                    ConnectionId::from_slice(b"peercid0")
                );
            }
            receive_ping(Role::Client, epoch, false, &paths, &first).await;
            assert_eq!(
                (first.selected(), second.selected()),
                (Path::SUSPEND, Path::SELECTED)
            );
            paths.retire_all();
        }
    }

    #[tokio::test]
    async fn server_initial_does_not_select_but_authenticated_handshake_does() {
        let (paths, first, second) = paths(Role::Server);
        receive_ping(Role::Server, Epoch::Initial, false, &paths, &first).await;
        assert_eq!(
            (first.selected(), second.selected()),
            (Path::MP_INITIAL, Path::MP_INITIAL)
        );
        receive_ping(Role::Server, Epoch::Handshake, true, &paths, &first).await;
        assert_eq!(
            (first.selected(), second.selected()),
            (Path::MP_INITIAL, Path::MP_INITIAL)
        );
        receive_ping(Role::Server, Epoch::Handshake, false, &paths, &second).await;
        assert_eq!(
            (first.selected(), second.selected()),
            (Path::SUSPEND, Path::SELECTED)
        );
        paths.retire_all();
    }
    #[tokio::test]
    async fn server_selects_initial_ack_of_crypto_but_not_ack_of_ping() {
        use qcongestion::Transport as _;
        use tokio::io::AsyncWriteExt;

        let (paths, first, second) = paths(Role::Server);
        let space = Arc::new(Space::<ArcKeys>::new(
            Epoch::Initial,
            ArcKeys::new(Arc::new(keys(true))),
        ));
        let server_keys = keys(true);
        first.validate();
        let header = || {
            LongHeaderBuilder::with_cid(
                ConnectionId::from_slice(b"peercid0"),
                ConnectionId::from_slice(b"localcid"),
            )
        };
        space
            .crypto
            .writer()
            .write_all(b"server hello")
            .await
            .unwrap();
        let mut ping = PingFrame;
        let packet = seal(
            header().initial(vec![]),
            &server_keys.sealing,
            &space.sent_journal,
            [&mut ping],
        )
        .unwrap();
        drop(packet);
        let mut crypto = space.crypto.outgoing();
        let packet = seal(
            header().initial(vec![]),
            &server_keys.sealing,
            &space.sent_journal,
            [&mut crypto],
        )
        .unwrap();
        drop(packet);
        for pn in [0, 1] {
            space
                .sent_journal
                .on_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
        }
        let client_keys = keys(false);
        let journal = ArcSentJournal::default();
        for pn in [0u32, 1] {
            let mut ack = AckFrame::new(pn.into(), 0u32.into(), 0u32.into(), vec![], None);
            let packet = seal(
                header().initial(vec![]),
                &client_keys.sealing,
                &journal,
                [&mut ack],
            )
            .unwrap();
            receive_bytes(
                BytesMut::from(packet.as_ref()),
                space.clone(),
                &paths,
                &second,
            )
            .await;
            assert_eq!(
                (first.selected(), second.selected()),
                if pn == 1 {
                    (Path::SUSPEND, Path::SELECTED)
                } else {
                    (Path::MP_INITIAL, Path::MP_INITIAL)
                }
            );
        }
        assert!(second.cc.need_ack(Epoch::Initial).is_none());
        paths.retire_all();
    }
}
