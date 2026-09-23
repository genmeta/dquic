//! Space nodes capture their pipes once; parameter completion only adds the Data node.
use std::sync::{Arc, OnceLock};

use qbase::{
    ArcReceiving, Epoch,
    error::{ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, Frame, io::ReceiveFrame},
    net::route::{Link, Pathway, Scopes},
    packet::{GetScid, GetType, OneRttHeader},
    role::Role,
    token::ArcTokenRegistry,
};
use qtransport::{
    GuaranteedFrame,
    keys::{ArcKeys, OneRttKeys},
    path::Path,
    recv,
    space::Space,
};
use tokio::time::Instant;

use crate::{
    ArcParameters, CloseReason, MaturePhase, Paths,
    terminate::{ArcTerminator, State},
};

pub type PacketReceiver<H> = qtransport::packet::channel::PacketReceiver<H>;

pub(crate) async fn recv_client_ih_pkt_and_deliver_frames<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    terminator: ArcTerminator,
    closed: ArcReceiving<CloseReason>,
) where
    H: GetScid + GetType + qtransport::packet::RcvdPacketHeader,
{
    recv_ih_pkt_and_deliver_frames_if(packets, space, paths, terminator, closed, |_| true).await;
}

pub(crate) async fn recv_server_ih_pkt_and_deliver_frames<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    terminator: ArcTerminator,
    closed: ArcReceiving<CloseReason>,
    scopes: Scopes,
) where
    H: GetScid + GetType + qtransport::packet::RcvdPacketHeader,
{
    recv_ih_pkt_and_deliver_frames_if(packets, space, paths, terminator, closed, move |pathway| {
        pathway.belongs_to(scopes)
    })
    .await;
}

pub(crate) async fn recv_pending_server_initial(
    packets: PacketReceiver<qbase::packet::InitialHeader>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    terminator: ArcTerminator,
    closed: ArcReceiving<CloseReason>,
    scopes: Arc<OnceLock<Scopes>>,
) {
    recv_ih_pkt_and_deliver_frames_if(packets, space, paths, terminator, closed, move |pathway| {
        scopes
            .get()
            .is_none_or(|scopes| pathway.belongs_to(*scopes))
    })
    .await;
}

async fn recv_ih_pkt_and_deliver_frames_if<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    terminator: ArcTerminator,
    closed: ArcReceiving<CloseReason>,
    belongs_to_scope: impl Fn(&Pathway) -> bool,
) where
    H: GetScid + GetType + qtransport::packet::RcvdPacketHeader,
{
    let role = paths.role();
    let ack_paths = paths.clone();
    let initial_scid = Arc::new(std::sync::OnceLock::new());
    let close_paths = paths.clone();
    let processed_paths = paths.clone();
    recv::run_receive(
        packets,
        space.clone(),
        {
            let paths = paths.clone();
            move |pathway, _| {
                belongs_to_scope(&pathway)
                    .then(|| paths.on_incoming_path(pathway).ok())
                    .flatten()
            }
        },
        {
            let space = space.clone();
            let initial_scid = initial_scid.clone();
            move |keys: &Arc<qtls::BidirectionalKeys>, packet, _pto| {
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
        move || !matches!(&terminator.lock_guard().state, State::Normal),
        {
            let space = space.clone();
            move |_, epoch, frame, path| match frame {
                Frame::Padding(_) | Frame::Ping(_) => Ok(()),
                Frame::Crypto(frame, bytes) => space.crypto.incoming().recv_frame((frame, bytes)),
                Frame::Ack(frame) => {
                    let mut cc = path.cc.lock();
                    let mut crypto_acked = false;
                    space.send_journal.acknowledge(&frame, |frame| {
                        if let GuaranteedFrame::Crypto(frame) = frame {
                            crypto_acked |= frame.len() > 0;
                            space.crypto.outgoing().on_data_acked(frame);
                        }
                    })?;
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
        move |epoch, path| {
            processed_paths.on_rcvd_packet();
            path.activity
                .on_rcvd(qbase::packet::PacketContent::default());
            if let Some(dcid) = initial_scid.get() {
                path.set_dcid(*dcid);
            }
            if role == Role::Client || epoch == Epoch::Handshake {
                processed_paths.select_path(path);
            }
            if epoch == Epoch::Handshake && (role == Role::Server || path.is_selected()) {
                path.validate();
            }
            Ok(())
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
    let terminator = sender.terminator.clone();
    let close_paths = paths.clone();
    let processed_paths = paths.clone();
    receive_data(
        packets,
        sender,
        paths.clone(),
        {
            let paths = paths.clone();
            move |pathway, _| paths.on_incoming_path(pathway).ok()
        },
        parameters,
        cid_registry,
        tokens,
        move || !matches!(&terminator.lock_guard().state, State::Normal),
        None,
        move |epoch, frame, path| close_paths.on_rcvd_close(epoch, path, frame),
        |_, path| {
            processed_paths.on_rcvd_packet();
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
    let terminator = sender.terminator.clone();
    let close_paths = paths.clone();
    let processed_paths = paths.clone();
    receive_data(
        packets,
        sender,
        paths.clone(),
        {
            let paths = paths.clone();
            move |pathway, _| {
                pathway
                    .belongs_to(scopes)
                    .then(|| paths.on_incoming_path(pathway).ok())
                    .flatten()
            }
        },
        parameters,
        cid_registry,
        tokens,
        move || !matches!(&terminator.lock_guard().state, State::Normal),
        None,
        move |epoch, frame, path| close_paths.on_rcvd_close(epoch, path, frame),
        |_, path| {
            processed_paths.on_rcvd_packet();
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
    path_for: impl FnMut(Pathway, Link) -> Option<Arc<Path>>,
    parameters: ArcParameters,
    cid_registry: crate::CidRegistry,
    tokens: ArcTokenRegistry,
    is_closing: impl Fn() -> bool + Sync,
    ready: Option<ArcReceiving<bool>>,
    on_close: impl Fn(Epoch, ConnectionCloseFrame, &Arc<Path>) + Send + Sync,
    on_processed: impl Fn(Epoch, &Arc<Path>),
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
        sender.streams.clone(),
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
        sender.spaces.data.clone(),
        path_for,
        |keys: &OneRttKeys, packet, pto| {
            keys.open_packet(
                packet,
                |pn| sender.spaces.data.rcvd_journal.decode_pn(pn),
                pto,
            )
        },
        is_closing,
        |keys, epoch, frame, path| {
            dispatch(epoch, frame, path, &|generation| keys.on_ack(generation))
        },
        |epoch, path| {
            on_processed(epoch, path);
            Ok(())
        },
        |error| {
            sender.streams.on_conn_error(&error);
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
    while matches!(&terminator.lock_guard().state, State::Normal) {
        let now = Instant::now();
        let snapshot = phase.get();
        match &snapshot {
            crate::ConnPhase::Initial(phase) => phase.initial.on_tick(now),
            crate::ConnPhase::Handshake(phase) => {
                phase.initial.initial.on_tick(now);
                phase.handshake.on_tick(now);
            }
            crate::ConnPhase::Mature(phase) => {
                phase.spaces.initial.on_tick(now);
                phase.spaces.handshake.on_tick(now);
                phase.spaces.data.on_tick(now);
            }
        }
        let active_paths = paths.snapshot();
        let pto = active_paths
            .iter()
            .map(|p| p.cc.pto_base(Epoch::Data))
            .max()
            .unwrap_or(std::time::Duration::from_secs(1));
        if matches!(&terminator.lock_guard().state, State::Normal)
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
mod tests {
    use std::time::Duration;

    use bytes::BytesMut;
    use qbase::{
        cid::ConnectionId,
        frame::{AckFrame, PingFrame},
        net::addr::EndpointAddr,
        packet::{DataHeader, LongHeaderBuilder, Packet, PacketReader, long},
        time::ArcConnIdle,
    };
    use qtransport::{
        packet::CipherPacket,
        send::{self, constraints::Constraints, records::ArcSendJournal},
    };

    use super::*;
    use crate::{ArcConnPhase, InitialPhase};

    fn keys(server: bool) -> qtls::BidirectionalKeys {
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

    async fn receive_ping(
        role: Role,
        epoch: Epoch,
        corrupt: bool,
        paths: &Arc<Paths>,
        path: &Arc<Path>,
    ) {
        let space = Arc::new(Space::<ArcKeys>::new(
            epoch,
            paths.phase().send_wakers(),
            |_| {},
        ));
        space
            .keys
            .install(Arc::new(keys(role == Role::Server)))
            .unwrap();
        let mut buffers = vec![BytesMut::with_capacity(1200)];
        let mut send_frames = Vec::new();
        let mut pns = std::collections::VecDeque::new();
        let mut signals = qbase::net::tx::Signals::empty();
        let keys = keys(role != Role::Server);
        let header = LongHeaderBuilder::with_cid(
            ConnectionId::from_slice(b"localcid"),
            ConnectionId::from_slice(b"peercid0"),
        );
        let constraints = Constraints {
            capacity: 1200,
            congestion: 1200,
            anti_amplification: 1200,
        };
        let journal = ArcSendJournal::default();
        let mut ping = PingFrame;
        let packet = if epoch == Epoch::Initial {
            send::assemble_long_packet(
                path.pathway,
                &path.cc,
                &mut buffers,
                &mut send_frames,
                &mut pns,
                &mut signals,
                &keys.sealing,
                header.initial(vec![]),
                &journal,
                &constraints,
                [&mut ping],
            )
        } else {
            send::assemble_long_packet(
                path.pathway,
                &path.cc,
                &mut buffers,
                &mut send_frames,
                &mut pns,
                &mut signals,
                &keys.sealing,
                header.handshake(),
                &journal,
                &constraints,
                [&mut ping],
            )
        }
        .unwrap()
        .unwrap();
        let mut bytes = BytesMut::from(packet.bytes());
        if corrupt {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        receive_bytes(bytes, space, paths, path).await;
    }

    async fn receive_bytes(
        bytes: BytesMut,
        space: Arc<Space<ArcKeys>>,
        paths: &Arc<Paths>,
        path: &Arc<Path>,
    ) {
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
                    paths.terminator(),
                    paths.closed(),
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
                    paths.terminator(),
                    paths.closed(),
                    |_| true,
                )
                .await;
            }
            _ => panic!(),
        }
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
    async fn client_selects_authenticated_initial_or_handshake_instead_of_first_added_path() {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            let (paths, first, second) = paths(Role::Client);
            assert!(!first.is_selected() && !second.is_selected());
            receive_ping(Role::Client, epoch, true, &paths, &first).await;
            assert!(!first.is_selected() && !second.is_selected());
            receive_ping(Role::Client, epoch, false, &paths, &second).await;
            assert!(!first.is_selected() && second.is_selected());
            receive_ping(Role::Client, epoch, false, &paths, &first).await;
            assert!(!first.is_selected() && second.is_selected());
            paths.retire_all();
        }
    }

    #[tokio::test]
    async fn server_initial_does_not_select_but_authenticated_handshake_does() {
        let (paths, first, second) = paths(Role::Server);
        receive_ping(Role::Server, Epoch::Initial, false, &paths, &first).await;
        assert!(!first.is_selected() && !second.is_selected());
        receive_ping(Role::Server, Epoch::Handshake, true, &paths, &first).await;
        assert!(!first.is_selected() && !second.is_selected());
        receive_ping(Role::Server, Epoch::Handshake, false, &paths, &second).await;
        assert!(!first.is_selected() && second.is_selected());
        paths.retire_all();
    }
    #[tokio::test]
    async fn server_selects_initial_ack_of_crypto_but_not_ack_of_ping() {
        use qcongestion::Transport as _;
        use tokio::io::AsyncWriteExt;

        let (paths, first, second) = paths(Role::Server);
        let space = Arc::new(Space::<ArcKeys>::new(
            Epoch::Initial,
            paths.phase().send_wakers(),
            |_| {},
        ));
        let server_keys = keys(true);
        space.keys.install(Arc::new(keys(true))).unwrap();
        first.validate();
        let mut buffers = vec![BytesMut::with_capacity(1200)];
        let mut send_frames = Vec::new();
        let mut pns = std::collections::VecDeque::new();
        let mut signals = qbase::net::tx::Signals::empty();
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
        let constraints = Constraints {
            capacity: 1200,
            congestion: 2400,
            anti_amplification: 2400,
        };
        let mut ping = PingFrame;
        let packet = send::assemble_long_packet(
            first.pathway,
            &first.cc,
            &mut buffers,
            &mut send_frames,
            &mut pns,
            &mut signals,
            &server_keys.sealing,
            header().initial(vec![]),
            &space.send_journal,
            &constraints,
            [&mut ping],
        )
        .unwrap()
        .unwrap();
        pns.push_back(packet);
        let mut crypto = space.crypto.outgoing();
        let packet = send::assemble_long_packet(
            first.pathway,
            &first.cc,
            &mut buffers,
            &mut send_frames,
            &mut pns,
            &mut signals,
            &server_keys.sealing,
            header().initial(vec![]),
            &space.send_journal,
            &constraints,
            [&mut crypto],
        )
        .unwrap()
        .unwrap();
        pns.push_back(packet);
        for pn in [0, 1] {
            space
                .send_journal
                .mark_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
        }
        let client_keys = keys(false);
        let journal = ArcSendJournal::default();
        let constraints = Constraints {
            capacity: 1200,
            congestion: 1200,
            anti_amplification: 1200,
        };
        for pn in [0u32, 1] {
            let mut ack = AckFrame::new(pn.into(), 0u32.into(), 0u32.into(), vec![], None);
            let packet = send::assemble_long_packet(
                first.pathway,
                &first.cc,
                &mut buffers,
                &mut send_frames,
                &mut pns,
                &mut signals,
                &client_keys.sealing,
                header().initial(vec![]),
                &journal,
                &constraints,
                [&mut ack],
            )
            .unwrap()
            .unwrap();
            receive_bytes(
                BytesMut::from(packet.bytes()),
                space.clone(),
                &paths,
                &second,
            )
            .await;
            assert!(!first.is_selected());
            assert_eq!(second.is_selected(), pn == 1);
        }
        assert!(second.cc.need_ack(Epoch::Initial).is_none());
        paths.retire_all();
    }
}
