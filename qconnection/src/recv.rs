//! Space nodes capture their pipes once; parameter completion only adds the Data node.
use std::sync::Arc;

#[cfg(test)]
use qbase::net::route::{Link, Pathway};
use qbase::{
    ArcReceiving, Epoch,
    error::{ErrorKind, QuicError},
    frame::{Frame, FrameReader, GetFrameType, io::ReceiveFrame},
    handshake::ArcHandshake,
    net::route::Scopes,
    packet::{GetScid, GetType, OneRttHeader, PacketContent},
    role::Role,
    token::ArcTokenRegistry,
};
use qcongestion::Transport as _;
#[cfg(test)]
use qtransport::path::Path;
use qtransport::{keys::ArcKeys, packet::RcvdPacketHeader, recv, space::Space};
use tokio::time::Instant;

use crate::{
    ArcParameters, ArcReliableFrames, CloseReason, MaturePhase, Paths, terminate::Terminator,
};

pub type PacketReceiver<H> = qtransport::packet::channel::PacketReceiver<H>;

pub(crate) async fn recv_ih_pkt_and_deliver_frames<H>(
    (mut packets, scopes): (PacketReceiver<H>, Option<Scopes>),
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
) where
    H: GetScid + GetType + RcvdPacketHeader,
{
    let role = paths.role();
    let epoch = space.epoch;
    let mut initial_scid = None;
    let mut parsed_frames = Vec::with_capacity(8);
    while let Some((packet, pathway, _)) = packets.recv().await {
        parsed_frames.clear();
        let received_bytes = packet.payload_len();
        let Ok(keys) = space.keys.get() else {
            break;
        };
        if scopes.is_some_and(|scopes| !pathway.belongs_to(scopes)) {
            continue;
        }
        let result = (|| -> Result<(), crate::Error> {
            let scid = (epoch == Epoch::Initial).then(|| *packet.scid());
            let Some(packet) = packet
                .decrypt_long_packet(&keys.opening, |pn| space.rcvd_journal.decode_pn(pn))
                .transpose()?
            else {
                return Ok(());
            };
            if let Some(scid) = scid {
                if initial_scid.is_some_and(|cid| cid != scid) {
                    return Ok(());
                }
                initial_scid = Some(scid);
            }
            let pn = packet.pn();
            let mut content = PacketContent::default();
            for frame in FrameReader::new(packet.body(), packet.get_type()) {
                let (frame, fty) = frame?;
                content += PacketContent::from(fty);
                if !matches!(frame, Frame::Padding(_)) {
                    parsed_frames.push(frame);
                }
            }
            // Admit paths only after authentication and complete frame parsing.
            let Ok(path) = paths.on_incoming_path(pathway) else {
                return Ok(());
            };
            path.on_datagram_received(received_bytes);
            paths.on_rcvd_packet();
            path.activity.on_rcvd(PacketContent::default());
            if let Some(dcid) = initial_scid {
                // This runs before CRYPTO delivery can wake the TLS consumer.
                paths.phase().set_dcid(dcid);
            }
            if role == Role::Client || epoch == Epoch::Handshake {
                paths.select_path(&path);
            }
            if epoch == Epoch::Handshake && paths.is_handshake_path(&path) {
                path.validate();
                paths.on_handshake_received();
            }
            // CLOSE takes priority over ordinary frame delivery.
            if let Some(Frame::Close(frame)) = parsed_frames
                .iter()
                .find(|frame| matches!(frame, Frame::Close(_)))
            {
                paths.on_rcvd_close(epoch, &path, frame.clone());
                return Ok(());
            }
            for frame in parsed_frames.drain(..) {
                match frame {
                    Frame::Ping(_) => {}
                    Frame::Crypto(frame, bytes) => {
                        space.crypto.incoming().recv_frame((frame, bytes))?;
                    }
                    Frame::Ack(frame) => {
                        let mut cc = path.cc.lock();
                        let crypto_acked = space.on_acked(&frame)?;
                        cc.on_ack_rcvd(epoch, &frame, Instant::now());
                        drop(cc);
                        if role == Role::Server && epoch == Epoch::Initial && crypto_acked {
                            paths.select_path(&path);
                        }
                    }
                    _ => {
                        return Err(QuicError::with_default_fty(
                            ErrorKind::ProtocolViolation,
                            "unexpected handshake frame",
                        )
                        .into());
                    }
                }
            }
            let pto = path.cc.get_pto(epoch);
            space
                .rcvd_journal
                .on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
            path.cc.on_pkt_rcvd(epoch, pn, content.is_ack_eliciting());
            path.send_waker.wake_all();
            Ok(())
        })();
        if let Err(error) = result {
            closed.set(error.into());
        }
    }
}

/// Receive Data packets and update the connection's paths, handshake and close state.
pub(crate) async fn receive_data(
    (mut packets, scopes): (PacketReceiver<OneRttHeader>, Option<Scopes>),
    sender: Arc<MaturePhase>,
    paths: Arc<Paths>,
    parameters: ArcParameters,
    cid_registry: crate::CidRegistry,
    tokens: ArcTokenRegistry,
    handshake: ArcHandshake<ArcReliableFrames>,
) {
    let closed = paths.closed();
    let data = &sender.spaces.data;
    let mut parsed_frames = Vec::with_capacity(8);
    while let Some((packet, pathway, link)) = packets.recv().await {
        parsed_frames.clear();
        let received_bytes = packet.payload_len();
        let Ok(keys) = data.keys.get() else {
            break;
        };
        if scopes.is_some_and(|scopes| !pathway.belongs_to(scopes)) {
            continue;
        }
        let result = (|| -> Result<(), crate::Error> {
            let Some(packet) = keys.open_packet(
                packet,
                |pn| data.rcvd_journal.decode_pn(pn),
                paths.pto_for(&pathway, Epoch::Data),
            )?
            else {
                return Ok(());
            };
            let pn = packet.pn();
            let mut content = PacketContent::default();
            for frame in FrameReader::new(packet.body(), packet.get_type()) {
                let (frame, fty) = frame?;
                content += PacketContent::from(fty);
                if !matches!(frame, Frame::Padding(_)) {
                    parsed_frames.push(frame);
                }
            }
            // Admit paths only after authentication and complete frame parsing.
            let Ok(path) = paths.on_incoming_path(pathway) else {
                return Ok(());
            };
            path.on_datagram_received(received_bytes);
            paths.on_rcvd_packet();
            path.activity.on_rcvd(PacketContent::default());
            // Start validation only after authentication and path admission.
            paths.start_validation(&path);
            // CLOSE reaches the control owner even when ordinary component pipes are full.
            if let Some(Frame::Close(frame)) = parsed_frames
                .iter()
                .find(|frame| matches!(frame, Frame::Close(_)))
            {
                let error = crate::Error::from(frame.clone());
                data.crypto.on_error(&error);
                data.streams.on_conn_error(&error);
                sender.flow.on_conn_error(&error);
                paths.on_rcvd_close(Epoch::Data, &path, frame.clone());
                return Ok(());
            }
            for frame in parsed_frames.drain(..) {
                let kind = frame.frame_type();
                match frame {
                    Frame::Ping(_) => {}
                    Frame::Ack(frame) => {
                        recv::acknowledge(data, &parameters, &frame, &path, |generation| {
                            keys.on_ack(generation)
                        })?;
                    }
                    Frame::Crypto(frame, bytes) => {
                        data.crypto.incoming().recv_frame((frame, bytes))?;
                    }
                    Frame::Stream(frame, bytes) => {
                        let fresh = data.streams.recv_frame((frame, bytes))?;
                        sender.flow.recver.on_new_rcvd(kind, fresh)?;
                    }
                    Frame::StreamCtl(frame) => {
                        let fresh = data.streams.recv_frame(frame)?;
                        sender.flow.recver.on_new_rcvd(kind, fresh)?;
                    }
                    Frame::MaxData(frame) => sender.flow.sender.recv_frame(frame)?,
                    Frame::DataBlocked(frame) => sender.flow.recver.recv_frame(frame)?,
                    Frame::NewConnectionId(frame) => {
                        cid_registry.remote.recv_frame(frame)?;
                    }
                    Frame::RetireConnectionId(frame) => {
                        cid_registry.local.recv_frame(frame)?;
                    }
                    Frame::NewToken(frame) => {
                        tokens.recv_frame(frame)?;
                    }
                    Frame::PathChallenge(frame) => path.recv_frame(frame)?,
                    Frame::PathResponse(frame) => paths.on_path_response(&path, frame),
                    Frame::HandshakeDone(frame) => {
                        handshake.recv_frame(frame)?;
                    }
                    Frame::AddAddress(frame) => sender.puncher.recv_add_address(frame),
                    Frame::RemoveAddress(frame) => {
                        // Unknown sequence numbers are ignored; do not truncate a
                        // wire VarInt into an existing 32-bit punch address ID.
                        if let Ok(seq) = u32::try_from(frame.seq_num.into_u64()) {
                            sender.puncher.recv_remove_address(seq);
                        }
                    }
                    Frame::PunchMeNow(frame) => {
                        sender.puncher.recv_punch_me_now(path.pathway, frame)
                    }
                    Frame::PunchHello(frame) => {
                        sender.puncher.recv_punch_hello(path.pathway, link, frame);
                    }
                    Frame::PunchDone(frame) => sender.puncher.recv_punch_done(link, frame),
                    _ => {
                        return Err(QuicError::with_default_fty(
                            ErrorKind::ProtocolViolation,
                            "unnegotiated frame",
                        )
                        .into());
                    }
                }
            }
            let pto = path.cc.get_pto(Epoch::Data);
            data.rcvd_journal
                .on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
            path.cc
                .on_pkt_rcvd(Epoch::Data, pn, content.is_ack_eliciting());
            path.send_waker.wake_all();
            Ok(())
        })();
        if let Err(error) = result {
            data.streams.on_conn_error(&error);
            sender.flow.on_conn_error(&error);
            closed.set(error.into());
        }
    }
}

/// Drive connection deadlines alongside its growing future, once per connection.
/// Path loss does not stop recovery; entering Closing or Draining ends this loop.
pub async fn tick(paths: Arc<Paths>) {
    let phase = paths.phase();
    let terminator = paths.terminator();
    let closed = paths.closed();
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
    ) {
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
                recv_ih_pkt_and_deliver_frames((rx, None), space, paths.clone(), paths.closed())
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
                recv_ih_pkt_and_deliver_frames((rx, None), space, paths.clone(), paths.closed())
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
    async fn only_authenticated_initial_packets_update_the_peer_cid() {
        for role in [Role::Client, Role::Server] {
            for epoch in [Epoch::Initial, Epoch::Handshake] {
                for corrupt in [true, false] {
                    let (paths, first, _) = paths(role);
                    receive_ping(role, epoch, corrupt, &paths, &first).await;
                    assert_eq!(
                        paths.phase().get().dcid(),
                        ConnectionId::from_slice(if !corrupt && epoch == Epoch::Initial {
                            b"peercid0"
                        } else {
                            b"original"
                        })
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
