//! Space nodes capture their pipes once; parameter completion only adds the Data node.
use std::sync::{Arc, OnceLock, atomic::Ordering};

use qbase::{
    ArcReceiving, Epoch,
    error::{ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, Frame, io::ReceiveFrame},
    net::route::{Link, Pathway},
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

use crate::{ArcParameters, BelongsTo, CloseReason, MaturePhase, Paths, Scopes};

pub type PacketReceiver<H> = qtransport::packet::channel::PacketReceiver<H>;

pub(crate) async fn recv_ih_pkt_and_deliver_frames<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
) where
    H: GetScid + GetType + qtransport::packet::RcvdPacketHeader,
{
    recv_ih_pkt_and_deliver_frames_if(packets, space, paths, closed, |_| true).await;
}

pub(crate) async fn recv_server_ih_pkt_and_deliver_frames<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
    scopes: Scopes,
) where
    H: GetScid + GetType + qtransport::packet::RcvdPacketHeader,
{
    recv_ih_pkt_and_deliver_frames_if(packets, space, paths, closed, move |link| {
        link.src.belongs_to(scopes)
    })
    .await;
}

pub(crate) async fn recv_pending_server_initial(
    packets: PacketReceiver<qbase::packet::InitialHeader>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
    scopes: Arc<OnceLock<Scopes>>,
) {
    recv_ih_pkt_and_deliver_frames_if(packets, space, paths, closed, move |link| {
        scopes
            .get()
            .is_none_or(|scopes| link.src.belongs_to(*scopes))
    })
    .await;
}

async fn recv_ih_pkt_and_deliver_frames_if<H>(
    packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
    belongs_to_scope: impl Fn(&Link) -> bool,
) where
    H: GetScid + GetType + qtransport::packet::RcvdPacketHeader,
{
    let initial_scid = Arc::new(std::sync::OnceLock::new());
    recv::run_receive(
        packets,
        space.clone(),
        {
            let paths = paths.clone();
            move |pathway, link| {
                belongs_to_scope(&link)
                    .then(|| paths.get(&pathway))
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
        Arc::default(),
        {
            let closed = closed.clone();
            let space = space.clone();
            move |_, epoch, frame, path| match frame {
                Frame::Padding(_) | Frame::Ping(_) => Ok(()),
                Frame::Crypto(frame, bytes) => space.crypto.incoming().recv_frame((frame, bytes)),
                Frame::Ack(frame) => {
                    let mut cc = path.cc.lock();
                    space.send_journal.acknowledge(&frame, |frame| {
                        if let GuaranteedFrame::Crypto(frame) = frame {
                            space.crypto.outgoing().on_data_acked(frame);
                        }
                    })?;
                    cc.on_ack_rcvd(epoch, &frame, Instant::now());
                    Ok(())
                }
                Frame::Close(frame) => {
                    closed.set(CloseReason::Peer(frame));
                    Ok(())
                }
                _ => Err(QuicError::with_default_fty(
                    ErrorKind::ProtocolViolation,
                    "unexpected handshake frame",
                )
                .into()),
            }
        },
        move |_, path| {
            path.activity
                .on_rcvd(qbase::packet::PacketContent::default());
            if let Some(dcid) = initial_scid.get() {
                path.set_dcid(*dcid);
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
    local_cids: crate::ArcLocalCids,
    remote_cids: qbase::cid::ArcRemoteCids<crate::ReliableFrames>,
    tokens: ArcTokenRegistry,
    closed: ArcReceiving<CloseReason>,
    on_handshake_done: impl Fn() + Send + Sync,
) {
    receive_data(
        packets,
        sender,
        {
            let paths = paths.clone();
            move |pathway, _| paths.get(&pathway)
        },
        parameters,
        local_cids,
        remote_cids,
        tokens,
        Arc::default(),
        None,
        {
            let closed = closed.clone();
            move |frame| closed.set(CloseReason::Peer(frame))
        },
        |_, path| {
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
    local_cids: crate::ArcLocalCids,
    remote_cids: qbase::cid::ArcRemoteCids<crate::ReliableFrames>,
    tokens: ArcTokenRegistry,
    closed: ArcReceiving<CloseReason>,
    scopes: Scopes,
) {
    receive_data(
        packets,
        sender,
        {
            let paths = paths.clone();
            move |pathway, link| {
                link.src
                    .belongs_to(scopes)
                    .then(|| paths.get(&pathway))
                    .flatten()
            }
        },
        parameters,
        local_cids,
        remote_cids,
        tokens,
        Arc::default(),
        None,
        {
            let closed = closed.clone();
            move |frame| closed.set(CloseReason::Peer(frame))
        },
        |_, path| {
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
    path_for: impl FnMut(Pathway, Link) -> Option<Arc<Path>>,
    parameters: ArcParameters,
    local_cids: crate::ArcLocalCids,
    remote_cids: qbase::cid::ArcRemoteCids<crate::ReliableFrames>,
    tokens: ArcTokenRegistry,
    closing: Arc<std::sync::atomic::AtomicBool>,
    ready: Option<ArcReceiving<bool>>,
    on_close: impl Fn(ConnectionCloseFrame) + Send + Sync,
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
        local_cids,
        remote_cids,
        tokens,
        closing.clone(),
        |_, frame, _| {
            on_close(frame);
            Ok(())
        },
        |_, frame, _| match frame {
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
        closing.clone(),
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
    terminator: Arc<crate::terminator::Terminator>,
    closed: ArcReceiving<CloseReason>,
) {
    while !terminator.terminated.load(Ordering::Acquire) {
        let now = Instant::now();
        let snapshot = phase.get();
        for space in std::iter::once(snapshot.initial()).chain(snapshot.handshake()) {
            space.on_tick(now);
        }
        if let Some(sender) = snapshot.material() {
            sender.spaces.data.on_tick(now);
        }
        let active_paths = paths.snapshot();
        let pto = active_paths
            .iter()
            .map(|p| p.cc.pto_base(Epoch::Data))
            .max()
            .unwrap_or(std::time::Duration::from_secs(1));
        if !terminator.closing.load(Ordering::Acquire)
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
