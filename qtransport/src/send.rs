//! One Data sender per path. The external owner can poll it alongside handshake work.
pub mod constraints;
pub mod packet;
pub mod records;

use std::{
    io,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use packet::{OneRttPacket, PacketError, PendingPacket};
use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    frame::{AckFrame, Frame, PingFrame},
    net::tx::Signals,
    packet::{OneRttHeader, io::Repeat},
    param::ParameterId,
    varint::{VARINT_MAX, VarInt},
};
use qcongestion::Transport as _;
use qprotocol::protocol::quic::QuicProtocol;

use crate::{
    Error,
    keys::OneRttKeys,
    path::{Path, PathState},
    transport::Transport,
};

pub struct Sender {
    keys: OneRttKeys,
    transport: Arc<Transport>,
    path: Arc<Path>,
    buffer: BytesMut,
    pending: Option<PendingPacket>,
    heartbeat_pending: bool,
    signals: Signals,
}

impl Sender {
    /// The connection driver distributes ready keys before starting path senders.
    pub fn new(
        keys: OneRttKeys,
        transport: Arc<Transport>,
        path: Arc<Path>,
    ) -> Result<Self, Error> {
        if !Arc::ptr_eq(&path.submission, &transport.data.submission) {
            return Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "path and space must share the submission boundary",
            )
            .into());
        }
        if path.sender_active.swap(true, Ordering::AcqRel) {
            return Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "path already has a sending owner",
            )
            .into());
        }
        transport
            .data
            .send_wakers
            .replace(path.pathway, &path.send_waker);
        Ok(Self {
            keys,
            transport,
            path,
            buffer: BytesMut::zeroed(1200),
            pending: None,
            heartbeat_pending: false,
            signals: Signals::all(),
        })
    }

    pub fn heartbeat(&mut self) {
        self.heartbeat_pending = true;
        self.path.send_waker.wake_by(Signals::PING);
    }

    pub fn prepare(&mut self) -> Result<bool, Error> {
        if self.pending.is_some() {
            return Ok(true);
        }
        self.signals =
            Signals::TRANSPORT | Signals::CREDIT | Signals::KEYS | Signals::PATH_VALIDATE;
        if !self.transport.data.can_send() {
            return Ok(false);
        }
        if self.path.state() == PathState::Retired {
            return Err(
                QuicError::with_default_fty(ErrorKind::NoViablePath, "path retired").into(),
            );
        }
        self.transport
            .requeue(self.transport.data.sent_packets.take_lost());
        if !self.transport.data.sent_packets.has_capacity() {
            return Ok(false);
        }
        let tag_len = self.keys.tag_len();
        let overhead = QuicProtocol::packet_overhead(self.path.pathway);
        let probe = self.path.cc.need_send_ack_eliciting(Epoch::Data) != 0;
        let mut constraints = self.path.constraints(1200, probe);
        constraints.capacity = constraints.capacity.saturating_sub(overhead);
        constraints.congestion = constraints.congestion.saturating_sub(overhead);
        constraints.anti_amplification = constraints.anti_amplification.saturating_sub(overhead);
        let pn = self.transport.data.sent_packets.next_pn()?;
        self.buffer.resize(1200 - overhead, 0);
        let mut packet = OneRttPacket::new(
            std::mem::take(&mut self.buffer),
            OneRttHeader::new(Default::default(), self.path.dcid()),
            pn,
            tag_len,
        )
        .map_err(packet_error)?;
        let mut ack = self
            .path
            .cc
            .need_ack(Epoch::Data)
            .and_then(|(pn, time)| {
                self.transport
                    .data
                    .rcvd_packets
                    .gen_ack_frame_util(pn, time, 400)
                    .ok()
            })
            .map(|ack| {
                let exponent: u64 = self
                    .transport
                    .parameters
                    .local(ParameterId::AckDelayExponent)
                    .unwrap();
                AckFrame::new(
                    VarInt::from_u64(ack.largest()).unwrap(),
                    VarInt::from_u64(ack.delay() >> exponent).unwrap(),
                    VarInt::from_u64(ack.first_range()).unwrap(),
                    ack.ranges().clone(),
                    None,
                )
            });
        let mut response = self.path.response();
        let mut challenge = self.path.challenge()?;
        let mut crypto = self.transport.data.crypto.outgoing().package(Epoch::Data);
        let mut reliable = self.transport.reliable_frames.clone();
        let mut streams = Repeat(
            self.transport
                .streams
                .package(self.transport.flow.sender.clone(), false),
        );
        let mut ping = (self.heartbeat_pending || probe).then_some(PingFrame);
        let assembled = if self.heartbeat_pending {
            packet.assemble(&mut constraints, [&mut ping])
        } else if !self.path.is_validated() {
            packet.assemble(
                &mut constraints,
                [&mut ack, &mut response, &mut challenge, &mut ping],
            )
        } else {
            packet.assemble(
                &mut constraints,
                [
                    &mut ack,
                    &mut response,
                    &mut challenge,
                    &mut crypto,
                    &mut reliable,
                    &mut ping,
                    &mut streams,
                ],
            )
        };
        match assembled {
            Ok(_) => {}
            Err(PacketError::Blocked(signals)) => {
                self.signals |= signals;
                self.transport.requeue(packet.abort(&mut constraints));
                return Ok(false);
            }
            Err(error) => {
                self.transport.requeue(packet.abort(&mut constraints));
                return Err(packet_error(error));
            }
        }
        if packet
            .frames()
            .iter()
            .any(|frame| matches!(frame, Frame::PathChallenge(_) | Frame::PathResponse(_)))
            && packet.pad_to(1200 - overhead, &mut constraints).is_err()
        {
            self.transport.requeue(packet.abort(&mut constraints));
            return Ok(false);
        }
        let frames = packet.frames().to_vec();
        let pending = match packet.seal(&self.keys) {
            Ok(pending) => pending,
            Err(error) => {
                self.transport.requeue(frames);
                return Err(packet_error(error));
            }
        };
        if !self.transport.data.sent_packets.pending(
            pending.pn,
            &self.path,
            pending.generation,
            &pending.frames,
        ) {
            self.transport.requeue(pending.frames);
            return Ok(false);
        }
        self.heartbeat_pending = false;
        self.pending = Some(pending);
        Ok(true)
    }

    /// A nonblocking submission. Pending retains this exact ciphertext; a subsequent
    /// poll rechecks retirement, key generation and the largest submitted packet number.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        protocol: &QuicProtocol,
    ) -> Poll<Result<bool, Error>> {
        self.poll_send_with(cx, |cx, path, bytes| {
            protocol.poll_send_packet(cx, path, bytes)
        })
    }

    pub(crate) fn poll_send_with(
        &mut self,
        cx: &mut Context<'_>,
        mut submit: impl FnMut(
            &mut Context<'_>,
            qbase::net::route::Pathway,
            &[u8],
        ) -> Poll<io::Result<usize>>,
    ) -> Poll<Result<bool, Error>> {
        let Some(packet) = &self.pending else {
            return Poll::Ready(Ok(false));
        };
        let data = self.transport.data.clone();
        let _submission = data.submission.lock().unwrap();
        if !data.can_send()
            || self.path.state() == PathState::Retired
            || !data.sent_packets.can_submit(packet.pn)
        {
            self.abort_pending();
            return Poll::Ready(Ok(false));
        }
        let wire_len = packet.bytes.len() + QuicProtocol::packet_overhead(self.path.pathway);
        let probe = self.path.cc.need_send_ack_eliciting(Epoch::Data) != 0;
        let quota = self.path.constraints(1200, probe);
        if wire_len > quota.anti_amplification || (packet.in_flight && wire_len > quota.congestion)
        {
            self.signals = Signals::CREDIT | Signals::CONGESTION;
            return Poll::Ready(Ok(false));
        }
        let Some(result) = self.keys.with_generation(packet.generation, || {
            submit(cx, self.path.pathway, &packet.bytes)
        }) else {
            self.abort_pending();
            return Poll::Ready(Ok(false));
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.abort_pending();
                Poll::Ready(Err(QuicError::with_default_fty(
                    ErrorKind::NoViablePath,
                    error.to_string(),
                )
                .into()))
            }
            Poll::Ready(Ok(submitted)) => {
                // One datagram is atomic; qprotocol reports its entire UDP payload size.
                assert_eq!(submitted, wire_len);
                let packet = self.pending.take().unwrap();
                self.path.on_sent(wire_len, &packet.frames);
                self.path.cc.on_pkt_sent(
                    Epoch::Data,
                    packet.pn,
                    packet.content.is_ack_eliciting(),
                    wire_len,
                    packet.in_flight,
                    packet.ack,
                );
                data.sent_packets.on_sent(
                    packet.pn,
                    packet.in_flight,
                    self.path.cc.pto_base(Epoch::Data) * 3,
                );
                self.buffer = packet.bytes;
                Poll::Ready(Ok(true))
            }
        }
    }

    fn abort_pending(&mut self) {
        if let Some(packet) = self.pending.take() {
            self.heartbeat_pending |= packet.content == qbase::packet::PacketContent::JustPing;
            self.transport
                .requeue(self.transport.data.sent_packets.abort(packet.pn));
            self.buffer = packet.bytes;
        }
    }

    /// Optional task body; caller owns spawning, cancellation and error supervision.
    /// Borrowing self keeps the path owner available for the external close driver.
    pub async fn run(&mut self, protocol: &QuicProtocol) -> Result<(), Error> {
        loop {
            if !self.transport.data.can_send() {
                self.abort_pending();
                return Ok(());
            }
            self.path.cc.do_tick().map_err(|error| {
                QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
            })?;
            if self.prepare()? {
                let wake = self.path.send_waker.clone();
                let signals = self.signals;
                let sent = tokio::select! {
                    result = std::future::poll_fn(|cx| self.poll_send(cx, protocol)) => result?,
                    _ = wake.wait_for(signals) => continue,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => continue,
                };
                if sent {
                    tokio::task::yield_now().await;
                    continue;
                }
            }
            tokio::select! {
                _ = self.path.send_waker.wait_for(self.signals) => {}
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }
}
impl Drop for Sender {
    fn drop(&mut self) {
        self.abort_pending();
        self.transport
            .data
            .send_wakers
            .remove_if(&self.path.pathway, &self.path.send_waker);
        self.path.sender_active.store(false, Ordering::Release);
    }
}

fn packet_error(error: PacketError) -> Error {
    match error {
        PacketError::Connection(error) => error,
        error => QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
    }
}

/// Data ACK pipe target. Capture the original components before Transport is created.
/// Serialization with socket submission makes an early ACK wait for CC accounting.
/// Report acknowledged generations to the receive task's ready OneRttKeys.
pub fn acknowledge(
    data: &crate::space::Space<crate::keys::ArcOneRttKeys>,
    streams: &qrecovery::streams::DataStreams<crate::ReliableFrames>,
    parameters: &crate::ArcParameters,
    ack: &AckFrame,
    received_on: &Arc<Path>,
    on_ack: impl Fn(u64),
) -> Result<(), Error> {
    let _submission = data.submission.lock().unwrap();
    let exponent: u64 = parameters.remote(ParameterId::AckDelayExponent).unwrap();
    let delay = ack
        .delay()
        .checked_shl(exponent as u32)
        .unwrap_or(VARINT_MAX)
        .min(VARINT_MAX);
    let acknowledged = data.sent_packets.acknowledge(ack)?;
    let ack = AckFrame::new(
        VarInt::from_u64(ack.largest()).unwrap(),
        VarInt::from_u64(delay).unwrap(),
        VarInt::from_u64(ack.first_range()).unwrap(),
        ack.ranges().clone(),
        ack.ecn(),
    );
    received_on.cc.on_ack_rcvd(Epoch::Data, &ack);
    for (path, packets) in acknowledged {
        if !Arc::ptr_eq(&path, received_on) {
            path.cc.on_ack_rcvd(Epoch::Data, &ack);
        }
        for (_, generation, frames) in packets {
            on_ack(generation);
            for frame in frames {
                match frame {
                    Frame::Crypto(frame, ()) => data.crypto.outgoing().on_data_acked(&frame),
                    Frame::Stream(frame, ()) => streams.on_data_acked(frame),
                    Frame::StreamCtl(qbase::frame::StreamCtlFrame::ResetStream(frame)) => {
                        streams.on_reset_acked(frame)
                    }
                    _ => {}
                }
            }
        }
        path.send_waker
            .wake_by(Signals::CONGESTION | Signals::TRANSPORT);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn idle_stream_sender_yields_pending_instead_of_spinning_on_returned_credit() {
        let [(client, transport, path), _] = crate::tests::pair(1);
        let (_, _writer) = client.open_uni_stream().await.unwrap().unwrap();
        let mut sender = Sender::new(
            transport.data.keys.clone().await.unwrap(),
            transport.clone(),
            path,
        )
        .unwrap();
        // The watchdog makes a spin a finite failing test rather than hanging the runtime.
        let watchdog = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            transport
                .close(QuicError::with_default_fty(ErrorKind::Internal, "test watchdog").into());
        });
        let protocol = QuicProtocol::new();
        let mut running = Box::pin(sender.run(&protocol));
        let polled = futures::poll!(&mut running);
        drop(running);
        watchdog.join().unwrap();
        assert!(polled.is_pending(), "idle sender must wait for new work");
        sender.run(&protocol).await.unwrap();
    }
}
