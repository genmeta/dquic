//! Component wiring for the established-connection integration tests.
use qprotocol::protocol::quic::QuicProtocol;

use super::*;
use crate::{
    path::PathState,
    send::{MAX_BURST_PACKETS, fixture::TestSender as PacketSender, write::PendingPacket},
};

pub(crate) struct Sender {
    inner: PacketSender,
    keys: OneRttKeys,
    transport: Arc<Transport>,
    path: Arc<Path>,
    heartbeat: bool,
    packets: Vec<std::io::IoSlice<'static>>,
}

impl Sender {
    pub(crate) fn new(
        keys: OneRttKeys,
        transport: Arc<Transport>,
        path: Arc<Path>,
    ) -> Result<Self, Error> {
        let inner = PacketSender::new(
            path.pathway,
            path.cc.clone(),
            path.anti_amplifier.clone(),
            Some(transport.data.clone()),
        );
        Ok(Self {
            inner,
            keys,
            transport,
            path,
            heartbeat: false,
            packets: Vec::with_capacity(MAX_BURST_PACKETS),
        })
    }
    pub(crate) fn heartbeat(&mut self) {
        self.heartbeat = true;
    }
    pub(crate) fn prepare(&mut self) -> Result<bool, Error> {
        if self.inner.pending().next().is_some() {
            return Ok(true);
        }
        if self.path.state() == PathState::Retired {
            return Err(
                QuicError::with_default_fty(ErrorKind::NoViablePath, "path retired").into(),
            );
        }
        let mut once = false;
        let count = self.inner.burst(|sender, constraints| {
            if once {
                return Ok(None);
            }
            once = true;
            let packet = assemble_data(
                sender,
                constraints,
                &self.keys,
                &self.transport,
                &self.path,
                self.heartbeat,
            )?;
            if packet.is_some() {
                self.heartbeat = false;
            }
            Ok(packet)
        })?;
        Ok(count != 0)
    }
    pub(crate) fn poll_send_with(
        &mut self,
        cx: &mut Context<'_>,
        mut submit: impl FnMut(&mut Context<'_>, Pathway, &[u8]) -> Poll<std::io::Result<usize>>,
    ) -> Poll<Result<bool, Error>> {
        self.inner
            .poll_send_with(
                cx,
                &mut self.packets,
                |cx, path, packets| submit(cx, path, &packets[0]).map(|result| result.map(|_| 1)),
                |_| self.path.state() != PathState::Retired,
                |packet| packet.on_sent(&self.path),
            )
            .map(|result| result.map(|n| n != 0))
    }
    pub(crate) fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        protocol: &QuicProtocol,
    ) -> Poll<Result<bool, Error>> {
        self.inner
            .poll_send_with(
                cx,
                &mut self.packets,
                |cx, pathway, packets| protocol.poll_send_datagrams(cx, pathway, packets),
                |_| self.path.state() != PathState::Retired,
                |packet| packet.on_sent(&self.path),
            )
            .map(|result| result.map(|n| n != 0))
    }
}
impl Drop for Sender {
    fn drop(&mut self) {
        self.inner.cancel_pending();
    }
}

pub(crate) fn assemble_data(
    sender: &mut PacketSender,
    constraints: &Constraints,
    keys: &OneRttKeys,
    transport: &Transport,
    path: &Path,
    heartbeat: bool,
) -> Result<Option<PendingPacket>, Error> {
    let mut ack = path
        .cc
        .need_ack(Epoch::Data)
        .and_then(|(pn, time)| {
            transport
                .data
                .rcvd_journal
                .gen_ack_frame_util(pn, time, 400)
                .ok()
        })
        .map(|ack| {
            let exponent: u64 = transport.parameters.local(ParameterId::AckDelayExponent);
            AckFrame::new(
                VarInt::from_u64(ack.largest()).unwrap(),
                VarInt::from_u64(ack.delay() >> exponent).unwrap(),
                VarInt::from_u64(ack.first_range()).unwrap(),
                ack.ranges().clone(),
                None,
            )
        });
    let mut response = path.response();
    let mut challenge = path.challenge();
    let mut crypto = transport.data.crypto.outgoing();
    let mut reliable = transport.data.reliable_frames.clone();
    let mut streams = transport.data.streams.clone();
    let mut credit = transport.flow.sender.credit(streams.fresh_bytes())?;
    constraints.flow_ctrl.set(credit.available());
    for packet in sender.pending() {
        if packet.epoch() == Epoch::Data
            && packet
                .largest_acked
                .is_some_and(|pn| ack.as_ref().is_some_and(|ack| pn >= ack.largest()))
        {
            ack = None;
        }
        if packet.response == response {
            response = None;
        }
        if packet.challenge == challenge {
            challenge = None;
        }
    }
    let mut ping =
        (heartbeat || path.cc.need_send_ack_eliciting(Epoch::Data) != 0).then_some(PingFrame);
    let header = OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original"));
    let result = if heartbeat {
        sender.assemble_1rtt_packet(
            keys,
            header,
            &transport.data.sent_journal,
            constraints,
            [&mut ping],
        )
    } else if !path.is_validated() {
        sender.assemble_1rtt_packet(
            keys,
            header,
            &transport.data.sent_journal,
            constraints,
            [&mut ack, &mut response, &mut challenge, &mut ping],
        )
    } else {
        sender.assemble_1rtt_packet(
            keys,
            header,
            &transport.data.sent_journal,
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
    };
    credit.post_sent(credit.available() - constraints.flow_ctrl.get());
    result
}
