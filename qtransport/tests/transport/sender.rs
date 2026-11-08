//! One-datagram fixture for receive and recovery tests, using production assembly.
use qbase::packet::assemble::Metadata;
use qprotocol::protocol::quic::QuicProtocol;
use qtransport::space::{ArcSpaces, Recover, Transmit};

use super::*;

pub(crate) struct Sender {
    transport: Arc<Transport>,
    path: Arc<Path>,
    bytes: BytesMut,
    pending: Option<Metadata>,
    heartbeat: bool,
}

impl Sender {
    pub(crate) fn new(transport: Arc<Transport>, path: Arc<Path>) -> Self {
        Self { transport, path, bytes: BytesMut::zeroed(1200), pending: None, heartbeat: false }
    }

    pub(crate) fn heartbeat(&mut self) {
        self.heartbeat = true;
    }

    pub(crate) fn prepare(&mut self) -> Result<bool, Error> {
        if self.pending.is_some() {
            return Ok(true);
        }
        let credit =
            self.path.validation.credit().map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?;
        let spaces = ArcSpaces::default();
        spaces.retire(Epoch::Handshake);
        spaces.add(self.transport.data.clone());
        self.path.cc.prepare_burst_budget(&mut Context::from_waker(std::task::Waker::noop())).unwrap();
        let overhead = QuicProtocol::datagram_overhead(self.path.pathway);
        let length = credit.map_or(1200, |credit| 1200.min(credit.saturating_sub(overhead)));
        let mut ack = self.transport.data.rcvd_journal.ack_package(self.path.cc.need_ack(Epoch::Data));
        let mut validation = self.path.validation.clone();
        let mut ping = self.heartbeat.then_some(PingFrame);
        self.bytes.resize(length, 0);
        let (size, packets) = spaces.poll_dump(
            &mut Context::from_waker(std::task::Waker::noop()),
            &self.path.cc,
            overhead,
            ConnectionId::from_slice(b"original"),
            self.bytes.as_mut(),
            PacketContent::EffectivePayload,
            &mut Vec::new(),
            &mut [&mut ack, &mut validation, &mut ping],
        );
        self.bytes.truncate(size);
        self.pending = packets.into_iter().next();
        if size > 0 {
            self.heartbeat = false;
        }
        Ok(size > 0)
    }

    pub(crate) fn poll_send_with(
        &mut self,
        cx: &mut Context<'_>,
        mut submit: impl FnMut(&mut Context<'_>, Pathway, &[u8]) -> Poll<std::io::Result<usize>>,
    ) -> Poll<Result<bool, Error>> {
        let Some(meta) = self.pending else {
            return Poll::Ready(Ok(false));
        };
        let delay = self.path.cc.retransmit_and_expire_time(Epoch::Data).0;
        let retention = self.path.cc.pto_base(Epoch::Data) * 3;
        let mut cc = self.path.cc.lock();
        std::task::ready!(submit(cx, self.path.pathway, &self.bytes))
            .map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?;
        Transmit::on_sent(self.transport.data.as_ref(), meta.pn, meta.in_flight, delay, retention);
        self.path.on_sent(&mut cc, [None, None, self.pending.take()]);
        drop(cc);
        self.path.validation.on_sent(self.bytes.len() + QuicProtocol::datagram_overhead(self.path.pathway));
        Poll::Ready(Ok(true))
    }

    pub(crate) fn poll_send(&mut self, cx: &mut Context<'_>, protocol: &QuicProtocol) -> Poll<Result<bool, Error>> {
        self.poll_send_with(cx, |cx, path, bytes| {
            protocol.poll_send(cx, path, &[std::io::IoSlice::new(bytes)]).map(|result| result.map(|_| bytes.len()))
        })
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.path.cc.on_burst_completed();
        if let Some(meta) = self.pending.take() {
            Recover::cancel(self.transport.data.as_ref(), meta.pn, &mut std::iter::empty());
        }
    }
}
