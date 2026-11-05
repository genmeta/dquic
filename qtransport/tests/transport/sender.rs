//! One-datagram fixture for receive and recovery tests, using production assembly.
use qbase::{packet::assemble::Metadata, time::timer::ArcIdleTimer};
use qprotocol::protocol::quic::QuicProtocol;
use qtransport::space::{Recover, Spaces, Transmit, assemble::Constraints};

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
        Self {
            transport,
            path,
            bytes: BytesMut::zeroed(1200),
            pending: None,
            heartbeat: false,
        }
    }

    pub(crate) fn heartbeat(&mut self) {
        self.heartbeat = true;
    }

    pub(crate) fn prepare(&mut self) -> Result<bool, Error> {
        if self.pending.is_some() {
            return Ok(true);
        }
        let credit = self.path.validation.credit().map_err(|error| {
            QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
        })?;
        let mut spaces = Spaces(IndexDeque::with_capacity(1));
        spaces.0.reset_offset(Epoch::Data as u64);
        spaces.0.push_back(self.transport.data.clone()).unwrap();
        let mut limits = Constraints {
            send_quota: self.path.cc.send_quota(),
            credit: credit.unwrap_or(usize::MAX),
            probe_quota: Epoch::EPOCHS.map(|epoch| {
                if self.path.cc.need_send_ack_eliciting(epoch) > 0 {
                    1200
                } else {
                    0
                }
            }),
            overhead: QuicProtocol::packet_overhead(self.path.pathway),
        };
        let mut ack = self
            .transport
            .data
            .rcvd_journal
            .ack_package(self.path.cc.need_ack(Epoch::Data));
        let mut validation = self.path.validation.clone();
        let mut ping = (self.heartbeat || limits.probe_quota[Epoch::Data] > 0).then_some(PingFrame);
        self.bytes.resize(1200, 0);
        let mut packets = [None; 3];
        let size = spaces.poll_dump(
            &mut Context::from_waker(std::task::Waker::noop()),
            ConnectionId::from_slice(b"original"),
            &mut self.bytes,
            &mut limits,
            &mut Vec::new(),
            &mut packets,
            &mut [&mut ack, &mut validation, &mut ping],
        )?;
        self.bytes.truncate(size);
        self.pending = packets[Epoch::Data];
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
        std::task::ready!(submit(cx, self.path.pathway, &self.bytes)).map_err(|error| {
            QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
        })?;
        Transmit::on_sent(
            self.transport.data.as_ref(),
            meta.pn,
            meta.in_flight,
            delay,
            retention,
        );
        self.path.on_sent(
            &mut cc,
            self.bytes.len(),
            [None, None, self.pending.take()],
            &ArcIdleTimer::new(Duration::ZERO),
        );
        Poll::Ready(Ok(true))
    }

    pub(crate) fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        protocol: &QuicProtocol,
    ) -> Poll<Result<bool, Error>> {
        self.poll_send_with(cx, |cx, path, bytes| {
            protocol
                .poll_send(cx, path, &[std::io::IoSlice::new(bytes)])
                .map(|result| result.map(|_| bytes.len()))
        })
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        if let Some(meta) = self.pending.take() {
            Recover::cancel(
                self.transport.data.as_ref(),
                meta.pn,
                &mut std::iter::empty(),
            );
        }
    }
}
