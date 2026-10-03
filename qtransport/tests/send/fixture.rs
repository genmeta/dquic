//! Test harness for isolated packet sources and mock UDP submission.

use super::*;
/// Fixture for mock submission and packet-source tests.
pub struct TestSender {
    pub pathway: Pathway,
    pub congestion: ArcCC,
    pub(super) anti_amplifier: Arc<AntiAmplifier>,
    buffers: Vec<BytesMut>,
    pub(super) send_frames: Vec<GuaranteedFrame>,
    pns: VecDeque<PendingPacket>,
    recovery: Option<Arc<DataSpace>>,
}

impl TestSender {
    pub fn new(
        pathway: Pathway,
        congestion: ArcCC,
        anti_amplifier: Arc<AntiAmplifier>,
        recovery: Option<Arc<DataSpace>>,
    ) -> Self {
        Self {
            pathway,
            recovery,
            congestion,
            anti_amplifier,
            buffers: (0..MAX_BURST_PACKETS)
                .map(|_| BytesMut::with_capacity(1200))
                .collect(),
            send_frames: Vec::with_capacity(256),
            pns: VecDeque::with_capacity(MAX_BURST_PACKETS),
        }
    }

    /// Already assembled intents can be excluded from the next packet in this burst.
    pub fn pending(&self) -> impl Iterator<Item = &PendingPacket> {
        self.pns.iter()
    }

    pub fn assemble_long_packet<H: HeaderSize + GetType, const N: usize>(
        &mut self,
        keys: &qtls::DirectionalKeys,
        header: H,
        journal: &ArcSentJournal,
        constraints: &Constraints,
        sources: [&mut dyn for<'a> Package<&'a mut [u8]>; N],
    ) -> Result<Option<PendingPacket>, Error>
    where
        for<'b> &'b mut [u8]: WriteHeader<H>,
    {
        super::assemble_long_packet(
            self.pathway,
            &self.congestion,
            &mut self.buffers,
            &mut self.send_frames,
            &mut self.pns,
            keys,
            header,
            journal,
            &self.recovery,
            constraints,
            sources,
        )
    }

    pub fn assemble_1rtt_packet<const N: usize>(
        &mut self,
        keys: &OneRttKeys,
        header: OneRttHeader,
        journal: &ArcSentJournal,
        constraints: &Constraints,
        sources: [&mut dyn for<'a> Package<&'a mut [u8]>; N],
    ) -> Result<Option<PendingPacket>, Error> {
        super::assemble_1rtt_packet(
            self.pathway,
            &self.congestion,
            &mut self.buffers,
            &mut self.send_frames,
            &mut self.pns,
            keys,
            header,
            journal,
            &self.recovery,
            constraints,
            sources,
        )
    }

    /// Assemble a bounded burst. The closure captures ready space components and
    /// skips missing keys synchronously; None means all eligible sources were tried.
    pub fn burst(
        &mut self,
        mut assemble: impl FnMut(&mut Self, &Constraints) -> Result<Option<PendingPacket>, Error>,
    ) -> Result<usize, Error> {
        if !self.pns.is_empty() {
            return Ok(self.pns.len());
        }

        let mut constraints = Constraints {
            flow_ctrl: std::cell::Cell::new(usize::MAX),
            capacity: 1200,
            congestion: self.congestion.send_quota(),
            anti_amplification: self.anti_amplifier.balance(),
        };
        while self.pns.len() < MAX_BURST_PACKETS {
            let Some(packet) = assemble(self, &constraints)? else {
                break;
            };
            let wire_len = packet.bytes().len() + QuicProtocol::packet_overhead(self.pathway);
            constraints.anti_amplification =
                constraints.anti_amplification.saturating_sub(wire_len);
            if packet.in_flight {
                constraints.congestion = constraints.congestion.saturating_sub(wire_len);
            }
            self.pns.push_back(packet);
        }
        Ok(self.pns.len())
    }

    pub(crate) fn poll_send_with(
        &mut self,
        cx: &mut Context<'_>,
        packets: &mut Vec<IoSlice<'static>>,
        submit: impl FnMut(&mut Context<'_>, Pathway, &[IoSlice<'_>]) -> Poll<io::Result<usize>>,
        allowed: impl Fn(Type) -> bool,
        on_sent: impl FnMut(&PendingPacket),
    ) -> Poll<Result<usize, Error>> {
        super::poll_send_with(
            self.pathway,
            &self.congestion,
            &self.anti_amplifier,
            &mut self.buffers,
            &mut self.pns,
            cx,
            packets,
            submit,
            allowed,
            on_sent,
        )
    }

    pub fn cancel_pending(&mut self) {
        while let Some(packet) = self.pns.pop_front() {
            self.buffers.push(packet.into_buffer());
        }
    }
}
