use std::{
    io,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU16, Ordering},
    },
    task::{Context, Waker},
};

use qbase::{Epoch, frame::AckFrame, handshake::HandshakeFacts, net::validate::ArcValidation, role::Role, util::ArcIndexDeque};
use qevent::quic::recovery::PacketLostTrigger;
use tokio::time::{Duration, Instant};

use crate::{
    Algorithm, MSS, Resend, Transport,
    algorithm::{Control, new_reno::NewReno},
    pacing::{self, Pacer},
    packets::{PacketSpace, SentPacket},
    rtt::{ArcRtt, INITIAL_RTT},
};

const INIT_CWND: usize = MSS * 10;
const PACKET_THRESHOLD: usize = 3;
// Report path failure when the PTO count exceeds this limit.
const MAX_PTO_COUNT: u32 = 6;
const TICK_INTERVAL: Duration = Duration::from_millis(10);

/// Imple RFC 9002 Appendix A. Loss Recovery
/// See [Appendix A](https://datatracker.ietf.org/doc/html/rfc9002#name-loss-recovery-pseudocode)
pub struct CongestionController {
    algorithm: Box<dyn Control>,
    // The Round-Trip Time (RTT) estimator.
    rtt: ArcRtt,
    loss_detection_timer: Option<Instant>,
    // The number of times a PTO has been sent without receiving an acknowledgment.
    // Use to pto backoff
    pto_count: u32,
    max_ack_delay: Duration,
    packet_spaces: [PacketSpace; Epoch::count()],
    discarded_epochs: [bool; Epoch::count()],
    // pacer is used to control the burst rate
    pacer: pacing::Pacer,
    // The waker to notify when the controller is ready to send.
    pending_burst: bool,
    burst_budget: Option<usize>,
    // Shared connection spaces, indexed by epoch even after early spaces retire.
    resenders: ArcIndexDeque<Arc<dyn Resend>, 2>,
    need_send_ack_eliciting_packets: [usize; Epoch::count()],
    hs_facts: Arc<HandshakeFacts>,
    pmtu: Arc<AtomicU16>,
    validation: ArcValidation,
    tx_waker: Option<Waker>,
}

impl CongestionController {
    fn mtu(&self) -> usize {
        self.pmtu.load(Ordering::Relaxed) as usize
    }

    /// A.4. Initialization
    fn init(
        algorithm: Algorithm,
        max_ack_delay: Duration,
        resenders: ArcIndexDeque<Arc<dyn Resend>, 2>,
        hs_facts: Arc<HandshakeFacts>,
        validation: ArcValidation,
        pmtu: Arc<AtomicU16>,
    ) -> Self {
        let algorithm: Box<dyn Control> = match algorithm {
            Algorithm::Bbr => todo!("implement BBR"),
            Algorithm::NewReno => Box::new(NewReno::new(pmtu.clone())),
        };

        let now = Instant::now();
        CongestionController {
            algorithm,
            rtt: ArcRtt::new(),
            loss_detection_timer: None,
            pto_count: 0,
            max_ack_delay,
            packet_spaces: [
                PacketSpace::with_epoch(Epoch::Initial, Duration::ZERO),
                PacketSpace::with_epoch(Epoch::Handshake, Duration::ZERO),
                PacketSpace::with_epoch(Epoch::Data, max_ack_delay),
            ],
            discarded_epochs: [false; Epoch::count()],
            pacer: Pacer::new(INITIAL_RTT, INIT_CWND, pmtu.load(Ordering::Relaxed) as usize, now, None),
            pending_burst: false,
            burst_budget: None,
            resenders,
            need_send_ack_eliciting_packets: [0; Epoch::count()],
            hs_facts,
            pmtu,
            validation,
            tx_waker: None,
        }
    }

    /// A.5. On Sending a Packet
    ///
    /// ```text
    /// OnPacketSent(packet_number, pn_space, ack_eliciting,
    ///              in_flight, sent_bytes):
    ///   sent_packets[pn_space][packet_number].packet_number =
    ///                                            packet_number
    ///   sent_packets[pn_space][packet_number].time_sent = now()
    ///   sent_packets[pn_space][packet_number].ack_eliciting =
    ///                                            ack_eliciting
    ///   sent_packets[pn_space][packet_number].in_flight = in_flight
    ///   sent_packets[pn_space][packet_number].sent_bytes = sent_bytes
    ///   if (in_flight):
    ///     if (ack_eliciting):
    ///       time_of_last_ack_eliciting_packet[pn_space] = now()
    ///     OnPacketSentCC(sent_bytes)
    ///     SetLossDetectionTimer()
    /// ```
    pub fn on_packet_sent(&mut self, packet_number: u64, epoch: Epoch, ack_eliciting: bool, in_flight: bool, sent_bytes: usize) {
        // A sealed batch may finish submission after this epoch's keys were retired.
        if self.discarded_epochs[epoch] {
            return;
        }
        let now = Instant::now();
        let sent = SentPacket::new(packet_number, now, ack_eliciting, in_flight, sent_bytes);
        if in_flight {
            if ack_eliciting {
                self.packet_spaces[epoch].time_of_last_ack_eliciting_packet = Some(now);
                self.need_send_ack_eliciting_packets[epoch] = self.need_send_ack_eliciting_packets[epoch].saturating_sub(1);
            }
            self.algorithm.on_packet_sent_cc(&sent);
        }
        // Pure ACK packets are neither ack-eliciting nor in flight. The peer is not required to
        // acknowledge them, and congestion control has no loss/RTT state to derive from them, so
        // retaining one record per packet would create an unbounded tail during one-way traffic.
        if ack_eliciting || in_flight {
            self.packet_spaces[epoch].sent_packets.push_back(sent);
        }
        if in_flight {
            self.set_loss_detection_timer();
        }
        self.pacer.on_sent(sent_bytes);
    }

    /// Record a submitted packet and the ACK carried by it under the same guard.
    pub fn on_pkt_sent(&mut self, epoch: Epoch, pn: u64, is_ack_eliciting: bool, sent_bytes: usize, in_flight: bool, ack: Option<u64>) {
        self.burst_budget = None;
        self.on_packet_sent(pn, epoch, is_ack_eliciting, in_flight, sent_bytes);
        if let Some(largest_acked) = ack {
            self.packet_spaces[epoch].rcvd_packets.on_ack_sent(pn, largest_acked);
        }
    }

    /// A.7. On Receiving an Acknowledgment
    ///
    /// ```text
    /// OnAckReceived(ack, pn_space):
    ///   if (largest_acked_packet[pn_space] == infinite):
    ///     largest_acked_packet[pn_space] = ack.largest_acked
    ///   else:
    ///     largest_acked_packet[pn_space] =
    ///         max(largest_acked_packet[pn_space], ack.largest_acked)
    ///
    ///   // DetectAndRemoveAckedPackets finds packets that are newly
    ///   // acknowledged and removes them from sent_packets.
    ///   newly_acked_packets =
    ///       DetectAndRemoveAckedPackets(ack, pn_space)
    ///   // Nothing to do if there are no newly acked packets.
    ///   if (newly_acked_packets.empty()):
    ///     return
    ///
    ///   // Update the RTT if the largest acknowledged is newly acked
    ///   // and at least one ack-eliciting was newly acked.
    ///   if (newly_acked_packets.largest().packet_number ==
    ///           ack.largest_acked &&
    ///       IncludesAckEliciting(newly_acked_packets)):
    ///     latest_rtt =
    ///       now() - newly_acked_packets.largest().time_sent
    ///     UpdateRtt(ack.ack_delay)
    ///
    ///   // Process ECN information if present.
    ///   if (ACK frame contains ECN information):
    ///       ProcessECN(ack, pn_space)
    ///
    ///   lost_packets = DetectAndRemoveLostPackets(pn_space)
    ///   if (!lost_packets.empty()):
    ///     OnPacketsLost(lost_packets)
    ///   OnPacketsAcked(newly_acked_packets)
    ///
    ///   // Reset pto_count unless the client is unsure if
    ///   // the server has validated the client's address.
    ///   if (PeerCompletedAddressValidation()):
    ///     pto_count = 0
    ///   SetLossDetectionTimer()
    /// ```
    pub fn on_ack_rcvd(&mut self, epoch: Epoch, ack_frame: &AckFrame, now: Instant) {
        if self.discarded_epochs[epoch] {
            return;
        }
        self.packet_spaces[epoch].update_largest_acked_packet(ack_frame.largest());

        match self.packet_spaces[epoch].on_ack_rcvd(ack_frame, &mut self.algorithm) {
            None => return,
            Some(newly_acked_packets) => {
                if epoch == Epoch::Handshake {
                    self.hs_facts.on_handshake_acked();
                }
                let (largest_pn, largest_time_sent) = newly_acked_packets.largest;
                if largest_pn == ack_frame.largest() && newly_acked_packets.include_ack_eliciting {
                    self.rtt.update(now - largest_time_sent, Duration::from_micros(ack_frame.delay()), self.hs_facts.is_handshake_done());
                }
                // Process ECN information if present.
                if ack_frame.ecn().is_some() {
                    self.process_ecn(ack_frame, &largest_time_sent, epoch)
                }
            }
        }

        let mut loss_pns =
            self.packet_spaces[epoch].detect_lost_packets(self.rtt.loss_delay(), PACKET_THRESHOLD, &mut self.algorithm).peekable();

        if loss_pns.peek().is_some() {
            self.rtt.try_backoff_rtt();
            let tracker = self.resenders.read_guard().get(epoch as u64).cloned();
            if let Some(tracker) = tracker {
                tracker.resend(PacketLostTrigger::TimeThreshold, &mut loss_pns);
            }
        }

        if self.peer_completed_address_validation() {
            self.pto_count = 0;
        }
        self.set_loss_detection_timer();
    }

    /// A.8. Setting the Loss Detection Timer
    /// SetLossDetectionTimer():
    ///   earliest_loss_time, _ = GetLossTimeAndSpace()
    ///   if (earliest_loss_time != 0):
    ///     // Time threshold loss detection.
    ///     loss_detection_timer.update(earliest_loss_time)
    ///     return
    ///
    ///   if (server is at anti-amplification limit):
    ///     // The server's timer is not set if nothing can be sent.
    ///     loss_detection_timer.cancel()
    ///     return
    ///
    ///   if (no ack-eliciting packets in flight &&
    ///       PeerCompletedAddressValidation()):
    ///     // There is nothing to detect lost, so no timer is set.
    ///     // However, the client needs to arm the timer if the
    ///     // server might be blocked by the anti-amplification limit.
    ///     loss_detection_timer.cancel()
    ///     return
    ///
    ///   timeout, _ = GetPtoTimeAndSpace()
    ///   loss_detection_timer.update(timeout)
    fn set_loss_detection_timer(&mut self) {
        if let Some((earliest_loss_time, _)) = self.get_loss_time_and_epoch() {
            self.loss_detection_timer = Some(earliest_loss_time);
            return;
        }

        if self.validation.is_blocking() {
            self.loss_detection_timer = None;
            return;
        }

        if self.no_ack_eliciting_in_flight() && self.peer_completed_address_validation() {
            self.loss_detection_timer = None;
            return;
        }

        self.loss_detection_timer = self.get_pto_time_and_epoch().map(|(timeout, _)| timeout);
    }

    // A.9. On Timeout
    /// OnLossDetectionTimeout():
    ///   earliest_loss_time, pn_space = GetLossTimeAndSpace()
    ///   if (earliest_loss_time != 0):
    ///     // Time threshold loss Detection
    ///     lost_packets = DetectAndRemoveLostPackets(pn_space)
    ///     assert(!lost_packets.empty())
    ///     OnPacketsLost(lost_packets)
    ///     SetLossDetectionTimer()
    ///     return
    ///
    ///   if (no ack-eliciting packets in flight):
    ///     assert(!PeerCompletedAddressValidation())
    ///     // Client sends an anti-deadlock packet: Initial is padded
    ///     // to earn more anti-amplification credit,
    ///     // a Handshake packet proves address ownership.
    ///     if (has Handshake keys):
    ///       SendOneAckElicitingHandshakePacket()
    ///     else:
    ///       SendOneAckElicitingPaddedInitialPacket()
    ///   else:
    ///     // PTO. Send new data if available, else retransmit old data.
    ///     // If neither is available, send a single PING frame.
    ///     _, pn_space = GetPtoTimeAndSpace()
    ///     SendOneOrTwoAckElicitingPackets(pn_space)
    ///
    ///   pto_count++
    ///   SetLossDetectionTimer()
    fn on_loss_detection_timeout(&mut self, peer_validated: bool) -> u32 {
        if let Some((_, epoch)) = self.get_loss_time_and_epoch() {
            let mut loss_pns =
                self.packet_spaces[epoch].detect_lost_packets(self.rtt.loss_delay(), PACKET_THRESHOLD, &mut self.algorithm).peekable();

            if loss_pns.peek().is_some() {
                self.rtt.try_backoff_rtt();
                let tracker = self.resenders.read_guard().get(epoch as u64).cloned();
                if let Some(tracker) = tracker {
                    tracker.resend(PacketLostTrigger::TimeThreshold, &mut loss_pns);
                }
            }
            self.set_loss_detection_timer();
            return self.pto_count;
        }

        if self.no_ack_eliciting_in_flight() {
            // Use the driver's decision: another path can advance the shared
            // handshake after that decision without changing this timeout event.
            debug_assert!(!peer_validated);
            if self.hs_facts.has_handshake_key() {
                // Send an anti-deadlock packet: Initial is padded
                // to earn more anti-amplification credit,
                // a Handshake packet proves address ownership.
                self.send_ack_eliciting_packet(Epoch::Handshake, 1);
            } else {
                self.send_ack_eliciting_packet(Epoch::Initial, 1);
            }
        } else {
            // PTO. Send new data if available, else retransmit old data.
            // If neither is available, send a single PING frame.
            if let Some((_, epoch)) = self.get_pto_time_and_epoch() {
                self.send_ack_eliciting_packet(epoch, 1);
            }
        }

        self.pto_count += 1;
        self.set_loss_detection_timer();
        self.pto_count
    }

    /// GetLossTimeAndSpace():
    ///   time = loss_time[Initial]
    ///   space = Initial
    ///   for pn_space in [ Handshake, ApplicationData ]:
    ///     if (time == 0 || loss_time[pn_space] < time):
    ///       time = loss_time[pn_space];
    ///       space = pn_space
    ///   return time, space
    fn get_loss_time_and_epoch(&self) -> Option<(Instant, Epoch)> {
        self.packet_spaces
            .iter()
            .zip(Epoch::iter())
            .filter(|(space, _)| space.loss_time.is_some())
            .map(|(space, epoch)| (space.loss_time.unwrap(), *epoch))
            .min_by_key(|(loss_time, _)| *loss_time)
    }

    // GetPtoTimeAndSpace():
    //   duration = (smoothed_rtt + max(4 * rttvar, kGranularity))
    //       * (2 ^ pto_count)
    //   // Anti-deadlock PTO starts from the current time
    //   if (no ack-eliciting packets in flight):
    //     assert(!PeerCompletedAddressValidation())
    //     if (has handshake keys):
    //       return (now() + duration), Handshake
    //     else:
    //       return (now() + duration), Initial
    //   pto_timeout = infinite
    //   pto_space = Initial
    //   for space in [ Initial, Handshake, ApplicationData ]:
    //     if (no ack-eliciting packets in flight in space):
    //         continue;
    //     if (space == ApplicationData):
    //       // Skip Application Data until handshake confirmed.
    //       if (handshake is not confirmed):
    //         return pto_timeout, pto_space
    //       // Include max_ack_delay and backoff for Application Data.
    //       duration += max_ack_delay * (2 ^ pto_count)
    //
    //     t = time_of_last_ack_eliciting_packet[space] + duration
    //     if (t < pto_timeout):
    //       pto_timeout = t
    //       pto_space = space
    //   return pto_timeout, pto_space
    fn get_pto_time_and_epoch(&self) -> Option<(Instant, Epoch)> {
        let mut duration = self.rtt.base_pto(self.pto_count);
        let now = Instant::now();
        if self.no_ack_eliciting_in_flight() {
            // assert!(!self.peer_completed_address_validation());
            if self.hs_facts.has_handshake_key() {
                return Some((now + duration, Epoch::Handshake));
            } else {
                return Some((now + duration, Epoch::Initial));
            }
        }

        let mut pto_time = None;
        for &epoch in Epoch::iter() {
            if self.packet_spaces[epoch].no_ack_eliciting_in_flight() {
                continue;
            }
            if epoch == Epoch::Data {
                // An endpoint MUST NOT set its PTO timer for the Application Data
                // packet number epoch until the handshake is confirmed
                if !self.hs_facts.is_handshake_done() {
                    return pto_time;
                }
                duration += self.max_ack_delay * (1 << self.pto_count);
            }
            let t = self.packet_spaces[epoch].time_of_last_ack_eliciting_packet.unwrap() + duration;
            if pto_time.is_none() || pto_time.is_some_and(|(pto_time, _)| t < pto_time) {
                pto_time = Some((t, epoch));
            }
        }
        pto_time
    }

    fn no_ack_eliciting_in_flight(&self) -> bool {
        Epoch::iter().all(|epoch| self.packet_spaces[*epoch].no_ack_eliciting_in_flight())
    }

    /// PeerCompletedAddressValidation():
    ///   // Assume clients validate the server's address implicitly.
    ///   if (endpoint is server):
    ///     return true
    ///   // Servers complete address validation when a
    ///   // protected packet is received.
    ///   return has received Handshake ACK ||
    ///        handshake confirmed
    fn peer_completed_address_validation(&self) -> bool {
        self.hs_facts.role() == Role::Server || self.hs_facts.has_handshake_acked() || self.hs_facts.is_handshake_done()
    }

    fn process_ecn(&mut self, ack: &AckFrame, sent_time: &Instant, epoch: Epoch) {
        self.algorithm.process_ecn(ack, sent_time, epoch);
    }

    fn send_ack_eliciting_packet(&mut self, epoch: Epoch, count: usize) {
        self.need_send_ack_eliciting_packets[epoch] += count;
        self.wake_sender();
    }

    fn wake_sender(&mut self) {
        if let Some(waker) = self.tx_waker.take() {
            waker.wake();
        }
    }

    #[inline]
    fn need_ack(&self) -> bool {
        Epoch::iter().any(|&epoch| self.packet_spaces[epoch].rcvd_packets.need_ack().is_some())
    }

    #[inline]
    fn send_quota(&mut self) -> usize {
        let now = Instant::now();
        let pacing_quota =
            self.pacer.schedule(self.rtt.smoothed_rtt(), self.algorithm.congestion_window(), self.mtu(), now, self.algorithm.pacing_rate());
        // Pacing tokens do not permit sending past the outstanding-byte limit.
        let window = self.algorithm.congestion_window().saturating_sub(self.algorithm.bytes_in_flight());
        pacing_quota.min(window)
    }

    //OnPacketNumberSpaceDiscarded(pn_space):
    //   assert(pn_space != ApplicationData)
    //   RemoveFromBytesInFlight(sent_packets[pn_space])
    //   sent_packets[pn_space].clear()
    //   // Reset the loss detection and PTO timer
    //   time_of_last_ack_eliciting_packet[pn_space] = 0
    //   loss_time[pn_space] = 0
    //   pto_count = 0
    //   SetLossDetectionTimer()
    fn discard_epoch(&mut self, epoch: Epoch) {
        assert!(epoch != Epoch::Data);
        if std::mem::replace(&mut self.discarded_epochs[epoch], true) {
            return;
        }
        _ = self.packet_spaces[epoch].discard(&mut self.algorithm);
        self.need_send_ack_eliciting_packets[epoch] = 0;
        self.loss_detection_timer = None;
        self.pto_count = 0;
        self.set_loss_detection_timer();
    }

    fn retire_handshake_spaces(&mut self) {
        if !self.discarded_epochs[Epoch::Initial] && self.hs_facts.is_initial_done() {
            self.discard_epoch(Epoch::Initial);
        }
        if !self.discarded_epochs[Epoch::Handshake] && self.hs_facts.is_handshake_done() {
            self.discard_epoch(Epoch::Handshake);
        }
    }

    /// Drive recovery: retire completed handshake spaces before processing a timeout.
    fn tick(&mut self) -> io::Result<()> {
        self.retire_handshake_spaces();
        // Another path's Handshake ACK can invalidate an already armed
        // anti-deadlock PTO. Cancel it before dispatching a timeout. Preserve
        // loss detection and existing PTO deadlines that are still needed.
        let peer_validated = self.peer_completed_address_validation();
        if self.loss_detection_timer.is_none()
            || self.validation.is_blocking()
            || (peer_validated && self.no_ack_eliciting_in_flight() && self.get_loss_time_and_epoch().is_none())
        {
            // Rearm after credit returns, keeping an already running PTO's deadline.
            self.set_loss_detection_timer();
        }
        if self.loss_detection_timer.is_some_and(|t| t <= Instant::now()) {
            let count = self.on_loss_detection_timeout(peer_validated);
            if count > MAX_PTO_COUNT {
                return Err(io::Error::new(io::ErrorKind::TimedOut, format!("no acknowledgment after {count} PTOs")));
            }
        }
        Ok(())
    }

    fn on_path_lost(&mut self) {
        // Initial and Handshake packets belong to the single handshake path. They are discarded
        // when the handshake completes, so retiring a path must not requeue them for retransmit.
        for &epoch in Epoch::iter() {
            let packet_numbers = self.packet_spaces[epoch].discard(&mut self.algorithm);
            if epoch == Epoch::Data && !packet_numbers.is_empty() {
                let tracker = self.resenders.read_guard().get(epoch as u64).cloned();
                if let Some(tracker) = tracker {
                    tracker.resend(PacketLostTrigger::PtoExpired, &mut packet_numbers.into_iter());
                }
            }
        }
        self.loss_detection_timer = None;
    }

    fn get_pto(&self, epoch: Epoch) -> Duration {
        let mut pto_time = self.rtt.base_pto(self.pto_count);
        if epoch == Epoch::Data {
            pto_time += self.max_ack_delay * (1 << self.pto_count);
        }
        pto_time
    }

    fn pto_base(&self, epoch: Epoch) -> Duration {
        let mut pto = self.rtt.base_pto(0);
        if epoch == Epoch::Data {
            pto += self.max_ack_delay;
        }
        pto
    }
}

#[derive(Clone)]
pub struct ArcCC(Arc<Mutex<CongestionController>>);

impl ArcCC {
    pub fn new(
        algorithm: Algorithm,
        max_ack_delay: Duration,
        resenders: ArcIndexDeque<Arc<dyn Resend>, 2>,
        hs_facts: Arc<HandshakeFacts>,
        validation: ArcValidation,
        pmtu: Arc<AtomicU16>,
    ) -> Self {
        let cc = ArcCC(Arc::new(Mutex::new(CongestionController::init(
            algorithm,
            max_ack_delay,
            resenders,
            hs_facts,
            validation.clone(),
            pmtu,
        ))));
        let blocked = Arc::downgrade(&cc.0);
        let charged = blocked.clone();
        validation.on_blocked(move || {
            if let Some(cc) = blocked.upgrade() {
                ArcCC(cc).on_blocked();
            }
        });
        validation.on_charged(move || {
            if let Some(cc) = charged.upgrade() {
                ArcCC(cc).on_charged();
            }
        });
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&cc.0);
            runtime.spawn(async move {
                let mut ticker = tokio::time::interval_at(Instant::now() + TICK_INTERVAL, TICK_INTERVAL);
                loop {
                    ticker.tick().await;
                    let Some(cc) = weak.upgrade() else { break };
                    let mut cc = cc.lock().unwrap();
                    if cc.pending_burst || cc.loss_detection_timer.is_some() || cc.need_ack() {
                        cc.wake_sender();
                    }
                }
            });
        }
        cc
    }

    /// Discard this path's sending waiter without notifying it.
    pub fn cancel(&self) {
        self.lock().tx_waker = None;
    }

    pub fn on_pkt_sealed(&self, sent_bytes: usize) {
        if let Some(budget) = self.lock().burst_budget.as_mut() {
            *budget = budget.saturating_sub(sent_bytes);
        }
    }

    /// Install negotiated local ACK scheduling and peer ACK/PTO bounds.
    pub fn set_ack_delays(&self, local: Duration, peer: Duration) {
        let mut guard = self.0.lock().unwrap();
        guard.max_ack_delay = peer;
        guard.rtt.set_max_ack_delay(peer);
        guard.packet_spaces[Epoch::Data].rcvd_packets.set_max_ack_delay(local);
    }

    /// Borrow the controller across a nonblocking submission and its accounting.
    /// Acquire this before recovery journals; release it before application callbacks.
    pub fn lock(&self) -> MutexGuard<'_, CongestionController> {
        self.0.lock().unwrap()
    }

    /// Returns the PTO period without exponential loss-recovery backoff.
    pub fn pto_base(&self, epoch: Epoch) -> Duration {
        self.0.lock().unwrap().pto_base(epoch)
    }

    /// Discards this path's recovery state and reports every unacknowledged packet as lost.
    pub fn on_path_lost(&self) {
        self.0.lock().unwrap().on_path_lost();
    }
}

impl super::Transport for ArcCC {
    fn on_blocked(&self) {
        self.lock().set_loss_detection_timer();
    }

    fn on_charged(&self) {
        let mut cc = self.lock();
        cc.set_loss_detection_timer();
        cc.wake_sender();
    }

    fn prepare_burst_budget(&self, cx: &mut Context<'_>) -> io::Result<()> {
        let mut cc = self.lock();
        // Tick runs inside the sender's poll; it must not notify a previous registration.
        cc.tx_waker = None;
        cc.tick()?;
        let quota = cc.send_quota();
        // PTO uses each space's probe allowance for one datagram.
        let probe = cc.need_send_ack_eliciting_packets.iter().any(|&need| need > 0);
        cc.pending_burst = quota < cc.mtu() || probe;
        cc.burst_budget = Some(if cc.pending_burst { 0 } else { quota });
        // ACK/recovery timers also need this waiter when quota is already available.
        // The path cancels it if the complete collect poll returns Ready.
        cc.tx_waker = Some(cx.waker().clone());
        Ok(())
    }

    fn refresh_budget(&self) {
        self.lock().burst_budget = None;
    }

    fn do_tick(&self) -> io::Result<()> {
        let mut guard = self.0.lock().unwrap();
        guard.tick()?;

        if guard.pending_burst && guard.send_quota() >= guard.mtu() {
            guard.pending_burst = false;
            guard.wake_sender();
        }
        if guard.need_ack() {
            guard.wake_sender();
        }

        Ok(())
    }

    fn send_quota(&self) -> usize {
        let mut guard = self.0.lock().unwrap();
        if let Some(budget) = guard.burst_budget {
            return budget;
        }
        let send_quota = guard.send_quota();
        guard.pending_burst = send_quota < guard.mtu();
        if guard.pending_burst { 0 } else { send_quota }
    }

    fn retransmit_and_expire_time(&self, epoch: Epoch) -> (Duration, Duration) {
        let guard = self.0.lock().unwrap();
        (
            // 尽量让路径先发起重传
            guard.rtt.loss_delay() + guard.rtt.rttvar(),
            guard.get_pto(epoch),
        )
    }

    fn need_ack(&self, epoch: Epoch) -> Option<(u64, Instant)> {
        let guard = self.0.lock().unwrap();
        guard.packet_spaces[epoch].rcvd_packets.need_ack()
    }

    fn on_pkt_sent(&self, epoch: Epoch, pn: u64, is_ack_eliciting: bool, sent_bytes: usize, in_flight: bool, ack: Option<u64>) {
        self.lock().on_pkt_sent(epoch, pn, is_ack_eliciting, sent_bytes, in_flight, ack);
    }

    fn on_ack_rcvd(&self, epoch: Epoch, ack_frame: &AckFrame) {
        let mut guard = self.0.lock().unwrap();
        let now = Instant::now();
        guard.on_ack_rcvd(epoch, ack_frame, now);
    }

    fn on_pkt_rcvd(&self, epoch: Epoch, pn: u64, is_ack_eliciting: bool) {
        if !is_ack_eliciting {
            return;
        }
        let mut guard = self.0.lock().unwrap();
        if guard.discarded_epochs[epoch] {
            return;
        }
        guard.packet_spaces[epoch].rcvd_packets.on_pkt_rcvd(pn);
    }

    fn get_pto(&self, epoch: Epoch) -> Duration {
        let guard = self.0.lock().unwrap();
        guard.get_pto(epoch)
    }

    fn discard_epoch(&self, epoch: Epoch) {
        let mut guard = self.0.lock().unwrap();
        guard.discard_epoch(epoch);
    }

    fn need_send_ack_eliciting(&self, epoch: Epoch) -> usize {
        let guard = self.0.lock().unwrap();
        guard.need_send_ack_eliciting_packets[epoch]
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicU16};

    use qbase::{handshake::HandshakeFacts, net::validate::ArcValidation, util::IndexDeque};

    use super::*;

    struct NoopFeedback;

    impl Resend for NoopFeedback {
        fn resend(&self, _trigger: PacketLostTrigger, _pns: &mut dyn Iterator<Item = u64>) {}
    }

    fn controller_with_feedback(feedback: Arc<dyn Resend>) -> CongestionController {
        let handshake = Arc::new(HandshakeFacts::with_role(Role::Client));
        handshake.on_handshake_done();
        let pmtu = Arc::new(AtomicU16::new(MSS as u16));

        let validation = ArcValidation::new();
        validation.exempt().unwrap();
        CongestionController::init(
            Algorithm::NewReno,
            Duration::from_millis(25),
            {
                let mut trackers = IndexDeque::with_capacity(3);
                for tracker in [feedback.clone(), feedback.clone(), feedback] {
                    trackers.push_back(tracker).unwrap();
                }
                ArcIndexDeque::from(trackers)
            },
            handshake,
            validation,
            pmtu,
        )
    }

    fn controller() -> CongestionController {
        let feedback: Arc<dyn Resend> = Arc::new(NoopFeedback);
        controller_with_feedback(feedback)
    }

    #[tokio::test(start_paused = true)]
    async fn validation_updates_pto_immediately_without_retaining_the_controller() {
        let validation = ArcValidation::new();
        let handshake = Arc::new(HandshakeFacts::with_role(Role::Client));
        handshake.on_handshake_done();
        let cc = ArcCC::new(
            Algorithm::NewReno,
            Duration::from_millis(25),
            Default::default(),
            handshake,
            validation.clone(),
            Arc::new(AtomicU16::new(MSS as u16)),
        );
        let weak = Arc::downgrade(&cc.0);
        cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
        assert!(cc.lock().loss_detection_timer.is_none());
        validation.on_received(400);
        let deadline = cc.lock().loss_detection_timer.unwrap();
        validation.on_sent(1200);
        assert!(cc.lock().loss_detection_timer.is_none());
        validation.grant().unwrap();
        assert_eq!(cc.lock().loss_detection_timer, Some(deadline));
        let blocked = weak.clone();
        let charged = weak.clone();
        validation
            .revalidate(
                move || {
                    if let Some(cc) = blocked.upgrade() {
                        ArcCC(cc).on_blocked();
                    }
                },
                move || {
                    if let Some(cc) = charged.upgrade() {
                        ArcCC(cc).on_charged();
                    }
                },
            )
            .unwrap();
        assert!(cc.lock().loss_detection_timer.is_none());
        validation.on_received(43);
        assert_eq!(cc.lock().loss_detection_timer, Some(deadline));
        drop(cc);
        assert!(weak.upgrade().is_none());
        validation.on_sent(3);
        validation.on_received(1);
    }

    #[test]
    fn pure_ack_packets_do_not_accumulate_sent_records() {
        let mut controller = controller();

        for pn in 0..100_000 {
            controller.on_packet_sent(pn, Epoch::Data, false, false, 64);
        }

        assert!(controller.packet_spaces[Epoch::Data].sent_packets.is_empty());
    }
}
