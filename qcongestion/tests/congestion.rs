use std::sync::{Arc, Mutex, RwLock};

use common::*;
use qbase::{
    Epoch,
    frame::AckFrame,
    handshake::HandshakeFacts,
    net::validate::ArcValidation,
    role::Role,
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::{ArcCC, MSS, Resend, Transport};
use qevent::quic::recovery::PacketLostTrigger;
use tokio::time::{Duration, Instant};

mod common;
mod congestion {
    mod handshake_retirement;
}

fn amplification_controller(feedback: Arc<dyn Resend>) -> (ArcCC, ArcValidation) {
    let validation = ArcValidation::new();
    let handshake = Arc::new(HandshakeFacts::with_role(Role::Client));
    handshake.on_handshake_done();
    (controller_with_validation(handshake, trackers(feedback), validation.clone()), validation)
}

fn ack(pn: u64) -> AckFrame {
    AckFrame::new(pn.try_into().unwrap(), 0u32.into(), 0u32.into(), vec![], None)
}

#[tokio::test(start_paused = true)]
async fn congestion_notifications_consume_the_waiter_until_registered_again() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
    };

    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let cc = controller();
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    cc.prepare_burst_budget(&mut Context::from_waker(&waker)).unwrap();
    cc.on_charged();
    cc.on_charged();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    cc.prepare_burst_budget(&mut Context::from_waker(&waker)).unwrap();
    cc.on_charged();
    assert_eq!(counter.0.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn delayed_acks_rearm_the_sender_even_when_send_quota_is_available() {
    let cc = controller();
    for pn in 0..4 {
        cc.on_pkt_rcvd(Epoch::Data, pn, true);
        let largest = tokio::time::timeout(
            Duration::from_millis(100),
            std::future::poll_fn(|cx| {
                cc.prepare_burst_budget(cx).unwrap();
                assert!(cc.send_quota() > 0);
                if let Some((largest, _)) = cc.need_ack(Epoch::Data) {
                    cc.cancel(cx.waker());
                    std::task::Poll::Ready(largest)
                } else {
                    std::task::Poll::Pending
                }
            }),
        )
        .await
        .expect("the ACK timer lost its registered sender");
        assert_eq!(largest, pn);
        cc.on_pkt_sent(Epoch::Data, pn, false, 32, false, Some(largest));
        cc.refresh_budget();
    }
}

#[tokio::test(start_paused = true)]
async fn pacing_tokens_do_not_bypass_the_congestion_window() {
    let cc = controller();
    let window = cc.send_quota();
    assert_eq!(window, 10 * MSS);
    cc.prepare_burst_budget(&mut std::task::Context::from_waker(std::task::Waker::noop())).unwrap();
    cc.on_pkt_sealed(window - 300);
    assert_eq!(cc.send_quota(), 300, "the prepared budget keeps a sub-MTU remainder");
    cc.do_tick().unwrap();
    assert_eq!(cc.send_quota(), 300, "a tick must not refill the assembly budget");
    cc.on_pkt_sealed(300);
    assert_eq!(cc.send_quota(), 0, "Some(0) must not fall back to live credit");
    cc.refresh_budget();
    assert_eq!(cc.send_quota(), window, "discarding sealed packets must not charge the real CC");
    cc.prepare_burst_budget(&mut std::task::Context::from_waker(std::task::Waker::noop())).unwrap();
    for pn in 0..window / MSS {
        cc.on_pkt_sent(Epoch::Data, pn as u64, true, MSS, true, None);
        assert_eq!(cc.send_quota(), window - (pn + 1) * MSS, "submission clears the prepared budget");
    }
    // The pacing bucket refills, but none of the outstanding data is ACKed.
    tokio::time::advance(Duration::from_millis(10)).await;
    assert_eq!(cc.send_quota(), 0);
    cc.on_ack_rcvd(Epoch::Data, &ack(0));
    assert!(cc.send_quota() > 0);
    assert!(cc.send_quota() <= 2 * MSS);
}

#[tokio::test(start_paused = true)]
async fn shared_trackers_follow_append_and_retirement() {
    struct UnlockedFeedback {
        trackers: std::sync::Weak<RwLock<IndexDeque<Arc<dyn Resend>, 2>>>,
        recovered: Arc<Mutex<Vec<u64>>>,
    }
    impl Resend for UnlockedFeedback {
        fn resend(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
            let trackers = self.trackers.upgrade().unwrap();
            assert!(trackers.try_write().is_ok(), "release the read lock before feedback");
            self.recovered.lock().unwrap().extend(pns);
        }
    }

    let mut entries = IndexDeque::<Arc<dyn Resend>, 2>::with_capacity(3);
    entries.push_back(Arc::new(NoopFeedback)).unwrap();
    let trackers = Arc::new(RwLock::new(entries));
    let handshake = Arc::new(HandshakeFacts::with_role(Role::Client));
    handshake.on_handshake_done();
    let controllers = [
        controller_with(handshake.clone(), ArcIndexDeque::from(trackers.clone())),
        controller_with(handshake, ArcIndexDeque::from(trackers.clone())),
    ];
    let recovered = Arc::new(Mutex::new(Vec::new()));
    {
        let mut entries = trackers.write().unwrap();
        entries.push_back(Arc::new(NoopFeedback)).unwrap();
        entries.push_back(Arc::new(UnlockedFeedback { trackers: Arc::downgrade(&trackers), recovered: recovered.clone() })).unwrap();
        // Removing both early spaces must preserve Data's epoch index.
        entries.drain_to(Epoch::Data as u64).for_each(drop);
    }
    for cc in &controllers {
        for pn in 0..4 {
            cc.on_pkt_sent(Epoch::Data, pn, true, MSS, true, None);
        }
        cc.on_ack_rcvd(Epoch::Data, &ack(3));
    }
    assert_eq!(*recovered.lock().unwrap(), [0, 0]);
    assert_eq!(trackers.write().unwrap().pop_front().unwrap().0, Epoch::Data as u64);
    for cc in &controllers {
        cc.on_path_lost();
    }
    assert_eq!(*recovered.lock().unwrap(), [0, 0]);
}

#[tokio::test(start_paused = true)]
async fn negotiated_ack_delays_separate_local_scheduling_from_peer_pto() {
    let cc = controller();
    let initial_pto = cc.pto_base(Epoch::Initial);
    let data_pto = cc.pto_base(Epoch::Data);
    cc.set_ack_delays(Duration::from_millis(3), Duration::from_millis(55));
    assert_eq!(cc.pto_base(Epoch::Initial), initial_pto);
    assert_eq!(cc.pto_base(Epoch::Data), data_pto + Duration::from_millis(30));
    cc.on_pkt_rcvd(Epoch::Data, 0, true);
    assert!(cc.need_ack(Epoch::Data).is_none());
    tokio::time::advance(Duration::from_millis(4)).await;
    assert!(cc.need_ack(Epoch::Data).is_some());
}

#[tokio::test(start_paused = true)]
async fn handshake_ack_completes_peer_address_validation_before_handshake_done() {
    let handshake = Arc::new(HandshakeFacts::with_role(Role::Client));
    handshake.install_handshake_key();
    let cc = controller_with(handshake.clone(), trackers(Arc::new(NoopFeedback)));
    let sent_at = Instant::now();
    cc.on_pkt_sent(Epoch::Handshake, 0, true, MSS, true, None);
    tokio::time::advance(cc.get_pto(Epoch::Handshake)).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Handshake), 1);
    cc.prepare_burst_budget(&mut std::task::Context::from_waker(std::task::Waker::noop())).unwrap();
    assert_eq!(cc.send_quota(), 0, "PTO uses the space's probe allowance for one datagram");
    assert!(cc.get_pto(Epoch::Handshake) > cc.pto_base(Epoch::Handshake));
    cc.on_pkt_sent(Epoch::Handshake, 1, true, MSS, true, None);
    cc.on_ack_rcvd(Epoch::Handshake, &AckFrame::new(1u32.into(), 0u32.into(), 1u32.into(), vec![], None));
    assert!(!handshake.is_handshake_done());
    assert_eq!(cc.get_pto(Epoch::Handshake), cc.pto_base(Epoch::Handshake));
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Handshake), 0);
    // No anti-deadlock probes remain necessary, even though HANDSHAKE_DONE has not arrived.
    tokio::time::advance(Instant::now() - sent_at + cc.get_pto(Epoch::Handshake) * 2).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Handshake), 0);
    assert_eq!(cc.get_pto(Epoch::Handshake), cc.pto_base(Epoch::Handshake));
}

#[tokio::test(start_paused = true)]
async fn discarded_epochs_ignore_late_sends_and_do_not_reset_data_pto_twice() {
    let cc = controller();
    cc.discard_epoch(Epoch::Initial);
    cc.discard_epoch(Epoch::Handshake);
    let quota = cc.send_quota();
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        cc.on_pkt_sent(epoch, 0, true, MSS, true, None);
        cc.on_pkt_rcvd(epoch, 1, true);
        assert_eq!(cc.send_quota(), quota);
        assert!(cc.need_ack(epoch).is_none());
        assert_eq!(cc.need_send_ack_eliciting(epoch), 0);
    }
    cc.on_pkt_sent(Epoch::Data, 1, true, MSS, true, None);
    tokio::time::advance(cc.get_pto(Epoch::Data)).await;
    cc.do_tick().unwrap();
    let backed_off = cc.get_pto(Epoch::Data);
    assert!(backed_off > cc.pto_base(Epoch::Data));
    cc.discard_epoch(Epoch::Initial);
    cc.discard_epoch(Epoch::Handshake);
    assert_eq!(cc.get_pto(Epoch::Data), backed_off);
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 1);
}

#[tokio::test(start_paused = true)]
async fn discarded_handshake_spaces_do_not_leak_probes_or_recovery() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let handshake = Arc::new(HandshakeFacts::with_role(Role::Client));
    let cc = controller_with(handshake.clone(), trackers(Arc::new(RecordingFeedback(recovered.clone()))));
    cc.on_pkt_sent(Epoch::Initial, 0, true, MSS, true, None);
    cc.on_pkt_rcvd(Epoch::Initial, 7, true);
    assert_eq!(cc.need_ack(Epoch::Initial).unwrap().0, 7);
    tokio::time::advance(cc.get_pto(Epoch::Initial)).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Initial), 1);
    handshake.on_handshake_done();
    cc.discard_epoch(Epoch::Initial);
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Initial), 0);
    assert!(cc.need_ack(Epoch::Initial).is_none());
    cc.on_path_lost();
    assert!(recovered.lock().unwrap().is_empty());
}

#[test]
fn path_loss_does_not_recover_handshake_spaces_before_confirmation() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with(Arc::new(HandshakeFacts::with_role(Role::Client)), trackers(Arc::new(RecordingFeedback(recovered.clone()))));
    cc.on_pkt_sent(Epoch::Initial, 0, true, MSS, true, None);
    cc.on_pkt_sent(Epoch::Handshake, 1, true, MSS, true, None);
    cc.on_pkt_sent(Epoch::Data, 2, true, MSS, true, None);
    cc.on_path_lost();
    assert_eq!(*recovered.lock().unwrap(), [2]);
}

#[tokio::test(start_paused = true)]
async fn sending_without_ack_arms_pto_not_loss_timer() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    let pto = cc.get_pto(Epoch::Data);
    tokio::time::advance(pto - Duration::from_nanos(1)).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 0);
    assert_eq!(cc.get_pto(Epoch::Data), pto);
    tokio::time::advance(Duration::from_nanos(1)).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 1);
    assert!(cc.get_pto(Epoch::Data) > pto);
    assert!(recovered.lock().unwrap().is_empty(), "PTO requests a probe without declaring loss");
}

#[tokio::test(start_paused = true)]
async fn pto_base_ignores_loss_recovery_backoff() {
    let cc = controller();
    let base = cc.pto_base(Epoch::Data);
    let sent_at = Instant::now();
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    for _ in 0..3 {
        let deadline = sent_at + cc.get_pto(Epoch::Data);
        tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
        cc.do_tick().unwrap();
    }
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 3);
    assert_eq!(cc.pto_base(Epoch::Data), base);
    assert!(cc.get_pto(Epoch::Data) > base);
}

#[tokio::test(start_paused = true)]
async fn multipath_packet_threshold_counts_sends_on_this_path() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    for pn in [0, 100] {
        cc.on_pkt_sent(Epoch::Data, pn, true, MSS, true, None);
    }
    cc.on_ack_rcvd(Epoch::Data, &ack(100));
    assert!(recovered.lock().unwrap().is_empty(), "other paths' PN gaps are not loss evidence");
    for pn in [200, 300] {
        cc.on_pkt_sent(Epoch::Data, pn, true, MSS, true, None);
    }
    cc.on_ack_rcvd(Epoch::Data, &ack(300));
    assert_eq!(*recovered.lock().unwrap(), [0]);
}

#[tokio::test(start_paused = true)]
async fn ack_with_largest_on_another_path_does_not_sample_rtt() {
    let cc = controller();
    let pto = cc.pto_base(Epoch::Data);
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    tokio::time::advance(Duration::from_millis(5)).await;
    let ack = AckFrame::new(1u32.into(), 0u32.into(), 1u32.into(), vec![], None);
    cc.on_ack_rcvd(Epoch::Data, &ack);
    assert_eq!(cc.pto_base(Epoch::Data), pto);
}

#[tokio::test(start_paused = true)]
async fn regression_releasing_amplification_credit_rearms_recovery() {
    let (cc, validation) = amplification_controller(Arc::new(NoopFeedback));
    cc.do_tick().unwrap();
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    let base = cc.get_pto(Epoch::Data);
    tokio::time::advance(base).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 0);
    assert_eq!(cc.get_pto(Epoch::Data), base);
    validation.on_received(43);
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 1);
    assert!(cc.get_pto(Epoch::Data) > base);
}

#[tokio::test(start_paused = true)]
async fn amplification_blocking_disarms_an_already_running_pto() {
    let (cc, validation) = amplification_controller(Arc::new(NoopFeedback));
    validation.on_received(400);
    cc.do_tick().unwrap();
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    let base = cc.get_pto(Epoch::Data);
    validation.on_sent(1200);
    tokio::time::advance(base).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 0);
    assert_eq!(cc.get_pto(Epoch::Data), base);
}

#[tokio::test(start_paused = true)]
async fn amplification_unblocking_preserves_the_deadline_and_backoff() {
    let (cc, validation) = amplification_controller(Arc::new(NoopFeedback));
    validation.on_received(400);
    cc.do_tick().unwrap();
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    tokio::time::advance(cc.get_pto(Epoch::Data)).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 1);
    cc.on_pkt_sent(Epoch::Data, 1, true, 30, true, None);
    let backoff = cc.get_pto(Epoch::Data);
    validation.on_sent(1200);
    tokio::time::advance(backoff / 2).await;
    for _ in 0..4 {
        validation.on_received(43);
        cc.do_tick().unwrap();
        assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 0);
        assert_eq!(cc.get_pto(Epoch::Data), backoff);
        tokio::time::advance(backoff / 8).await;
    }
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 1);
    assert!(cc.get_pto(Epoch::Data) > backoff);
}

#[tokio::test(start_paused = true)]
async fn amplification_blocking_preserves_time_threshold_loss_detection() {
    let lost = Arc::new(Mutex::new(Vec::new()));
    let (cc, validation) = amplification_controller(Arc::new(RecordingFeedback(lost.clone())));
    validation.on_received(400);
    cc.do_tick().unwrap();
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    cc.on_pkt_sent(Epoch::Data, 1, true, MSS, true, None);
    tokio::time::advance(Duration::from_millis(5)).await;
    cc.on_ack_rcvd(Epoch::Data, &ack(1));
    assert!(lost.lock().unwrap().is_empty());
    validation.on_sent(1200);
    tokio::time::advance(Duration::from_millis(10)).await;
    cc.do_tick().unwrap();
    assert_eq!(*lost.lock().unwrap(), [0]);
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 0);
}

#[tokio::test(start_paused = true)]
async fn packet_threshold_survives_removing_the_queue_front() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    for pn in [0, 100, 200, 300, 400] {
        cc.on_pkt_sent(Epoch::Data, pn, true, MSS, true, None);
    }
    for pn in [0, 200] {
        cc.on_ack_rcvd(Epoch::Data, &ack(pn));
    }
    assert!(recovered.lock().unwrap().is_empty());
    cc.on_ack_rcvd(Epoch::Data, &ack(400));
    assert_eq!(*recovered.lock().unwrap(), [100]);
}

#[tokio::test(start_paused = true)]
async fn one_way_receive_traffic_cannot_starve_pto() {
    let cc = controller();
    let sent_at = Instant::now();
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    for pn in 1..=7 {
        cc.on_pkt_rcvd(Epoch::Data, pn, true);
        let deadline = sent_at + cc.get_pto(Epoch::Data);
        tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
        let result = cc.do_tick();
        if pn < 7 {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        }
        assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), pn as usize);
    }
}

#[tokio::test(start_paused = true)]
async fn ack_ranges_keep_healthy_path_alive_while_other_path_times_out() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let healthy = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    let black_holed = controller();
    let sent_at = Instant::now();
    healthy.on_pkt_sent(Epoch::Data, 8, true, MSS, true, None);
    black_holed.on_pkt_sent(Epoch::Data, 9, true, MSS, true, None);
    healthy.on_pkt_sent(Epoch::Data, 10, true, MSS, true, None);
    healthy.on_ack_rcvd(Epoch::Data, &AckFrame::new(10u32.into(), 0u32.into(), 0u32.into(), vec![(0u32.into(), 0u32.into())], None));

    for timeout_count in 1..=7 {
        let pn = 10 + timeout_count * 2;
        healthy.on_pkt_sent(Epoch::Data, pn, true, MSS, true, None);
        healthy.on_ack_rcvd(Epoch::Data, &ack(pn));
        let deadline = sent_at + black_holed.get_pto(Epoch::Data);
        tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
        healthy.do_tick().unwrap();
        assert_eq!(healthy.need_send_ack_eliciting(Epoch::Data), 0);
        assert_eq!(healthy.get_pto(Epoch::Data), healthy.pto_base(Epoch::Data));
        let result = black_holed.do_tick();
        if timeout_count < 7 {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        }
    }
    assert_eq!(black_holed.need_send_ack_eliciting(Epoch::Data), 7);
    healthy.on_path_lost();
    assert!(recovered.lock().unwrap().is_empty(), "all ACK ranges must clear the healthy path");
}
