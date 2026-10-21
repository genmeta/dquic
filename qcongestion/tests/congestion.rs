use std::sync::{Arc, Mutex, RwLock};

use common::*;
use qbase::{
    Epoch,
    frame::AckFrame,
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::{ArcCC, HandshakeStatus, MSS, Resend, Transport};
use qevent::quic::recovery::PacketLostTrigger;
use tokio::time::{Duration, Instant};

mod common;
mod congestion {
    mod handshake_retirement;
}

fn ack(pn: u64) -> AckFrame {
    AckFrame::new(
        pn.try_into().unwrap(),
        0u32.into(),
        0u32.into(),
        vec![],
        None,
    )
}

#[tokio::test(start_paused = true)]
async fn pacing_tokens_do_not_bypass_the_congestion_window() {
    let cc = controller();
    let window = cc.send_quota();
    assert_eq!(window, 10 * MSS);
    for pn in 0..window / MSS {
        cc.on_pkt_sent(Epoch::Data, pn as u64, true, MSS, true, None);
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
            assert!(
                trackers.try_write().is_ok(),
                "release the read lock before feedback"
            );
            self.recovered.lock().unwrap().extend(pns);
        }
    }

    let mut entries = IndexDeque::<Arc<dyn Resend>, 2>::with_capacity(3);
    entries.push_back(Arc::new(NoopFeedback)).unwrap();
    let trackers = Arc::new(RwLock::new(entries));
    let handshake = Arc::new(HandshakeStatus::new(false));
    handshake.handshake_confirmed();
    let controllers = [
        controller_with(
            path_status(handshake.clone()),
            ArcIndexDeque::from(trackers.clone()),
        ),
        controller_with(
            path_status(handshake),
            ArcIndexDeque::from(trackers.clone()),
        ),
    ];
    let recovered = Arc::new(Mutex::new(Vec::new()));
    {
        let mut entries = trackers.write().unwrap();
        entries.push_back(Arc::new(NoopFeedback)).unwrap();
        entries
            .push_back(Arc::new(UnlockedFeedback {
                trackers: Arc::downgrade(&trackers),
                recovered: recovered.clone(),
            }))
            .unwrap();
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
    assert_eq!(
        trackers.write().unwrap().pop_front().unwrap().0,
        Epoch::Data as u64
    );
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
    assert_eq!(
        cc.pto_base(Epoch::Data),
        data_pto + Duration::from_millis(30)
    );
    cc.on_pkt_rcvd(Epoch::Data, 0, true);
    assert!(cc.need_ack(Epoch::Data).is_none());
    tokio::time::advance(Duration::from_millis(4)).await;
    assert!(cc.need_ack(Epoch::Data).is_some());
}

#[tokio::test(start_paused = true)]
async fn handshake_ack_completes_peer_address_validation_before_handshake_done() {
    let handshake = Arc::new(HandshakeStatus::new(false));
    handshake.got_handshake_key();
    let cc = controller_with(
        path_status(handshake.clone()),
        trackers(Arc::new(NoopFeedback)),
    );
    let sent_at = Instant::now();
    cc.on_pkt_sent(Epoch::Handshake, 0, true, MSS, true, None);
    tokio::time::advance(cc.get_pto(Epoch::Handshake)).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Handshake), 1);
    assert!(cc.get_pto(Epoch::Handshake) > cc.pto_base(Epoch::Handshake));
    cc.on_pkt_sent(Epoch::Handshake, 1, true, MSS, true, None);
    cc.on_ack_rcvd(
        Epoch::Handshake,
        &AckFrame::new(1u32.into(), 0u32.into(), 1u32.into(), vec![], None),
    );
    assert!(!handshake.is_handshake_confirmed());
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
    let handshake = Arc::new(HandshakeStatus::new(false));
    let cc = controller_with(
        path_status(handshake.clone()),
        trackers(Arc::new(RecordingFeedback(recovered.clone()))),
    );
    cc.on_pkt_sent(Epoch::Initial, 0, true, MSS, true, None);
    cc.on_pkt_rcvd(Epoch::Initial, 7, true);
    assert_eq!(cc.need_ack(Epoch::Initial).unwrap().0, 7);
    tokio::time::advance(cc.get_pto(Epoch::Initial)).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Initial), 1);
    handshake.handshake_confirmed();
    cc.discard_epoch(Epoch::Initial);
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Initial), 0);
    assert!(cc.need_ack(Epoch::Initial).is_none());
    cc.on_path_lost();
    assert!(recovered.lock().unwrap().is_empty());
}

#[test]
fn path_loss_does_not_recover_handshake_spaces_before_confirmation() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with(
        path_status(Arc::new(HandshakeStatus::new(false))),
        trackers(Arc::new(RecordingFeedback(recovered.clone()))),
    );
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
    assert!(
        recovered.lock().unwrap().is_empty(),
        "PTO requests a probe without declaring loss"
    );
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
    assert!(
        recovered.lock().unwrap().is_empty(),
        "other paths' PN gaps are not loss evidence"
    );
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
    let handshake = Arc::new(HandshakeStatus::new(false));
    handshake.handshake_confirmed();
    let status = path_status(handshake);
    let cc = controller_with(status.clone(), trackers(Arc::new(NoopFeedback)));
    cc.do_tick().unwrap();
    status.enter_anti_amplification_limit();
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    let base = cc.get_pto(Epoch::Data);
    tokio::time::advance(base).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 0);
    assert_eq!(cc.get_pto(Epoch::Data), base);
    cc.grant_anti_amplification();
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 1);
    assert!(cc.get_pto(Epoch::Data) > base);
}

#[tokio::test(start_paused = true)]
async fn ack_only_send_that_exhausts_amplification_credit_disarms_pto() {
    let handshake = Arc::new(HandshakeStatus::new(false));
    handshake.handshake_confirmed();
    let status = path_status(handshake);
    let cc = controller_with(status.clone(), trackers(Arc::new(NoopFeedback)));
    cc.do_tick().unwrap();
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    let base = cc.get_pto(Epoch::Data);
    status.enter_anti_amplification_limit();
    cc.on_pkt_sent(Epoch::Data, 1, false, 30, false, None);
    tokio::time::advance(base).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 0);
    assert_eq!(cc.get_pto(Epoch::Data), base);
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
            assert_eq!(result.unwrap_err().to_string(), "Too many PTOs: 7");
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
    healthy.on_ack_rcvd(
        Epoch::Data,
        &AckFrame::new(
            10u32.into(),
            0u32.into(),
            0u32.into(),
            vec![(0u32.into(), 0u32.into())],
            None,
        ),
    );

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
            assert_eq!(result.unwrap_err().to_string(), "Too many PTOs: 7");
        }
    }
    assert_eq!(black_holed.need_send_ack_eliciting(Epoch::Data), 7);
    healthy.on_path_lost();
    assert!(
        recovered.lock().unwrap().is_empty(),
        "all ACK ranges must clear the healthy path"
    );
}
