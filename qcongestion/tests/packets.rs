use std::sync::{Arc, Mutex};

use common::*;
use qbase::{Epoch, frame::AckFrame};
use qcongestion::{MSS, Transport};
use tokio::time::Duration;

mod common;

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
async fn does_not_detect_loss_before_any_ack() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
    tokio::time::advance(Duration::from_secs(1)).await;
    cc.do_tick().unwrap();
    assert!(recovered.lock().unwrap().is_empty());
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 1);
    cc.on_path_lost();
    assert_eq!(
        *recovered.lock().unwrap(),
        [0],
        "PTO must leave the packet in flight"
    );
}

#[tokio::test(start_paused = true)]
async fn only_detects_packets_sent_before_largest_ack() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    cc.on_pkt_sent(Epoch::Data, 10, true, MSS, true, None);
    tokio::time::advance(Duration::from_secs(1)).await;
    cc.on_pkt_sent(Epoch::Data, 100, true, MSS, true, None);
    tokio::time::advance(Duration::from_secs(1)).await;
    cc.on_pkt_sent(Epoch::Data, 101, true, MSS, true, None);
    tokio::time::advance(Duration::from_secs(1)).await;
    cc.on_ack_rcvd(Epoch::Data, &ack(100));
    assert_eq!(*recovered.lock().unwrap(), [10]);
    recovered.lock().unwrap().clear();
    tokio::time::advance(Duration::from_secs(3)).await;
    cc.do_tick().unwrap();
    assert!(
        recovered.lock().unwrap().is_empty(),
        "packet 101 is newer than the largest ACK"
    );
    cc.on_path_lost();
    assert_eq!(*recovered.lock().unwrap(), [101]);
}

#[tokio::test(start_paused = true)]
async fn packet_threshold_uses_queue_indexes_not_packet_number_gaps() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    for pn in [10, 100] {
        cc.on_pkt_sent(Epoch::Data, pn, true, MSS, true, None);
    }
    cc.on_ack_rcvd(Epoch::Data, &ack(100));
    assert!(recovered.lock().unwrap().is_empty());
    cc.on_path_lost();
    assert_eq!(*recovered.lock().unwrap(), [10]);
}

#[tokio::test(start_paused = true)]
async fn ack_ranges_match_sparse_sent_packets() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    for pn in [10, 100, 1_000_000] {
        cc.on_pkt_sent(Epoch::Data, pn, true, MSS, true, None);
    }
    // The ACK interval contains a million packet numbers but only three local packets.
    cc.on_ack_rcvd(
        Epoch::Data,
        &AckFrame::new(
            1_000_000u32.into(),
            0u32.into(),
            1_000_000u32.into(),
            vec![],
            None,
        ),
    );
    tokio::time::advance(cc.get_pto(Epoch::Data) * 2).await;
    cc.do_tick().unwrap();
    assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 0);
    cc.on_path_lost();
    assert!(
        recovered.lock().unwrap().is_empty(),
        "every sparse packet was acknowledged"
    );
}

#[tokio::test(start_paused = true)]
async fn discard_reports_only_in_flight_packets() {
    let recovered = Arc::new(Mutex::new(Vec::new()));
    let cc = controller_with_feedback(Arc::new(RecordingFeedback(recovered.clone())));
    // Submission can finish out of PN order. Only packet 11 is old enough to be lost.
    cc.on_pkt_sent(Epoch::Data, 11, true, MSS, true, None);
    tokio::time::advance(Duration::from_millis(10)).await;
    cc.on_pkt_sent(Epoch::Data, 10, true, MSS, true, None);
    cc.on_pkt_sent(Epoch::Data, 12, true, MSS, true, None);
    cc.on_ack_rcvd(Epoch::Data, &ack(12));
    assert_eq!(*recovered.lock().unwrap(), [11]);
    recovered.lock().unwrap().clear();
    cc.on_path_lost();
    assert_eq!(*recovered.lock().unwrap(), [10]);
    recovered.lock().unwrap().clear();
    cc.on_path_lost();
    assert!(recovered.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn test_rcvd_records() {
    let cc = controller();
    cc.set_ack_delays(Duration::from_millis(100), Duration::from_millis(25));
    for pn in 0..10 {
        cc.on_pkt_rcvd(Epoch::Data, pn, true);
    }
    tokio::time::advance(Duration::from_millis(100)).await;
    assert_eq!(cc.need_ack(Epoch::Data).unwrap().0, 9);
    cc.on_pkt_sent(Epoch::Data, 9, false, 0, false, Some(9));
    assert_eq!(cc.need_ack(Epoch::Data), None);
    cc.on_pkt_rcvd(Epoch::Data, 10, true);
    assert_eq!(cc.need_ack(Epoch::Data), None);
    cc.on_pkt_rcvd(Epoch::Data, 15, true);
    assert_eq!(cc.need_ack(Epoch::Data).unwrap().0, 15);
    cc.on_pkt_rcvd(Epoch::Data, 11, true);
    assert_eq!(cc.need_ack(Epoch::Data).unwrap().0, 15);
}

#[tokio::test(start_paused = true)]
async fn sending_an_older_ack_does_not_clear_a_newer_path_trigger() {
    let cc = controller();
    cc.set_ack_delays(Duration::ZERO, Duration::from_millis(25));
    cc.on_pkt_rcvd(Epoch::Data, 100, true);
    cc.on_pkt_rcvd(Epoch::Data, 101, true);
    cc.on_pkt_sent(Epoch::Data, 10, false, 0, false, Some(100));
    assert_eq!(cc.need_ack(Epoch::Data).unwrap().0, 101);
}

#[tokio::test(start_paused = true)]
async fn two_ack_eliciting_packets_trigger_ack_without_waiting_for_delay() {
    let cc = controller();
    cc.on_pkt_rcvd(Epoch::Data, 0, true);
    assert!(cc.need_ack(Epoch::Data).is_none());
    cc.on_pkt_rcvd(Epoch::Data, 1, true);
    assert_eq!(cc.need_ack(Epoch::Data).unwrap().0, 1);
    cc.on_pkt_sent(Epoch::Data, 0, false, 0, false, Some(1));
    cc.on_pkt_rcvd(Epoch::Data, 2, true);
    assert!(cc.need_ack(Epoch::Data).is_none());
    tokio::time::advance(Duration::from_millis(26)).await;
    assert_eq!(cc.need_ack(Epoch::Data).unwrap().0, 2);
}
