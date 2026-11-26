use std::sync::Arc;

use qbase::metric::*;

#[test]
fn test_connection_metrics_new() {
    let metrics = ConnectionMetrics::default();
    assert_eq!(metrics.pending_bytes(), 0);
    assert_eq!(metrics.inflight_bytes(), 0);
    assert_eq!(metrics.acked_bytes(), 0);
}

#[test]
fn test_add_pending_send() {
    let metrics = ConnectionMetrics::default();
    metrics.add_pending(100);
    assert_eq!(metrics.pending_bytes(), 100);
    metrics.add_pending(50);
    assert_eq!(metrics.pending_bytes(), 150);
}

#[test]
fn test_on_data_sent() {
    let metrics = ConnectionMetrics::default();
    metrics.add_pending(200);
    metrics.on_data_sent(150);
    assert_eq!(metrics.pending_bytes(), 50);
    assert_eq!(metrics.inflight_bytes(), 150);
}

#[test]
fn test_on_data_acked() {
    let metrics = ConnectionMetrics::default();
    metrics.add_pending(200);
    metrics.on_data_sent(150);
    metrics.on_data_acked(100);
    assert_eq!(metrics.pending_bytes(), 50);
    assert_eq!(metrics.inflight_bytes(), 50);
    assert_eq!(metrics.acked_bytes(), 100);
}

#[test]
fn test_full_data_flow() {
    let metrics = ConnectionMetrics::default();

    // Application writes 1000 bytes
    metrics.add_pending(1000);
    assert_eq!(metrics.pending_bytes(), 1000);
    assert_eq!(metrics.inflight_bytes(), 0);
    assert_eq!(metrics.acked_bytes(), 0);

    // Transport layer sends 600 bytes
    metrics.on_data_sent(600);
    assert_eq!(metrics.pending_bytes(), 400);
    assert_eq!(metrics.inflight_bytes(), 600);
    assert_eq!(metrics.acked_bytes(), 0);

    // Peer acknowledges 300 bytes
    metrics.on_data_acked(300);
    assert_eq!(metrics.pending_bytes(), 400);
    assert_eq!(metrics.inflight_bytes(), 300);
    assert_eq!(metrics.acked_bytes(), 300);

    // Transport layer sends remaining 400 bytes
    metrics.on_data_sent(400);
    assert_eq!(metrics.pending_bytes(), 0);
    assert_eq!(metrics.inflight_bytes(), 700);
    assert_eq!(metrics.acked_bytes(), 300);

    // Peer acknowledges all remaining data
    metrics.on_data_acked(700);
    assert_eq!(metrics.pending_bytes(), 0);
    assert_eq!(metrics.inflight_bytes(), 0);
    assert_eq!(metrics.acked_bytes(), 1000);
}

#[test]
fn test_arc_connection_metrics() {
    let metrics = Arc::new(ConnectionMetrics::default());
    let metrics_clone = Arc::clone(&metrics);

    metrics.add_pending(100);
    assert_eq!(metrics_clone.pending_bytes(), 100);

    metrics_clone.on_data_sent(100);
    assert_eq!(metrics.inflight_bytes(), 100);
    assert_eq!(metrics.pending_bytes(), 0);
}

#[test]
fn acked_counter_wraps_and_preserves_sampled_delta() {
    let metrics = ConnectionMetrics::default();
    for amount in [usize::MAX, 1, usize::MAX, 1] {
        let before = metrics.acked_bytes();
        metrics.add_pending(amount);
        metrics.on_data_sent(amount);
        assert_eq!(metrics.inflight_bytes(), amount);
        metrics.on_data_acked(amount);
        assert_eq!(metrics.acked_bytes().wrapping_sub(before), amount);
        assert_eq!(metrics.pending_bytes(), 0);
        assert_eq!(metrics.inflight_bytes(), 0);
    }
    assert_eq!(metrics.acked_bytes(), 0);
}

#[test]
fn acked_counter_crosses_the_signed_boundary() {
    let metrics = ConnectionMetrics::default();
    let amount = isize::MAX as usize;
    metrics.add_pending(amount);
    metrics.on_data_sent(amount);
    metrics.on_data_acked(amount);
    let before = metrics.acked_bytes();

    metrics.add_pending(1);
    metrics.on_data_sent(1);
    metrics.on_data_acked(1);
    assert_eq!(metrics.acked_bytes(), amount + 1);
    assert_eq!(metrics.acked_bytes().wrapping_sub(before), 1);
}
