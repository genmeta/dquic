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
    metrics.new_pending(100);
    assert_eq!(metrics.pending_bytes(), 100);
    metrics.new_pending(50);
    assert_eq!(metrics.pending_bytes(), 150);
}

#[test]
fn test_on_data_sent() {
    let metrics = ConnectionMetrics::default();
    metrics.new_pending(200);
    metrics.on_data_sent(150);
    assert_eq!(metrics.pending_bytes(), 50);
    assert_eq!(metrics.inflight_bytes(), 150);
}

#[test]
fn test_on_data_acked() {
    let metrics = ConnectionMetrics::default();
    metrics.new_pending(200);
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
    metrics.new_pending(1000);
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

    metrics.new_pending(100);
    assert_eq!(metrics_clone.pending_bytes(), 100);

    metrics_clone.on_data_sent(100);
    assert_eq!(metrics.inflight_bytes(), 100);
    assert_eq!(metrics.pending_bytes(), 0);
}
