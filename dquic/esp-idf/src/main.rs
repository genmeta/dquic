mod echo;
mod udp;

fn main() -> Result<(), dquic_esp_idf::Error> {
    dquic_esp_idf::initialize()?;
    let metrics = dquic::qbase::metric::ConnectionMetrics::default();
    for amount in [usize::MAX, 1, usize::MAX, 1] {
        let before = metrics.acked_bytes();
        metrics.add_pending(amount);
        metrics.on_data_sent(amount);
        metrics.on_data_acked(amount);
        assert_eq!(metrics.acked_bytes().wrapping_sub(before), amount);
        assert_eq!(metrics.pending_bytes(), 0);
        assert_eq!(metrics.inflight_bytes(), 0);
    }
    assert_eq!(metrics.acked_bytes(), 0);
    println!("PASS: pointer-sized counters wrap and preserve sampled deltas on C3");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().thread_stack_size(8192).build()?;
    runtime.block_on(async {
        udp::check().await?;
        echo::run().await
    })?;
    dquic_esp_idf::report_heap("echo complete");
    Ok(())
}
