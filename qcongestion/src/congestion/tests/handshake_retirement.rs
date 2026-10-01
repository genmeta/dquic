use super::*;

fn shared_controller(handshake: &Arc<HandshakeStatus>) -> ArcCC {
    let mut cc = controller();
    cc.path_status.handshake = handshake.clone();
    ArcCC(Arc::new(Mutex::new(cc)))
}

#[tokio::test(start_paused = true)]
async fn shared_progress_retires_each_paths_spaces_once() {
    for is_server in [false, true] {
        let handshake = Arc::new(HandshakeStatus::new(is_server));
        let controllers = [shared_controller(&handshake), shared_controller(&handshake)];
        handshake.got_handshake_key();
        // Only the client's first send / server's first receive retires Initial.
        if is_server {
            handshake.on_handshake_sent();
        } else {
            handshake.on_handshake_received();
        }
        for cc in &controllers {
            cc.on_pkt_sent(Epoch::Initial, 0, true, MSS, true, None);
            cc.on_pkt_rcvd(Epoch::Initial, 1, true);
            assert!(!cc.lock().discarded_epochs[Epoch::Initial]);
            cc.lock().pto_count = 3;
        }
        if is_server {
            handshake.on_handshake_received();
        } else {
            handshake.on_handshake_sent();
        }
        tokio::time::advance(Duration::from_secs(30)).await;
        for cc in &controllers {
            // Locking has no lifecycle side effects; recovery drives retirement
            // before considering the now-expired Initial timeout.
            assert!(!cc.lock().discarded_epochs[Epoch::Initial]);
            cc.do_tick().unwrap();
            assert!(cc.lock().discarded_epochs[Epoch::Initial]);
            assert_eq!(cc.lock().pto_count, 0);
            cc.on_pkt_sent(Epoch::Initial, 2, true, MSS, true, Some(1));
            cc.on_pkt_rcvd(Epoch::Initial, 3, true);
            assert!(
                cc.lock().packet_spaces[Epoch::Initial]
                    .sent_packets
                    .is_empty()
            );
            assert!(cc.need_ack(Epoch::Initial).is_none());
            assert_eq!(cc.need_send_ack_eliciting(Epoch::Initial), 0);
        }
        handshake.handshake_confirmed();
        for cc in controllers
            .iter()
            .chain([shared_controller(&handshake)].iter())
        {
            cc.do_tick().unwrap();
            assert!(cc.lock().discarded_epochs[Epoch::Handshake]);
            cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
            cc.lock().pto_count = 2;
            cc.do_tick().unwrap();
            assert_eq!(cc.lock().pto_count, 2);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn handshake_ack_on_another_path_cancels_an_armed_anti_deadlock_probe() {
    let handshake = Arc::new(HandshakeStatus::new(false));
    handshake.got_handshake_key();
    let waiting = shared_controller(&handshake);
    let receiving = shared_controller(&handshake);
    handshake.on_handshake_sent();
    waiting.do_tick().unwrap();
    let deadline = waiting.lock().loss_detection_timer.unwrap();
    tokio::time::advance((deadline - Instant::now()) / 2).await;
    waiting.do_tick().unwrap();
    assert_eq!(waiting.lock().loss_detection_timer, Some(deadline));
    receiving.on_pkt_sent(Epoch::Handshake, 0, true, MSS, true, None);
    receiving.on_ack_rcvd(
        Epoch::Handshake,
        &AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None),
    );
    // Shared progress cancels the old timer before its deadline, rather than
    // relying on an early return inside the timeout handler.
    assert!(Instant::now() < deadline);
    waiting.do_tick().unwrap();
    assert!(waiting.lock().loss_detection_timer.is_none());
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    waiting.do_tick().unwrap();
    assert_eq!(waiting.need_send_ack_eliciting(Epoch::Handshake), 0);
    assert_eq!(waiting.lock().pto_count, 0);
    assert!(waiting.lock().loss_detection_timer.is_none());
}
