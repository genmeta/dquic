use crate::*;

fn shared_controller(handshake: &Arc<HandshakeStatus>) -> ArcCC {
    controller_with(
        path_status(handshake.clone()),
        trackers(Arc::new(NoopFeedback)),
    )
}

#[tokio::test(start_paused = true)]
async fn shared_progress_retires_each_paths_spaces_once() {
    for is_server in [false, true] {
        let handshake = Arc::new(HandshakeStatus::new(is_server));
        let mut controllers = vec![shared_controller(&handshake), shared_controller(&handshake)];
        handshake.got_handshake_key();
        // Only the client's first send / server's first receive retires Initial.
        if is_server {
            handshake.on_handshake_sent();
        } else {
            handshake.on_handshake_received();
        }
        let sent_at = Instant::now();
        for cc in &controllers {
            cc.on_pkt_sent(Epoch::Initial, 0, true, MSS, true, None);
            cc.on_pkt_rcvd(Epoch::Initial, 1, true);
            assert_eq!(cc.need_ack(Epoch::Initial).unwrap().0, 1);
        }
        // Establish real PTO backoff before retiring the shared Initial space.
        for _ in 0..3 {
            let deadline = sent_at + controllers[0].get_pto(Epoch::Initial);
            tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
            for cc in &controllers {
                cc.do_tick().unwrap();
                assert_eq!(cc.need_ack(Epoch::Initial).unwrap().0, 1);
            }
        }
        for cc in &controllers {
            assert_eq!(cc.need_send_ack_eliciting(Epoch::Initial), 3);
            assert!(cc.get_pto(Epoch::Initial) > cc.pto_base(Epoch::Initial));
        }
        if is_server {
            handshake.on_handshake_received();
        } else {
            handshake.on_handshake_sent();
        }
        tokio::time::advance(Duration::from_secs(30)).await;
        for cc in &controllers {
            // Taking the submission guard must not retire spaces; recovery does that on tick.
            drop(cc.lock());
            assert_eq!(cc.need_ack(Epoch::Initial).unwrap().0, 1);
            cc.do_tick().unwrap();
            assert_eq!(cc.get_pto(Epoch::Initial), cc.pto_base(Epoch::Initial));
            cc.on_pkt_sent(Epoch::Initial, 2, true, MSS, true, Some(1));
            cc.on_pkt_rcvd(Epoch::Initial, 3, true);
            assert!(cc.need_ack(Epoch::Initial).is_none());
            assert_eq!(cc.need_send_ack_eliciting(Epoch::Initial), 0);
        }

        handshake.handshake_confirmed();
        controllers.push(shared_controller(&handshake));
        let sent_at = Instant::now();
        for cc in &controllers {
            cc.do_tick().unwrap();
            let quota = cc.send_quota();
            cc.on_pkt_sent(Epoch::Handshake, 0, true, MSS, true, None);
            assert_eq!(cc.send_quota(), quota);
            cc.on_pkt_rcvd(Epoch::Handshake, 1, true);
            assert!(cc.need_ack(Epoch::Handshake).is_none());
            assert_eq!(cc.need_send_ack_eliciting(Epoch::Handshake), 0);
            cc.on_pkt_sent(Epoch::Data, 0, true, MSS, true, None);
        }
        for _ in 0..2 {
            let deadline = sent_at + controllers[0].get_pto(Epoch::Data);
            tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
            for cc in &controllers {
                cc.do_tick().unwrap();
            }
        }
        for cc in &controllers {
            assert_eq!(cc.need_send_ack_eliciting(Epoch::Data), 2);
            let backed_off = cc.get_pto(Epoch::Data);
            assert!(backed_off > cc.pto_base(Epoch::Data));
            cc.do_tick().unwrap();
            assert_eq!(cc.get_pto(Epoch::Data), backed_off);
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
    let deadline = Instant::now() + waiting.get_pto(Epoch::Handshake);
    tokio::time::advance((deadline - Instant::now()) / 2).await;
    waiting.do_tick().unwrap();
    assert_eq!(waiting.need_send_ack_eliciting(Epoch::Handshake), 0);
    receiving.on_pkt_sent(Epoch::Handshake, 0, true, MSS, true, None);
    receiving.on_ack_rcvd(Epoch::Handshake, &ack(0));
    assert!(Instant::now() < deadline);
    waiting.do_tick().unwrap();
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    waiting.do_tick().unwrap();
    assert_eq!(waiting.need_send_ack_eliciting(Epoch::Handshake), 0);
    assert_eq!(
        waiting.get_pto(Epoch::Handshake),
        waiting.pto_base(Epoch::Handshake)
    );
    // A later tick must not reveal a rescheduled anti-deadlock timer either.
    tokio::time::advance(waiting.get_pto(Epoch::Handshake) * 2).await;
    waiting.do_tick().unwrap();
    assert_eq!(waiting.need_send_ack_eliciting(Epoch::Handshake), 0);
    assert_eq!(
        waiting.get_pto(Epoch::Handshake),
        waiting.pto_base(Epoch::Handshake)
    );
}
