mod path {
    mod cids;
}

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::{
    frame::{PathChallengeFrame, io::ReceiveFrame},
    net::{addr::EndpointAddr, route::Pathway},
    packet::{Constraints, GetType, OneRttHeader, Package, PacketBuffer},
    time::heartbeat::ArcHeartbeat,
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::{HandshakeStatus, Transport as _};
use qtransport::path::Path;

struct Counter(AtomicUsize);
impl std::task::Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test(start_paused = true)]
async fn handshake_confirmation_stops_early_epoch_pto() {
    use qbase::Epoch;
    let handshake = Arc::new(HandshakeStatus::new(false));
    let path = Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:5500".parse().unwrap()),
        ),
        handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        ArcIndexDeque::from(IndexDeque::with_capacity(3)),
        &qtransport::path::PathCids::new(Default::default()),
    );
    path.exempt();
    handshake.got_handshake_key();
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        path.cc.on_pkt_sent(epoch, 0, true, 1200, true, None);
    }
    handshake.handshake_confirmed();
    for _ in 0..8 {
        tokio::time::advance(Duration::from_secs(1)).await;
        path.cc.do_tick().unwrap();
        assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
        assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn repeatedly_polling_unlimited_credit_does_not_postpone_handshake_pto() {
    use qbase::Epoch;

    let path = Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:5500".parse().unwrap()),
        ),
        Arc::new(HandshakeStatus::new(false)),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        ArcIndexDeque::default(),
        &qtransport::path::PathCids::new(Default::default()),
    );
    path.exempt();
    let step = path.cc.get_pto(Epoch::Initial) / 10;
    for _ in 0..11 {
        tokio::time::advance(step).await;
        assert!(matches!(
            path.poll_credit(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(usize::MAX))
        ));
        path.cc.do_tick().unwrap();
    }
    assert!(path.cc.need_send_ack_eliciting(Epoch::Initial) > 0);
}

#[tokio::test(start_paused = true)]
async fn validation_registers_only_when_both_sources_are_empty() {
    for queued in [false, true] {
        for quota in [0, 128] {
            let path = Path::new(
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:5500".parse().unwrap()),
                ),
                Arc::new(HandshakeStatus::new(true)),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                ArcIndexDeque::default(),
                &qtransport::path::PathCids::new(Default::default()),
            );
            if queued {
                path.validation
                    .recv_frame(PathChallengeFrame::from_slice(&[1; 8]))
                    .unwrap();
                path.validation
                    .challenge(PathChallengeFrame::from_slice(&[2; 8]))
                    .unwrap();
            }
            let counter = Arc::new(Counter(AtomicUsize::new(0)));
            let waker = Waker::from(counter.clone());
            let mut bytes = bytes::BytesMut::new();
            let mut frames = Vec::new();
            let mut limits = Constraints {
                flow_ctrl: 0,
                send_quota: quota,
                credit: 128,
                min_size: 0,
                max_size: 128,
                ..Default::default()
            };
            let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
            let result = path.validation.clone().poll_dump(
                &mut Context::from_waker(&waker),
                &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
            );
            assert_eq!(result.is_pending(), !queued);
            if queued {
                assert_eq!(result, Poll::Ready(Ok(if quota == 0 { 0 } else { 2 })));
            }
            path.validation
                .recv_frame(PathChallengeFrame::from_slice(&[3; 8]))
                .unwrap();
            assert_eq!(counter.0.load(Ordering::Relaxed), usize::from(!queued));
        }
    }
}

#[tokio::test]
async fn every_duplicate_challenge_is_packaged_as_a_response() {
    let path = Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:5500".parse().unwrap()),
        ),
        Arc::new(HandshakeStatus::new(true)),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        ArcIndexDeque::default(),
        &qtransport::path::PathCids::new(Default::default()),
    );
    for _ in 0..10 {
        path.validation
            .recv_frame(PathChallengeFrame::from_slice(&[1; 8]))
            .unwrap();
    }
    let mut bytes = bytes::BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 128,
        credit: 128,
        max_size: 128,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let result = path.validation.clone().poll_dump(
        &mut Context::from_waker(Waker::noop()),
        &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
    );
    assert_eq!(result, Poll::Ready(Ok(10)));
}
