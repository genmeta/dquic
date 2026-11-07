mod support {
    pub mod path;
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
    handshake::HandshakeFacts,
    net::{addr::EndpointAddr, route::Pathway},
    packet::{GetType, OneRttHeader, Package, PacketBuffer},
    role::Role,
    time::heartbeat::ArcHeartbeat,
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::Transport as _;

struct Counter(AtomicUsize);
impl std::task::Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn activation_changes_wake_the_sender_without_retiring_the_path() {
    let path = support::path::path(
        qbase::cid::ArcRemoteCids::client(Default::default(), qtransport::ArcReliableFrames::with_capacity(0)),
        Pathway::new("127.0.0.1:4400".parse::<EndpointAddr>().unwrap(), "127.0.0.1:5500".parse().unwrap()),
        Arc::new(HandshakeFacts::with_role(Role::Client)),
        Default::default(),
        ArcIndexDeque::default(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        Default::default(),
    );
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    path.send_waker.register(&Waker::from(counter.clone()));
    assert!(path.is_active());
    path.disable();
    path.disable();
    assert!(!path.is_active());
    assert!(!path.validation.is_cancelled());
    assert!(path.dcid.poll_borrow(&mut Context::from_waker(Waker::noop())).is_ready());
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    path.enable();
    path.enable();
    assert!(path.is_active());
    assert_eq!(counter.0.load(Ordering::Relaxed), 2);
    path.close();
    assert!(!path.is_active());
    assert!(path.validation.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn handshake_events_stop_early_epoch_pto() {
    use qbase::Epoch;
    let handshake = Arc::new(HandshakeFacts::with_role(Role::Client));
    let path = support::path::path(
        qbase::cid::ArcRemoteCids::client(Default::default(), qtransport::ArcReliableFrames::with_capacity(0)),
        Pathway::new(EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()), EndpointAddr::direct("127.0.0.1:5500".parse().unwrap())),
        handshake.clone(),
        Default::default(),
        ArcIndexDeque::from(IndexDeque::with_capacity(3)),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        Default::default(),
    );
    path.validation.exempt().unwrap();
    handshake.install_handshake_key();
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        path.cc.on_pkt_sent(epoch, 0, true, 1200, true, None);
    }
    handshake.on_handshake_sent();
    handshake.on_handshake_done();
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

    let path = support::path::path(
        qbase::cid::ArcRemoteCids::client(Default::default(), qtransport::ArcReliableFrames::with_capacity(0)),
        Pathway::new(EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()), EndpointAddr::direct("127.0.0.1:5500".parse().unwrap())),
        Arc::new(HandshakeFacts::with_role(Role::Client)),
        Default::default(),
        ArcIndexDeque::default(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        Default::default(),
    );
    path.validation.exempt().unwrap();
    let step = path.cc.get_pto(Epoch::Initial) / 10;
    for _ in 0..11 {
        tokio::time::advance(step).await;
        assert!(matches!(path.validation.poll_credit(&mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(None))));
        path.cc.do_tick().unwrap();
    }
    assert!(path.cc.need_send_ack_eliciting(Epoch::Initial) > 0);
}

#[tokio::test(start_paused = true)]
async fn cancelling_shared_validation_retires_the_path() {
    let path = support::path::path(
        qbase::cid::ArcRemoteCids::client(Default::default(), qtransport::ArcReliableFrames::with_capacity(0)),
        Pathway::new(EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()), EndpointAddr::direct("127.0.0.1:5500".parse().unwrap())),
        Arc::new(HandshakeFacts::with_role(Role::Server)),
        Default::default(),
        ArcIndexDeque::default(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        Default::default(),
    );
    assert!(path.validation.credit().is_ok());
    path.validation.cancel();
    assert!(matches!(path.validation.poll_credit(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(qbase::Cancelled))));
    path.close();
    path.close();
    assert!(path.validation.enter_validated().is_err());
    assert!(matches!(path.validation.poll_credit(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(qbase::Cancelled))));
}

#[tokio::test(start_paused = true)]
async fn validation_registers_only_when_both_sources_are_empty() {
    for queued in [false, true] {
        for quota in [0, 128] {
            let path = support::path::path(
                qbase::cid::ArcRemoteCids::client(Default::default(), qtransport::ArcReliableFrames::with_capacity(0)),
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:5500".parse().unwrap()),
                ),
                Arc::new(HandshakeFacts::with_role(Role::Server)),
                Default::default(),
                ArcIndexDeque::default(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                Default::default(),
            );
            if queued {
                path.validation.recv_frame(PathChallengeFrame::from_slice(&[1; 8])).unwrap();
                path.validation.challenge(PathChallengeFrame::from_slice(&[2; 8])).unwrap();
            }
            let counter = Arc::new(Counter(AtomicUsize::new(0)));
            let waker = Waker::from(counter.clone());
            let mut bytes = bytes::BytesMut::new();
            let mut frames = Vec::new();
            let limits_quota = quota;
            let limits_length = 128;
            let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
            let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
            let result = path
                .validation
                .clone()
                .poll_dump(&mut Context::from_waker(&waker), &mut PacketBuffer::new(&mut writer_0, limits_quota, &mut frames, ty, 0, 0));
            assert_eq!(result.is_pending(), !queued);
            if queued {
                assert_eq!(result, Poll::Ready(Ok(if quota == 0 { 0 } else { 2 })));
            }
            path.validation.recv_frame(PathChallengeFrame::from_slice(&[3; 8])).unwrap();
            assert_eq!(counter.0.load(Ordering::Relaxed), usize::from(!queued));
        }
    }
}

#[tokio::test]
async fn every_duplicate_challenge_is_packaged_as_a_response() {
    let path = support::path::path(
        qbase::cid::ArcRemoteCids::client(Default::default(), qtransport::ArcReliableFrames::with_capacity(0)),
        Pathway::new(EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()), EndpointAddr::direct("127.0.0.1:5500".parse().unwrap())),
        Arc::new(HandshakeFacts::with_role(Role::Server)),
        Default::default(),
        ArcIndexDeque::default(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        Default::default(),
    );
    for _ in 0..10 {
        path.validation.recv_frame(PathChallengeFrame::from_slice(&[1; 8])).unwrap();
    }
    let mut bytes = bytes::BytesMut::new();
    let mut frames = Vec::new();
    let limits_quota = 128;
    let limits_length = 128;
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut writer_1 = bytes::BufMut::limit(&mut bytes, limits_length);
    let result = path
        .validation
        .clone()
        .poll_dump(&mut Context::from_waker(Waker::noop()), &mut PacketBuffer::new(&mut writer_1, limits_quota, &mut frames, ty, 0, 0));
    assert_eq!(result, Poll::Ready(Ok(10)));
}
