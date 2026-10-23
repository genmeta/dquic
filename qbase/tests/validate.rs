use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bytes::{Bytes, BytesMut};
use qbase::{
    Cancelled,
    error::Error,
    frame::{
        Frame, FrameReader, PathChallengeFrame, PathResponseFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::route::Pathway,
    packet::{
        Assemble, Constraints, GetType, LongHeaderBuilder, OneRttHeader, Package, PacketBuffer,
    },
    validate::{ArcValidation, ArcValidations, Validation},
};

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn waiter() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(count.clone());
    (count, waker)
}

fn count(wakes: &WakeCount) -> usize {
    wakes.0.load(Ordering::Relaxed)
}

fn challenge(value: u8) -> PathChallengeFrame {
    PathChallengeFrame::from_slice(&[value; 8])
}

fn credit(validation: &ArcValidation) -> Poll<Result<Option<usize>, Cancelled>> {
    validation.poll_credit(&mut Context::from_waker(Waker::noop()))
}

fn dump(
    validation: &mut impl Package<BytesMut>,
    capacity: usize,
    waker: &Waker,
) -> (Poll<Result<usize, Error>>, Vec<Frame<Bytes>>) {
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        credit: capacity,
        send_quota: capacity,
        max_size: capacity,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let (result, written) = {
        let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
        let result = validation.poll_dump(&mut Context::from_waker(waker), &mut buffer);
        (result, buffer.meta.nframes)
    };
    if let Poll::Ready(Ok(n)) = result {
        assert_eq!(n, written);
    }
    assert!(frames.is_empty());
    let decoded = FrameReader::new(bytes.freeze(), ty)
        .map(|frame| frame.unwrap().0)
        .collect::<Vec<_>>();
    assert_eq!(decoded.len(), written);
    (result, decoded)
}

fn pathway(port: u16) -> Pathway {
    Pathway::new(
        "127.0.0.1:4433".parse().unwrap(),
        format!("127.0.0.1:{port}").parse().unwrap(),
    )
}

#[test]
fn shared_validation_send_frame_wakes_sender_and_packages_both_frame_types() {
    let mut frames = ArcValidation::new();
    let sender = frames.clone();
    let (wakes, waker) = waiter();
    assert!(dump(&mut frames, 64, &waker).0.is_pending());
    sender.send_frame(std::iter::empty::<PathChallengeFrame>());
    sender.send_frame(std::iter::empty::<PathResponseFrame>());
    assert_eq!(count(&wakes), 0);

    sender.send_frame([challenge(3)]);
    assert_eq!(count(&wakes), 1);
    sender.send_frame([
        PathResponseFrame::from(challenge(1)),
        PathResponseFrame::from(challenge(2)),
        PathResponseFrame::from(challenge(1)),
    ]);
    let (result, decoded) = dump(&mut frames, 64, &waker);
    assert_eq!(result, Poll::Ready(Ok(4)));
    assert_eq!(
        decoded,
        vec![
            Frame::PathResponse(challenge(1).into()),
            Frame::PathResponse(challenge(2).into()),
            Frame::PathResponse(challenge(1).into()),
            Frame::PathChallenge(challenge(3)),
        ]
    );
    assert!(dump(&mut frames, 64, &waker).0.is_pending());
    sender.send_frame([PathResponseFrame::from(challenge(4))]);
    assert_eq!(count(&wakes), 2);

    frames.enter_validated().unwrap();
    sender.send_frame([challenge(5)]);
    sender.send_frame([PathResponseFrame::from(challenge(6))]);
    assert_eq!(
        dump(&mut frames, 64, &waker).1,
        vec![
            Frame::PathResponse(challenge(4).into()),
            Frame::PathResponse(challenge(6).into()),
        ]
    );
    assert!(dump(&mut frames, 64, &waker).0.is_pending());
    frames.cancel();
    assert_eq!(count(&wakes), 3);
    sender.send_frame([challenge(7)]);
    sender.send_frame([PathResponseFrame::from(challenge(8))]);
    assert_eq!(dump(&mut frames, 64, &waker).0, Poll::Ready(Ok(0)));
}

#[tokio::test]
async fn raw_validation_receives_both_frame_types_without_internal_locking() {
    let mut validation = Validation::new();
    validation.recv_path_challenge_frame(challenge(1));
    validation.recv_path_challenge_frame(challenge(1));
    assert_eq!(
        dump(&mut validation, 64, Waker::noop()).1,
        vec![
            Frame::PathResponse(challenge(1).into()),
            Frame::PathResponse(challenge(1).into()),
        ]
    );

    let incoming = PathResponseFrame::from(challenge(2));
    let response = validation.respond();
    validation.recv_path_response_frame(incoming);
    assert_eq!(response.await.unwrap(), Some(incoming));
    assert!(!validation.is_validated());

    validation.cancel();
    validation.recv_path_challenge_frame(challenge(3));
    validation.recv_path_response_frame(incoming);
    assert!(matches!(validation.respond().await, Err(Cancelled)));
    assert_eq!(
        dump(&mut validation, 64, Waker::noop()).0,
        Poll::Ready(Ok(0))
    );
}

#[test]
fn unvalidated_credit_counts_datagrams_and_debits_successful_sends() {
    let validation = ArcValidation::new();
    assert!(credit(&validation).is_pending());
    validation.on_received(100);
    assert!(matches!(credit(&validation), Poll::Ready(Ok(Some(300)))));
    validation.on_sent(250);
    assert!(matches!(credit(&validation), Poll::Ready(Ok(Some(50)))));
    validation.on_received(10);
    assert!(matches!(credit(&validation), Poll::Ready(Ok(Some(80)))));
    validation.on_sent(80);
    assert!(credit(&validation).is_pending());
}

#[test]
fn credit_arithmetic_does_not_wrap() {
    let validation = ArcValidation::new();
    validation.on_received(usize::MAX);
    validation.on_received(1);
    assert!(matches!(
        credit(&validation),
        Poll::Ready(Ok(Some(usize::MAX)))
    ));
    validation.on_sent(usize::MAX);
    validation.on_sent(1);
    assert!(credit(&validation).is_pending());
}

#[test]
fn credit_and_frame_waiters_are_independent() {
    let mut validation = ArcValidation::new();
    let (credit_count, credit_waker) = waiter();
    let (send_count, send_waker) = waiter();
    assert!(
        validation
            .poll_credit(&mut Context::from_waker(&credit_waker))
            .is_pending()
    );
    assert!(dump(&mut validation, 64, &send_waker).0.is_pending());

    validation.on_received(0);
    assert_eq!(count(&credit_count), 0);
    validation.on_received(10);
    assert_eq!(count(&credit_count), 1);
    assert_eq!(count(&send_count), 0);

    validation.recv_frame(challenge(1)).unwrap();
    assert_eq!(count(&credit_count), 1);
    assert_eq!(count(&send_count), 1);
}

#[test]
fn each_waiter_slot_keeps_only_its_latest_waker() {
    let mut validation = ArcValidation::new();
    let (old_credit, old_credit_waker) = waiter();
    let (new_credit, new_credit_waker) = waiter();
    let (old_send, old_send_waker) = waiter();
    let (new_send, new_send_waker) = waiter();
    assert!(
        validation
            .poll_credit(&mut Context::from_waker(&old_credit_waker))
            .is_pending()
    );
    assert!(
        validation
            .poll_credit(&mut Context::from_waker(&new_credit_waker))
            .is_pending()
    );
    assert!(dump(&mut validation, 64, &old_send_waker).0.is_pending());
    assert!(dump(&mut validation, 64, &new_send_waker).0.is_pending());
    validation.on_received(1);
    validation.challenge(challenge(1)).unwrap();
    assert_eq!(count(&old_credit), 0);
    assert_eq!(count(&new_credit), 1);
    assert_eq!(count(&old_send), 0);
    assert_eq!(count(&new_send), 1);
}

#[test]
fn exemption_grants_unlimited_credit_and_revalidation_revokes_it() {
    let mut validation = ArcValidation::new();
    validation.on_received(100);
    validation.on_sent(50);
    validation.recv_frame(challenge(7)).unwrap();
    validation.exempt().unwrap();
    assert!(validation.is_validated());
    validation.on_received(usize::MAX);
    validation.on_sent(usize::MAX);
    assert!(matches!(credit(&validation), Poll::Ready(Ok(None))));
    validation.revalidate().unwrap();
    assert!(!validation.is_validated());
    assert!(credit(&validation).is_pending());
    assert_eq!(
        dump(&mut validation, 64, Waker::noop()).1,
        vec![Frame::PathResponse(challenge(7).into())]
    );
}

#[test]
fn both_directions_share_the_frame_buffer_and_one_dump_writes_multiple_frames() {
    let mut validation = ArcValidation::new();
    validation.challenge(challenge(3)).unwrap();
    validation.recv_frame(challenge(1)).unwrap();
    validation.recv_frame(challenge(2)).unwrap();
    let (result, frames) = dump(&mut validation, 64, Waker::noop());
    assert_eq!(result, Poll::Ready(Ok(3)));
    assert_eq!(
        frames,
        vec![
            Frame::PathResponse(challenge(1).into()),
            Frame::PathResponse(challenge(2).into()),
            Frame::PathChallenge(challenge(3)),
        ]
    );
    assert!(dump(&mut validation, 64, Waker::noop()).0.is_pending());
}

#[test]
fn insufficient_space_preserves_unsent_frames_for_the_next_packet() {
    let mut validation = ArcValidation::new();
    validation.challenge(challenge(3)).unwrap();
    validation.recv_frame(challenge(1)).unwrap();
    validation.recv_frame(challenge(2)).unwrap();
    assert_eq!(
        dump(&mut validation, 8, Waker::noop()).0,
        Poll::Ready(Ok(0))
    );
    assert_eq!(
        dump(&mut validation, 9, Waker::noop()).1,
        vec![Frame::PathResponse(challenge(1).into())]
    );
    let (result, frames) = dump(&mut validation, 18, Waker::noop());
    assert_eq!(result, Poll::Ready(Ok(2)));
    assert_eq!(
        frames,
        vec![
            Frame::PathResponse(challenge(2).into()),
            Frame::PathChallenge(challenge(3))
        ]
    );
}

#[tokio::test]
async fn respond_does_not_match_challenges_or_enter_validated() {
    let validation = ArcValidation::new();
    validation.on_received(10);
    validation.challenge(challenge(1)).unwrap();
    let incoming = PathResponseFrame::from(challenge(2));
    validation.recv_frame(incoming).unwrap();
    assert_eq!(validation.respond().await.unwrap(), Some(incoming));
    assert!(!validation.is_validated());
    assert!(matches!(credit(&validation), Poll::Ready(Ok(Some(30)))));

    validation.enter_validated().unwrap();
    assert!(validation.is_validated());
    assert_eq!(validation.respond().await.unwrap(), None);
    assert!(matches!(credit(&validation), Poll::Ready(Ok(None))));
}

#[tokio::test]
async fn validated_state_preserves_the_receiver_and_its_result() {
    let mut validation = Validation::new();
    let original = validation.respond();
    let frame = PathResponseFrame::from(challenge(1));
    validation.recv_path_response_frame(frame);
    validation.trust().unwrap();
    let validated = validation.respond();

    assert_eq!(validated.clone().await.unwrap(), Some(frame));
    assert_eq!(original.clone().await.unwrap(), None);

    validation.cancel();
    assert!(matches!(original.await, Err(Cancelled)));
    assert!(matches!(validated.await, Err(Cancelled)));
    assert!(matches!(validation.respond().await, Err(Cancelled)));
}

#[tokio::test]
async fn validated_state_keeps_the_response_waiter_until_cancellation() {
    let validation = ArcValidation::new();
    let response = validation.respond();
    tokio::pin!(response);
    let (wakes, waker) = waiter();
    assert!(
        response
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );

    validation.enter_validated().unwrap();
    assert_eq!(count(&wakes), 0);
    validation.cancel();
    assert_eq!(count(&wakes), 1);
    assert!(matches!(response.await, Err(Cancelled)));
    assert!(matches!(validation.respond().await, Err(Cancelled)));
}

#[tokio::test]
async fn explicit_validation_wakes_credit_and_preserves_replies_to_the_peer() {
    let mut validation = ArcValidation::new();
    validation.challenge(challenge(1)).unwrap();
    validation.recv_frame(challenge(2)).unwrap();
    let response = validation.respond();
    tokio::pin!(response);
    assert!(futures::poll!(&mut response).is_pending());
    let (wakes, waker) = waiter();
    assert!(
        validation
            .poll_credit(&mut Context::from_waker(&waker))
            .is_pending()
    );
    validation
        .recv_frame(PathResponseFrame::from(challenge(1)))
        .unwrap();
    assert_eq!(
        response.await.unwrap(),
        Some(PathResponseFrame::from(challenge(1)))
    );
    assert_eq!(count(&wakes), 0);
    validation.enter_validated().unwrap();
    assert_eq!(count(&wakes), 1);
    assert_eq!(
        dump(&mut validation, 64, Waker::noop()).1,
        vec![Frame::PathResponse(challenge(2).into())]
    );
    validation.recv_frame(challenge(3)).unwrap();
    assert_eq!(
        dump(&mut validation, 64, Waker::noop()).1,
        vec![Frame::PathResponse(challenge(3).into())]
    );
}

#[tokio::test]
async fn retransmitting_the_challenge_preserves_the_receiver_and_credit() {
    let mut validation = ArcValidation::new();
    validation.on_received(100);
    validation.on_sent(10);
    let response = validation.respond();
    tokio::pin!(response);
    let (wakes, waker) = waiter();
    assert!(
        response
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );

    for _ in 0..4 {
        validation.challenge(challenge(1)).unwrap();
        assert_eq!(count(&wakes), 0);
        assert!(
            response
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert!(matches!(credit(&validation), Poll::Ready(Ok(Some(290)))));
        assert_eq!(
            dump(&mut validation, 64, Waker::noop()).1,
            vec![Frame::PathChallenge(challenge(1))]
        );
    }

    let incoming = PathResponseFrame::from(challenge(1));
    validation.recv_frame(incoming).unwrap();
    assert_eq!(count(&wakes), 1);
    assert_eq!(response.await.unwrap(), Some(incoming));
    assert_eq!(validation.respond().await.unwrap(), None);
}

#[tokio::test]
async fn revalidate_during_validation_preserves_the_current_attempt() {
    let mut validation = ArcValidation::new();
    validation.on_received(100);
    validation.on_sent(10);
    validation.challenge(challenge(1)).unwrap();
    let response = validation.respond();
    tokio::pin!(response);
    assert!(futures::poll!(&mut response).is_pending());

    validation.revalidate().unwrap();
    assert!(futures::poll!(&mut response).is_pending());
    assert!(matches!(credit(&validation), Poll::Ready(Ok(Some(290)))));
    assert_eq!(
        dump(&mut validation, 64, Waker::noop()).1,
        vec![Frame::PathChallenge(challenge(1))]
    );
    let incoming = PathResponseFrame::from(challenge(1));
    validation.recv_frame(incoming).unwrap();
    assert_eq!(response.await.unwrap(), Some(incoming));
    assert_eq!(validation.respond().await.unwrap(), None);
}

#[tokio::test]
async fn revalidation_from_validated_creates_a_receiver_for_the_new_attempt() {
    let validation = ArcValidation::new();
    let previous = validation.respond();
    validation.challenge(challenge(1)).unwrap();
    let first = PathResponseFrame::from(challenge(1));
    validation.recv_frame(first).unwrap();
    validation.enter_validated().unwrap();

    validation.revalidate().unwrap();
    let response = validation.respond();
    tokio::pin!(response);
    assert!(futures::poll!(&mut response).is_pending());
    validation.challenge(challenge(2)).unwrap();
    assert!(futures::poll!(&mut response).is_pending());

    let second = PathResponseFrame::from(challenge(2));
    validation.recv_frame(second).unwrap();
    assert_eq!(previous.await.unwrap(), Some(first));
    assert_eq!(response.await.unwrap(), Some(second));
    assert_eq!(validation.respond().await.unwrap(), None);
}

#[tokio::test]
async fn first_response_is_preserved_and_consumed_only_once() {
    let validation = ArcValidation::new();
    let first = PathResponseFrame::from(challenge(1));
    validation.recv_frame(first).unwrap();
    validation
        .recv_frame(PathResponseFrame::from(challenge(2)))
        .unwrap();
    assert_eq!(validation.respond().await.unwrap(), Some(first));
    assert_eq!(validation.respond().await.unwrap(), None);
}

#[tokio::test]
async fn cancellation_wakes_all_three_waiters_and_cannot_be_reversed() {
    let mut validation = ArcValidation::new();
    let (credit_count, credit_waker) = waiter();
    let (send_count, send_waker) = waiter();
    let (response_count, response_waker) = waiter();
    assert!(
        validation
            .poll_credit(&mut Context::from_waker(&credit_waker))
            .is_pending()
    );
    assert!(dump(&mut validation, 64, &send_waker).0.is_pending());
    let response = validation.respond();
    tokio::pin!(response);
    assert!(
        response
            .as_mut()
            .poll(&mut Context::from_waker(&response_waker))
            .is_pending()
    );
    validation.cancel();
    validation.cancel();
    assert_eq!(count(&credit_count), 1);
    assert_eq!(count(&send_count), 1);
    assert_eq!(count(&response_count), 1);
    assert!(matches!(response.await, Err(Cancelled)));
    assert!(matches!(credit(&validation), Poll::Ready(Err(Cancelled))));
    assert!(validation.exempt().is_err());
    assert!(validation.enter_validated().is_err());
    assert!(validation.revalidate().is_err());
    assert!(validation.challenge(challenge(1)).is_err());
    assert!(matches!(validation.respond().await, Err(Cancelled)));
    validation.recv_frame(challenge(2)).unwrap();
    validation
        .recv_frame(PathResponseFrame::from(challenge(1)))
        .unwrap();
    validation.on_received(10);
    assert_eq!(
        dump(&mut validation, 64, Waker::noop()).0,
        Poll::Ready(Ok(0))
    );
}

#[test]
fn every_received_challenge_queues_a_response_in_both_states() {
    for validated in [false, true] {
        let mut validation = ArcValidation::new();
        if validated {
            validation.enter_validated().unwrap();
        }
        for _ in 0..10 {
            validation.recv_frame(challenge(1)).unwrap();
        }
        let (result, frames) = dump(&mut validation, 128, Waker::noop());
        assert_eq!(result, Poll::Ready(Ok(10)));
        assert_eq!(frames, vec![Frame::PathResponse(challenge(1).into()); 10]);
    }
}

#[test]
fn assembly_filters_validation_out_of_long_header_packets() {
    let mut validation = ArcValidation::new();
    validation.challenge(challenge(1)).unwrap();
    validation.recv_frame(challenge(2)).unwrap();
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        credit: 64,
        send_quota: 64,
        max_size: 64,
        ..Default::default()
    };
    let ty = LongHeaderBuilder::with_cid(Default::default(), Default::default())
        .initial(vec![])
        .get_type();
    let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
    assert!(
        buffer
            .assemble(
                &mut Context::from_waker(Waker::noop()),
                &mut [&mut validation]
            )
            .is_pending()
    );
    assert_eq!(buffer.written(), 0);
    assert_eq!(
        dump(&mut validation, 64, Waker::noop()).0,
        Poll::Ready(Ok(2))
    );
}

#[tokio::test]
async fn registry_clones_dispatch_both_directions_to_the_correct_path() {
    let validations = ArcValidations::default();
    let receiver = validations.clone();
    let mut first = ArcValidation::new();
    let mut second = ArcValidation::new();
    validations.insert(pathway(1), first.clone());
    validations.insert(pathway(2), second.clone());
    receiver.recv_frame((pathway(1), challenge(1))).unwrap();
    receiver.recv_frame((pathway(2), challenge(2))).unwrap();
    receiver.recv_frame((pathway(3), challenge(3))).unwrap();
    receiver
        .recv_frame((pathway(3), PathResponseFrame::from(challenge(3))))
        .unwrap();
    assert_eq!(
        dump(&mut first, 64, Waker::noop()).1,
        vec![Frame::PathResponse(challenge(1).into())]
    );
    assert_eq!(
        dump(&mut second, 64, Waker::noop()).1,
        vec![Frame::PathResponse(challenge(2).into())]
    );
    receiver
        .recv_frame((pathway(1), PathResponseFrame::from(challenge(11))))
        .unwrap();
    receiver
        .recv_frame((pathway(2), PathResponseFrame::from(challenge(22))))
        .unwrap();
    assert_eq!(
        first.respond().await.unwrap(),
        Some(PathResponseFrame::from(challenge(11)))
    );
    assert_eq!(
        second.respond().await.unwrap(),
        Some(PathResponseFrame::from(challenge(22)))
    );
    let shared = receiver.get(&pathway(1)).unwrap();
    shared.enter_validated().unwrap();
    assert!(first.is_validated());
}

#[tokio::test]
async fn replacing_or_removing_a_registry_entry_cancels_only_that_instance() {
    let validations = ArcValidations::default();
    let first = ArcValidation::new();
    validations.insert(pathway(1), first.clone());
    validations.insert(pathway(1), first.clone());
    assert!(credit(&first).is_pending());
    let response = first.respond();
    let second = ArcValidation::new();
    validations.insert(pathway(1), second.clone());
    assert!(matches!(response.await, Err(Cancelled)));
    assert!(matches!(credit(&first), Poll::Ready(Err(Cancelled))));
    assert!(credit(&second).is_pending());
    validations.remove(&pathway(1)).unwrap();
    assert!(matches!(credit(&second), Poll::Ready(Err(Cancelled))));
    assert!(validations.get(&pathway(1)).is_none());
}
