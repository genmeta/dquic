use std::{collections::BTreeSet, time::Duration};

use qbase::{
    error::Error,
    frame::{AckFrame, GuaranteedFrame, GuaranteedFrame as Frame, ReliableFrame},
    packet::{PacketNumber, assemble::Metadata},
};
use qrecovery::journal::ArcSentJournal;
use tokio::time::Instant;

fn ack(pn: u64) -> AckFrame {
    AckFrame::new(
        pn.try_into().unwrap(),
        0u32.into(),
        0u32.into(),
        vec![],
        None,
    )
}

fn frame(value: u32) -> GuaranteedFrame {
    Frame::Reliable(ReliableFrame::MaxData(qbase::frame::MaxDataFrame::new(
        value.into(),
    )))
}

fn record_pending(
    records: &ArcSentJournal,
    generation: impl Into<Option<u64>>,
    frames: &mut Vec<GuaranteedFrame>,
) -> Result<(u64, PacketNumber), Error> {
    let number = records.next_pn()?;
    records.on_sealed(
        number.0,
        generation.into(),
        0,
        Metadata::new(qbase::packet::Type::Short(
            qbase::packet::r#type::short::OneRtt(0.into()),
        )),
        frames.drain(..),
    );
    Ok(number)
}

fn acknowledged_values(records: &ArcSentJournal, pn: u64) -> Vec<u64> {
    let mut values = Vec::new();
    records
        .on_acked(&ack(pn), |frame| match frame {
            Frame::Reliable(ReliableFrame::MaxData(frame)) => values.push(frame.max_data()),
            _ => panic!("unexpected recovery frame"),
        })
        .unwrap();
    values
}

#[test]
fn ack_returns_highest_generation_or_none() {
    for (generations, expected) in [
        (vec![None, None], None),
        (vec![Some(0)], Some(0)),
        (vec![Some(1), Some(7), Some(2), None, Some(7)], Some(7)),
    ] {
        let records = ArcSentJournal::default();
        for generation in &generations {
            record_pending(&records, *generation, &mut vec![frame(42)]).unwrap();
        }
        let largest = (generations.len() as u64 - 1).try_into().unwrap();
        let ack = AckFrame::new(largest, 0u32.into(), largest, vec![], None);
        let mut confirmed = 0;
        assert_eq!(
            records.on_acked(&ack, |_| confirmed += 1).unwrap(),
            expected
        );
        assert_eq!(confirmed, generations.len());
        assert_eq!(
            records
                .on_acked(&ack, |_| panic!("duplicate ACK notification"))
                .unwrap(),
            None
        );
    }
}

#[test]
fn pending_reliable_records_reuse_scratch_allocation() {
    let records = ArcSentJournal::default();
    let mut scratch = vec![frame(10)];
    let allocation = scratch.as_ptr();
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0);
    assert!(scratch.is_empty());
    assert_eq!(scratch.as_ptr(), allocation);
    records.on_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
    records.resend(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
    );
    assert_eq!(acknowledged_values(&records, 0), [10]);
}

#[test]
fn regression_invalid_ack_ranges_return_an_error_without_underflow() {
    let records = ArcSentJournal::default();
    let malformed = AckFrame::new(0u32.into(), 0u32.into(), 1u32.into(), vec![], None);
    assert!(records.on_acked(&malformed, |_| {}).is_err());
}

#[tokio::test]
async fn shared_handles_distinguish_cancelled_pending_and_sent_packets() {
    let first = ArcSentJournal::default();
    let second = first.clone();
    let mut frames = vec![frame(10)];
    let cancelled = record_pending(&first, 0, &mut frames).unwrap().0;
    let sent = record_pending(&second, 0, &mut frames).unwrap().0;
    let pending = record_pending(&first, 0, &mut frames).unwrap().0;
    assert_eq!((cancelled, sent, pending), (0, 1, 2));
    second.cancel(cancelled, |frame| frames.push(frame));
    assert!(
        matches!(frames.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
    );
    frames.clear();
    first.on_sent(sent, false, Duration::ZERO, Duration::ZERO);
    assert!(second.on_acked(&ack(sent), |_| {}).unwrap().is_none());
    assert!(second.on_acked(&ack(cancelled), |_| {}).is_err());
    assert_eq!(first.on_acked(&ack(pending), |_| {}).unwrap(), Some(0));
    second.on_sent(pending, false, Duration::ZERO, Duration::ZERO);
    assert!(first.on_acked(&ack(pending), |_| {}).unwrap().is_none());
    let spanning_gap = AckFrame::new(2u32.into(), 0u32.into(), 2u32.into(), vec![], None);
    assert!(first.on_acked(&spanning_gap, |_| {}).is_err());
    assert!((0..3).all(|pn| first.lock_guard().packet(pn).is_none()));
}

#[tokio::test(start_paused = true)]
async fn pending_ack_releases_frames_before_late_submission() {
    let records = ArcSentJournal::default();
    let pn = record_pending(&records, 7, &mut vec![frame(42)]).unwrap().0;
    let mut acknowledged = Vec::new();
    assert_eq!(
        records
            .on_acked(&ack(pn), |frame| acknowledged.push(frame.clone()))
            .unwrap(),
        Some(7)
    );
    assert_eq!(acknowledged, [frame(42)]);
    {
        let journal = records.lock_guard();
        assert!(
            journal.packet(pn).is_some(),
            "keep metadata for the socket result"
        );
        assert_eq!(journal.frames(pn).count(), 0);
    }
    records.on_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
    records.on_tick(Instant::now() + Duration::from_secs(4), |_| {
        panic!("acked frame retransmitted")
    });
    assert!(
        records
            .on_acked(&ack(pn), |_| panic!("duplicate ACK notification"))
            .unwrap()
            .is_none()
    );
    assert!(records.lock_guard().packet(pn).is_none());
}

#[test]
fn recovery_keeps_data_headers_and_moves_tokens_without_copying() {
    use qbase::frame::{CryptoFrame, NewTokenFrame, StreamFrame};
    let records = ArcSentJournal::default();
    let crypto = CryptoFrame::new(10u32.into(), 20u32.into());
    let stream = StreamFrame::new(
        qbase::sid::StreamId::new(qbase::role::Role::Client, qbase::sid::Dir::Uni, 0),
        30,
        40,
    );
    let token = NewTokenFrame::new(vec![5; 20]);
    let allocation = token.token().as_ptr();
    // Keep an earlier packet live so cancellation cannot drain the queue prefix.
    assert_eq!(
        record_pending(&records, 0, &mut vec![frame(0)]).unwrap().0,
        0
    );
    let mut scratch = vec![
        Frame::Crypto(crypto),
        Frame::Stream(stream),
        Frame::Reliable(ReliableFrame::NewToken(token)),
    ];
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 1);
    assert!(scratch.is_empty());
    records.cancel(1, |frame| scratch.push(frame));
    assert!(matches!(scratch.as_slice(),
        [Frame::Crypto(c), Frame::Stream(s), Frame::Reliable(ReliableFrame::NewToken(t))]
        if *c == crypto && *s == stream && t.token().as_ptr() == allocation));
    scratch.clear();
    records.cancel(0, |frame| scratch.push(frame));
    assert_eq!(scratch, [frame(0)]);
    assert!((0..2).all(|pn| records.lock_guard().packet(pn).is_none()));
}

#[tokio::test]
async fn reverse_submission_and_ack_order_preserve_each_packets_frames() {
    let records = ArcSentJournal::default();
    let mut scratch = Vec::with_capacity(4);
    let allocation = scratch.as_ptr();
    scratch.extend([frame(110), frame(111)]);
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0);
    assert!(scratch.is_empty());
    assert_eq!(scratch.as_ptr(), allocation);
    scratch.push(frame(100));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 1);
    {
        let journal = records.lock_guard();
        assert_eq!(
            journal.frames(0).cloned().collect::<Vec<_>>(),
            [frame(110), frame(111)]
        );
        assert_eq!(journal.frames(1).cloned().collect::<Vec<_>>(), [frame(100)]);
    }
    records.on_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
    records.on_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
    assert_eq!(acknowledged_values(&records, 1), [100]);
    assert!(records.lock_guard().packet(1).is_none());
    assert_eq!(
        records.lock_guard().frames(0).cloned().collect::<Vec<_>>(),
        [frame(110), frame(111)]
    );
    assert_eq!(acknowledged_values(&records, 0), [110, 111]);
    assert!((0..2).all(|pn| records.lock_guard().packet(pn).is_none()));
    assert!(acknowledged_values(&records, 0).is_empty());
    scratch.push(frame(120));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 2);
    records.cancel(2, |frame| scratch.push(frame));
    assert_eq!(scratch.as_ptr(), allocation);
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 120)
    );
    assert!(records.lock_guard().packet(2).is_none());
    assert!(records.on_acked(&ack(2), |_| {}).is_err());
}

#[test]
fn batch_ack_preserves_pending_frames_after_prefix_reclamation() {
    let records = ArcSentJournal::default();
    let mut scratch = Vec::new();
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0); // Empty ranges do not pin frames.
    scratch.push(frame(10));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 1);
    scratch.extend([frame(20), frame(21)]);
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 2);
    scratch.push(frame(30));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 3);
    records.on_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
    records.on_sent(2, true, Duration::from_secs(1), Duration::from_secs(3));
    let ack = AckFrame::new(2u32.into(), 0u32.into(), 1u32.into(), vec![], None);
    let mut values = Vec::new();
    records
        .on_acked(&ack, |frame| match frame {
            GuaranteedFrame::Reliable(qbase::frame::ReliableFrame::MaxData(frame)) => {
                values.push(frame.max_data());
            }
            _ => panic!("unexpected recovery frame"),
        })
        .unwrap();
    assert_eq!(values, [10, 20, 21]);
    {
        let journal = records.lock_guard();
        assert!(journal.packet(0).is_some());
        assert_eq!(journal.frames(0).count(), 0);
        assert!((1..3).all(|pn| journal.packet(pn).is_none()));
        assert_eq!(journal.frames(3).cloned().collect::<Vec<_>>(), [frame(30)]);
    }
    records
        .on_acked(&ack, |_| panic!("duplicate ACK delivered a frame"))
        .unwrap();
    records.cancel(3, |frame| scratch.push(frame));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(frame))] if frame.max_data() == 30)
    );
    assert!(records.lock_guard().packet(3).is_none());
    records.cancel(0, |_| panic!("empty packet returned a frame"));
}

#[test]
fn concurrent_batches_keep_each_packets_frames_together() {
    let records = &ArcSentJournal::default();
    std::thread::scope(|scope| {
        for worker in 0..4 {
            scope.spawn(move || {
                let mut scratch = Vec::new();
                for i in 0..100 {
                    let value = worker * 100 + i;
                    scratch.extend([frame(value), frame(value + 1000)]);
                    record_pending(records, 0, &mut scratch).unwrap();
                    assert!(scratch.is_empty());
                }
            });
        }
    });
    let mut values = BTreeSet::new();
    let mut scratch = Vec::new();
    for pn in (0..400).rev() {
        records.cancel(pn, |frame| scratch.push(frame));
        let [
            Frame::Reliable(ReliableFrame::MaxData(a)),
            Frame::Reliable(ReliableFrame::MaxData(b)),
        ] = scratch.as_slice()
        else {
            panic!()
        };
        assert_eq!(b.max_data(), a.max_data() + 1000);
        assert!(values.insert(a.max_data()));
        scratch.clear();
    }
    assert!((0..400).all(|pn| records.lock_guard().packet(pn).is_none()));
}

#[tokio::test(start_paused = true)]
async fn terminal_slots_are_reclaimed_only_when_the_live_prefix_finishes() {
    let records = ArcSentJournal::default();
    // Fill the frame budget, so prefix reclamation is observable through capacity.
    const FRAME_CAPACITY: usize = 32768;
    let mut scratch = Vec::new();
    let now = Instant::now();
    for pn in 0..5 {
        scratch.resize(
            if pn == 4 { FRAME_CAPACITY - 4 } else { 1 },
            frame(pn as u32),
        );
        assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, pn);
    }
    assert!(!records.has_capacity());
    records.on_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
    records.on_sent(3, true, Duration::from_secs(1), Duration::from_secs(3));
    assert_eq!(acknowledged_values(&records, 1), [1]);
    records.cancel(2, |frame| scratch.push(frame));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 2)
    );
    scratch.clear();
    records.resend(&mut [3].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 3)
    );
    scratch.clear();
    assert_eq!(
        records.lock_guard().frames(3).cloned().collect::<Vec<_>>(),
        [frame(3)]
    );
    records.on_tick(now + Duration::from_secs(3), |frame| {
        scratch.push(frame.clone())
    });
    assert!(scratch.is_empty());
    {
        let journal = records.lock_guard();
        assert!((1..4).all(|pn| journal.packet(pn).is_none()));
        assert_eq!(journal.frames(0).cloned().collect::<Vec<_>>(), [frame(0)]);
        assert_eq!(journal.frames(4).count(), FRAME_CAPACITY - 4);
    }
    assert!(
        !records.has_capacity(),
        "the live prefix still pins released slots"
    );
    records.cancel(0, |frame| scratch.push(frame));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 0)
    );
    scratch.clear();
    assert!(records.has_capacity());
    scratch.resize(3, frame(5));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 5);
    assert!(records.has_capacity(), "one reclaimed slot remains");
    scratch.push(frame(6));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 6);
    assert!(
        !records.has_capacity(),
        "all four released slots can be reused"
    );
    records.cancel(4, |frame| scratch.push(frame));
    assert_eq!(scratch, vec![frame(4); FRAME_CAPACITY - 4]);
    assert!(records.has_capacity());
    scratch.clear();
    records.cancel(5, |frame| scratch.push(frame));
    assert_eq!(scratch, vec![frame(5); 3]);
    scratch.clear();
    records.cancel(6, |frame| scratch.push(frame));
    assert_eq!(scratch, [frame(6)]);
    assert!((0..7).all(|pn| records.lock_guard().packet(pn).is_none()));

    // A complete new frame budget fits after the final packet is released.
    scratch.clear();
    scratch.resize(FRAME_CAPACITY - 1, frame(7));
    let pn = record_pending(&records, 0, &mut scratch).unwrap().0;
    assert!(records.has_capacity());
    scratch.push(frame(8));
    let last = record_pending(&records, 0, &mut scratch).unwrap().0;
    assert!(!records.has_capacity());
    records.cancel(pn, drop);
    records.cancel(last, drop);
    assert!(records.has_capacity());
}

#[tokio::test(start_paused = true)]
async fn loss_retains_frames_for_late_ack_and_expiration_removes_records() {
    let records = ArcSentJournal::default();
    let mut scratch = vec![frame(10)];
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0);
    records.on_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
    records.resend(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
    );
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 1);
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(scratch.is_empty());
    records.on_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
    // The new PN can itself be lost; the retained original must not requeue again.
    records.resend(&mut [0, 1].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
    );
    scratch.clear();
    assert_eq!(acknowledged_values(&records, 0), [10]);
    assert_eq!(acknowledged_values(&records, 1), [10]);
    assert!((0..2).all(|pn| records.lock_guard().packet(pn).is_none()));

    scratch.push(frame(20));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 2);
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(scratch.is_empty(), "unsent packets have no loss feedback");
    records.on_sent(2, true, Duration::from_secs(1), Duration::from_secs(3));
    records.resend(&mut [2].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    scratch.clear();
    tokio::time::advance(Duration::from_secs(4)).await;
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(scratch.is_empty());
    assert!(records.lock_guard().packet(2).is_none());
    assert!(acknowledged_values(&records, 2).is_empty());
}

#[tokio::test(start_paused = true)]
async fn repeated_loss_never_requeues_retained_packets_or_extends_retention() {
    let records = ArcSentJournal::default();
    let mut scratch = vec![frame(10)];
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0);
    records.on_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
    scratch.push(frame(20));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 1);
    records.on_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
    records.resend(&mut [0, 1, 0, 1].into_iter(), |frame| {
        scratch.push(frame.clone())
    });
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(a)), Frame::Reliable(ReliableFrame::MaxData(b))]
        if a.max_data() == 10 && b.max_data() == 20)
    );
    scratch.clear();

    tokio::time::advance(Duration::from_secs(2)).await;
    records.resend(&mut [0, 1].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(
        scratch.is_empty(),
        "retained packets must not be requeued twice"
    );
    assert_eq!(acknowledged_values(&records, 0), [10]);
    assert!(acknowledged_values(&records, 0).is_empty());
    assert!(records.lock_guard().packet(1).is_some());

    tokio::time::advance(Duration::from_secs(1)).await;
    records.resend(&mut [1].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(
        scratch.is_empty(),
        "expiration must not requeue the old packet"
    );
    assert!(
        (0..2).all(|pn| records.lock_guard().packet(pn).is_none()),
        "repeat loss must not extend retention"
    );
}

#[test]
fn late_ack_after_immediate_loss_notification_reclaims_original() {
    let records = ArcSentJournal::default();
    let mut scratch = vec![frame(10)];
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0);
    records.on_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
    records.resend(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
    );
    scratch.clear();
    assert_eq!(acknowledged_values(&records, 0), [10]);
    records.resend(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(scratch.is_empty());
    assert!(acknowledged_values(&records, 0).is_empty());
    assert!(records.lock_guard().packet(0).is_none());
}

#[tokio::test(start_paused = true)]
async fn retention_starts_at_submission_and_is_not_reset_by_loss() {
    let records = ArcSentJournal::default();
    let mut scratch = vec![frame(10)];
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0);
    // Time spent waiting for the socket is not part of the sent packet's retention.
    tokio::time::advance(Duration::from_secs(5)).await;
    records.on_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
    tokio::time::advance(Duration::from_secs(1)).await;
    records.resend(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));

    tokio::time::advance(Duration::from_secs(1)).await;
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
    );
    assert!(records.lock_guard().packet(0).is_some());
    scratch.clear();
    tokio::time::advance(Duration::from_secs(1)).await;
    records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
    assert!(scratch.is_empty());
    assert!(records.lock_guard().packet(0).is_none());
}

#[tokio::test(start_paused = true)]
async fn loss_notification_delivers_data_even_after_retention_deadline() {
    for delayed_loss in [false, true] {
        let records = ArcSentJournal::default();
        let mut scratch = vec![frame(10)];
        assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0);
        records.on_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
        if delayed_loss {
            tokio::time::advance(Duration::from_secs(4)).await;
        }
        records.resend(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
        if !delayed_loss {
            tokio::time::advance(Duration::from_secs(4)).await;
        }
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
        );
        scratch.clear();
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(scratch.is_empty());
        assert!(records.lock_guard().packet(0).is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn timer_and_loss_feedback_schedule_each_packet_once() {
    let records = ArcSentJournal::default();
    let mut scratch = Vec::new();
    let now = Instant::now();
    for pn in 0..3 {
        scratch.push(frame(pn as u32));
        assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, pn);
        records.on_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
    }
    scratch.push(frame(3));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 3);
    assert_eq!(acknowledged_values(&records, 1), [1]);
    records.resend(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(now + Duration::from_millis(999), |frame| {
        scratch.push(frame.clone())
    });
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 0)
    );
    scratch.clear();

    records.on_tick(now + Duration::from_secs(1), |frame| {
        scratch.push(frame.clone())
    });
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 2)
    );
    scratch.clear();
    records.resend(&mut [0, 2].into_iter(), |frame| scratch.push(frame.clone()));
    records.on_tick(now + Duration::from_secs(1), |frame| {
        scratch.push(frame.clone())
    });
    assert!(scratch.is_empty());
    assert_eq!(acknowledged_values(&records, 0), [0]);
    records.on_tick(now + Duration::from_secs(3), |frame| {
        scratch.push(frame.clone())
    });
    assert!(scratch.is_empty());
    assert!(acknowledged_values(&records, 2).is_empty());
    // A never-submitted packet has no recovery deadline.
    assert!(records.lock_guard().packet(3).is_some());
    records.cancel(3, |frame| scratch.push(frame));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 3)
    );
    scratch.clear();

    scratch.push(frame(4));
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 4);
    records.on_sent(4, true, Duration::from_secs(1), Duration::from_secs(3));
    // Even a late tick must deliver the data before retiring its original record.
    records.on_tick(now + Duration::from_secs(4), |frame| {
        scratch.push(frame.clone())
    });
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 4)
    );
    assert!((0..5).all(|pn| records.lock_guard().packet(pn).is_none()));
}

#[tokio::test(start_paused = true)]
async fn deadlines_order_by_time_and_keep_packets_with_equal_times() {
    let records = ArcSentJournal::default();
    let now = Instant::now();
    let mut scratch = Vec::new();
    for (pn, retransmit, expire) in [(0, 3, 8), (1, 1, 5), (2, 1, 5), (3, 2, 6)] {
        scratch.push(frame(pn as u32));
        assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, pn);
        records.on_sent(
            pn,
            true,
            Duration::from_secs(retransmit),
            Duration::from_secs(expire),
        );
    }
    records.on_tick(now + Duration::from_millis(999), |frame| {
        scratch.push(frame.clone())
    });
    assert!(scratch.is_empty());
    records.on_tick(now + Duration::from_secs(1), |frame| {
        scratch.push(frame.clone())
    });
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(a)), Frame::Reliable(ReliableFrame::MaxData(b))]
        if a.max_data() == 1 && b.max_data() == 2)
    );
    scratch.clear();
    assert_eq!(acknowledged_values(&records, 1), [1]);
    // ACK removes a future retransmission; CC loss notifies immediately.
    assert_eq!(acknowledged_values(&records, 0), [0]);
    records.resend(&mut [3, 3].into_iter(), |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 3)
    );
    scratch.clear();
    records.on_tick(now + Duration::from_millis(4999), |_| {
        panic!("ACKed or already retransmitted frame delivered again")
    });
    assert!((0..2).all(|pn| records.lock_guard().packet(pn).is_none()));
    assert!(records.lock_guard().packet(2).is_some());
    assert!(records.lock_guard().packet(3).is_some());
    assert_eq!(acknowledged_values(&records, 3), [3]);
    records.on_tick(now + Duration::from_secs(5), |frame| {
        scratch.push(frame.clone())
    });
    assert!(scratch.is_empty());
    assert!((0..4).all(|pn| records.lock_guard().packet(pn).is_none()));
    records.on_tick(now + Duration::from_secs(8), |_| {
        panic!("retired or ACKed frame delivered again")
    });
}

#[tokio::test(start_paused = true)]
async fn equal_retransmission_and_retirement_deadlines_deliver_data_once() {
    let records = ArcSentJournal::default();
    let now = Instant::now();
    let mut scratch = vec![frame(10)];
    assert_eq!(record_pending(&records, 0, &mut scratch).unwrap().0, 0);
    records.on_sent(0, true, Duration::ZERO, Duration::ZERO);
    records.on_tick(now, |frame| scratch.push(frame.clone()));
    assert!(
        matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
    );
    scratch.clear();
    records.on_tick(now, |frame| scratch.push(frame.clone()));
    assert!(scratch.is_empty());
    assert!(records.lock_guard().packet(0).is_none());
}

#[test]
fn skipped_number_history_expires_and_allows_reordered_submission() {
    // The journal retains the latest 256 cancelled packet numbers.
    const SKIPPED_HISTORY: u64 = 256;
    let journal = ArcSentJournal::default();
    let mut frames = Vec::new();
    for _ in 0..3 {
        record_pending(&journal, 0, &mut frames).unwrap();
    }
    journal.on_sent(2, false, Duration::ZERO, Duration::ZERO);
    journal
        .on_acked(&ack(2), |_| panic!("empty packet acknowledged a frame"))
        .unwrap();
    journal.on_acked(&ack(0), |_| {}).unwrap();
    journal.on_sent(0, false, Duration::ZERO, Duration::ZERO);
    journal.on_acked(&ack(0), |_| {}).unwrap();
    journal.cancel(1, |frame| frames.push(frame));
    assert!(journal.on_acked(&ack(1), |_| {}).is_err());
    for _ in 0..SKIPPED_HISTORY {
        let (pn, _) = record_pending(&journal, 0, &mut frames).unwrap();
        journal.cancel(pn, |frame| frames.push(frame));
    }
    assert!((0..3 + SKIPPED_HISTORY).all(|pn| journal.lock_guard().packet(pn).is_none()));
    // Old history is deliberately forgotten; retained skipped PNs are still rejected.
    journal.on_acked(&ack(1), |_| {}).unwrap();
    for pn in 3..3 + SKIPPED_HISTORY {
        assert!(journal.on_acked(&ack(pn), |_| {}).is_err());
    }
    assert!(journal.on_acked(&ack(3 + SKIPPED_HISTORY), |_| {}).is_err());
}

#[test]
fn pn_encoding_tracks_valid_ack_even_after_recovery_records_are_removed() {
    let records = ArcSentJournal::default();
    // Advance through real allocations while retiring each record immediately.
    for expected in 0..1 << 15 {
        let (pn, encoded) = records.next_pn().unwrap();
        assert_eq!(pn, expected);
        assert_eq!(encoded, PacketNumber::U16(pn as u16));
        records.on_sent(pn, false, Duration::ZERO, Duration::ZERO);
        assert!(records.lock_guard().packet(pn).is_none());
    }
    let (pn, encoded) = records.next_pn().unwrap();
    assert_eq!(pn, 1 << 15);
    assert_eq!(encoded, PacketNumber::U24(pn as u32));
    records.on_sent(pn, false, Duration::ZERO, Duration::ZERO);
    assert!(records.lock_guard().packet(pn).is_none());

    assert!(records.on_acked(&ack(pn + 1), |_| {}).is_err());
    let (next, encoded) = records.next_pn().unwrap();
    assert_eq!(next, pn + 1);
    assert_eq!(
        encoded,
        PacketNumber::U24(next as u32),
        "invalid ACK changed encoding"
    );
    records.on_sent(next, false, Duration::ZERO, Duration::ZERO);

    // Valid, older and duplicate ACKs must each preserve the reduced encoding gap.
    for (index, acked) in [pn, 0, pn].into_iter().enumerate() {
        records
            .on_acked(&ack(acked), |_| {
                panic!("retired packet acknowledged a frame")
            })
            .unwrap();
        let (next, encoded) = records.next_pn().unwrap();
        let expected = pn + 2 + index as u64;
        assert_eq!(
            (next, encoded),
            (expected, PacketNumber::U16(expected as u16))
        );
        records.on_sent(next, false, Duration::ZERO, Duration::ZERO);
    }
}

#[test]
fn concurrent_packet_allocation_is_unique() {
    let records = ArcSentJournal::default();
    let numbers = std::thread::scope(|scope| {
        (0..4)
            .map(|_| {
                let records = records.clone();
                scope.spawn(move || {
                    (0..1000)
                        .map(|_| records.next_pn().unwrap().0)
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    let unique = numbers
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), 4000);
    assert_eq!(records.next_pn().unwrap().0, 4000);
}
