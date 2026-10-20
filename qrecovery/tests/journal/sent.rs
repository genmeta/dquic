use std::time::Duration;

use qbase::{
    error::Error,
    frame::{AckFrame, GuaranteedFrame, GuaranteedFrame as Frame, ReliableFrame},
    packet::{PacketNumber, assemble::Metadata},
};
use qrecovery::journal::ArcSentJournal;

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
