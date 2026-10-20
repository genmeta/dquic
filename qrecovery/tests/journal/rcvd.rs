use std::{
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    frame::{AckFrame, Frame, FrameReader},
    packet::{
        Constraints, GetType, InvalidPacketNumber, OneRttHeader, Package, PacketBuffer,
        PacketNumber,
    },
    varint::VarInt,
};
use qrecovery::journal::ArcRcvdJournal;
use tokio::time::Instant;

const MAX_TRACKED_ACK_RANGES: usize = 256;

fn ack_package(records: &ArcRcvdJournal, pn: u64) -> AckFrame {
    let mut package = records.ack_package(Some((pn, Instant::now())));
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 1200,
        credit: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    assert!(matches!(
        package.poll_dump(
            &mut Context::from_waker(Waker::noop()),
            &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0)
        ),
        Poll::Ready(Ok(1))
    ));
    let mut frames = FrameReader::new(bytes.freeze(), ty);
    let Frame::Ack(ack) = frames.next().unwrap().unwrap().0 else {
        panic!("expected ACK")
    };
    assert!(frames.next().is_none());
    ack
}

#[test]
fn contiguous_packets_merge_into_one_range() {
    let records = ArcRcvdJournal::with_capacity(16, None);
    for pn in [10, 12, 11] {
        records.on_rcvd_pn(pn, true, Duration::ZERO);
    }
    let ack = records
        .gen_ack_frame_util(12, Instant::now(), 1200)
        .unwrap();
    let mut ranges = ack.iter();
    assert_eq!(ranges.next(), Some(10..=12));
    assert_eq!(ranges.next(), None);
}

#[test]
fn large_packet_number_gap_does_not_allocate_empty_states() {
    let records = ArcRcvdJournal::with_capacity(16, None);
    records.on_rcvd_pn(10, true, Duration::ZERO);
    records.on_rcvd_pn(10_000_000, true, Duration::ZERO);
    let ack = records
        .gen_ack_frame_util(10_000_000, Instant::now(), 1200)
        .unwrap();
    assert_eq!(
        ack.iter().collect::<Vec<_>>(),
        [10_000_000..=10_000_000, 10..=10]
    );
}

#[test]
fn range_bound_evicts_oldest_and_retires_it() {
    let records = ArcRcvdJournal::with_capacity(MAX_TRACKED_ACK_RANGES, None);
    for pn in (0..=MAX_TRACKED_ACK_RANGES as u64 * 2).step_by(2) {
        records.on_rcvd_pn(pn, true, Duration::ZERO);
    }
    let ack = records
        .gen_ack_frame_util(512, Instant::now(), 1200)
        .unwrap();
    assert_eq!(
        ack.iter().collect::<Vec<_>>(),
        (1..=256u32)
            .rev()
            .map(|n| u64::from(n) * 2)
            .map(|pn| pn..=pn)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        records.decode_pn(PacketNumber::encode(0, 0)),
        Err(InvalidPacketNumber::TooOld)
    );
}

#[test]
fn ack_ranges_preserve_holes_and_encode_exactly() {
    let records = ArcRcvdJournal::with_capacity(16, None);
    for pn in [100, 101, 104, 105, 110] {
        records.on_rcvd_pn(pn, true, Duration::ZERO);
    }
    let ack = records
        .gen_ack_frame_util(110, Instant::now(), 1200)
        .unwrap();
    assert_eq!(ack.largest(), 110);
    assert_eq!(ack.first_range(), 0);
    assert_eq!(
        ack.ranges(),
        &vec![
            (VarInt::from_u64(3).unwrap(), VarInt::from_u64(1).unwrap()),
            (VarInt::from_u64(1).unwrap(), VarInt::from_u64(1).unwrap()),
        ]
    );
    assert!(ack.iter().any(|range| range == (100..=101)));
    assert!(ack.iter().any(|range| range == (104..=105)));
}

#[test]
fn ack_generation_is_read_only() {
    let records = ArcRcvdJournal::with_capacity(16, None);
    records.on_rcvd_pn(1, true, Duration::ZERO);
    for _ in 0..2 {
        let ack = records.gen_ack_frame_util(1, Instant::now(), 1200).unwrap();
        let mut ranges = ack.iter();
        assert_eq!(ranges.next(), Some(1..=1));
        assert_eq!(ranges.next(), None);
        assert!(records.covers_range(1..=1));
        assert!(!records.covers_range(0..=1));
        assert_eq!(records.decode_pn(PacketNumber::encode(0, 0)), Ok(0));
    }
}

#[test]
fn high_packet_number_does_not_retire_slow_path_range() {
    let records = ArcRcvdJournal::with_capacity(16, None);
    records.on_rcvd_pn(100, true, Duration::ZERO);
    records.on_rcvd_pn(10_000, true, Duration::ZERO);
    let ack = records
        .gen_ack_frame_util(10_000, Instant::now(), 1200)
        .unwrap();
    assert_eq!(ack.iter().collect::<Vec<_>>(), [10_000..=10_000, 100..=100]);
}

#[test]
fn path_local_trigger_selects_ack_largest_in_shared_journal() {
    let records = ArcRcvdJournal::with_capacity(16, None);
    records.on_rcvd_pn(100, true, Duration::ZERO);
    records.on_rcvd_pn(10_000, true, Duration::ZERO);

    let ack = ack_package(&records, 100);

    assert_eq!(ack.largest(), 100);
    assert!(ack.iter().any(|range| range.contains(&100)));
    assert!(!ack.iter().any(|range| range.contains(&10_000)));
}

#[test]
fn retired_path_trigger_can_still_generate_singleton_ack() {
    let records = ArcRcvdJournal::with_capacity(MAX_TRACKED_ACK_RANGES, None);
    records.on_rcvd_pn(0, true, Duration::ZERO);
    for pn in (2..=MAX_TRACKED_ACK_RANGES as u64 * 2).step_by(2) {
        records.on_rcvd_pn(pn, true, Duration::ZERO);
    }
    assert_eq!(
        records.decode_pn(PacketNumber::encode(0, 0)),
        Err(InvalidPacketNumber::TooOld)
    );

    let ack = ack_package(&records, 0);

    assert_eq!(ack.largest(), 0);
    assert_eq!(ack.first_range(), 0);
    assert_eq!(ack.ranges(), &[]);
}
