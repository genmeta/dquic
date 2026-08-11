use std::ops::RangeInclusive;

use nom::{Parser, combinator::map};

use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// ECN flag for ACK frames
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Ecn {
    /// ECN counts are not present
    None,
    /// ECN counts are present
    Exist,
}

impl From<Ecn> for u8 {
    fn from(ecn: Ecn) -> u8 {
        match ecn {
            Ecn::None => 0,
            Ecn::Exist => 1,
        }
    }
}

impl From<u8> for Ecn {
    fn from(value: u8) -> Self {
        match value & 0x01 {
            0 => Ecn::None,
            _ => Ecn::Exist,
        }
    }
}

/// ACK Frame
///
/// ```text
/// ACK Frame {
///   Type (i) = 0x02..0x03,
///   Largest Acknowledged (i),
///   ACK Delay (i),
///   ACK Range Count (i),
///   First ACK Range (i),
///   ACK Range (..) ...,
///   [ECN Counts (..)],
/// }
/// ```
///
/// Receiver sends ACK frames (types 0x02 and 0x03) to inform the sender of packets they have
/// received and processed. The ACK frame contains one or more ACK Ranges.
///
/// See [ack frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames) of QUIC RFC 9000.
///
/// The ACK Range Count is not included in the struct because it is an intermediate variable.
/// It can be obtained from the ranges when writing and is no longer needed after generating
/// the ranges when parsing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AckFrame {
    largest: VarInt,
    delay: VarInt,
    first_range: VarInt,
    ranges: Vec<(VarInt, VarInt)>,
    ecn: Option<EcnCounts>,
}

impl super::GetFrameType for AckFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Ack(if self.ecn.is_some() {
            Ecn::Exist
        } else {
            Ecn::None
        })
    }
}

impl super::EncodeSize for AckFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8 + 8 + 8 + self.ranges.len() * 16 + if self.ecn.is_some() { 24 } else { 0 }
    }

    fn encoding_size(&self) -> usize {
        let ack_range_count = VarInt::try_from(self.ranges.len()).unwrap();

        1 + self.largest.encoding_size()
            + self.delay.encoding_size()
            + ack_range_count.encoding_size()
            + self.first_range.encoding_size()
            + self
                .ranges
                .iter()
                .map(|(gap, ack)| gap.encoding_size() + ack.encoding_size())
                .sum::<usize>()
            + if let Some(e) = self.ecn.as_ref() {
                e.encoding_size()
            } else {
                0
            }
    }
}

impl AckFrame {
    /// Create a new [`AckFrame`].
    pub fn new(
        largest: VarInt,
        delay: VarInt,
        first_range: VarInt,
        ranges: Vec<(VarInt, VarInt)>,
        ecn: Option<EcnCounts>,
    ) -> Self {
        Self {
            largest,
            delay,
            first_range,
            ranges,
            ecn,
        }
    }

    /// Return the largest acknowledged packet number.
    pub fn largest(&self) -> u64 {
        self.largest.into_u64()
    }

    /// Return the delay in microseconds.
    pub fn delay(&self) -> u64 {
        self.delay.into_u64()
    }

    /// Return the first range.
    pub fn first_range(&self) -> u64 {
        self.first_range.into_u64()
    }

    /// Return the ranges.
    pub fn ranges(&self) -> &Vec<(VarInt, VarInt)> {
        &self.ranges
    }

    /// Return the ECN (Explicit Congestion Notification) counter.
    pub fn ecn(&self) -> Option<EcnCounts> {
        self.ecn
    }

    /// Set the value of the ECN (Explicit Congestion Notification) counter
    pub fn set_ecn(&mut self, ecn: EcnCounts) {
        self.ecn = Some(ecn);
    }

    /// Take the value of the ECN (Explicit Congestion Notification) counter
    pub fn take_ecn(&mut self) -> Option<EcnCounts> {
        self.ecn.take()
    }

    /// Iterate through the acknowledged packet ranges, starting from the largest and going down.
    pub fn iter_ranges(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
        let right = self.largest.into_u64();
        let left = right - self.first_range.into_u64();
        Some(left..=right).into_iter().chain(
            self.ranges
                .iter()
                .map(|(gap, range)| (gap.into_u64(), range.into_u64()))
                .scan(left, |largest, (gap, range)| {
                    let right = *largest - gap - 2;
                    let left = right - range;
                    *largest = left;
                    Some(left..=right)
                }),
        )
    }

    /// Iterate through the sequence numbers of the packets acknowledged by the ACK frame,
    /// starting from the largest and going down.
    pub fn iter(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
        self.iter_ranges()
    }
}

/// The counts of Explicit Congestion Notification (ECN) types.
///
/// See [ecn-counts](https://www.rfc-editor.org/rfc/rfc9000.html#name-ecn-counts) of QUIC RFC 9000.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EcnCounts {
    ect0: VarInt,
    ect1: VarInt,
    ce: VarInt,
}

impl EcnCounts {
    /// Create a new [`EcnCounts`].
    pub fn new(ect0: VarInt, ect1: VarInt, ce: VarInt) -> Self {
        Self { ect0, ect1, ce }
    }

    /// Get the value of the ECT0 counter.
    pub fn ect0(&self) -> u64 {
        self.ect0.into_u64()
    }

    /// Get the value of the ECT1 counter.
    pub fn ect1(&self) -> u64 {
        self.ect1.into_u64()
    }

    /// Get the value of the CE counter.
    pub fn ce(&self) -> u64 {
        self.ce.into_u64()
    }

    /// Calculates the encoding size of the [`EcnCounts`] struct.
    fn encoding_size(&self) -> usize {
        self.ect0.encoding_size() + self.ect1.encoding_size() + self.ce.encoding_size()
    }
}

/// Parser for parsing an ACK frame with the given ECN flag,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn ack_frame_with_ecn(ecn: Ecn) -> impl Fn(&[u8]) -> nom::IResult<&[u8], AckFrame> {
    move |input: &[u8]| {
        let (mut remain, (largest, delay, count, first_range)) =
            (be_varint, be_varint, be_varint, be_varint).parse(input)?;
        let mut ranges = Vec::new();
        let mut count = count.into_u64() as usize;
        while count > 0 {
            let (i, (gap, ack)) = (be_varint, be_varint).parse(remain)?;
            ranges.push((gap, ack));
            count -= 1;
            remain = i;
        }

        let ecn = if ecn == Ecn::Exist {
            let (i, ecn) = be_ecn_counts(remain)?;
            remain = i;
            Some(ecn)
        } else {
            None
        };

        Ok((
            remain,
            AckFrame {
                largest,
                delay,
                first_range,
                ranges,
                ecn,
            },
        ))
    }
}

/// Parse the ECN counts from the input bytes,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub(super) fn be_ecn_counts(input: &[u8]) -> nom::IResult<&[u8], EcnCounts> {
    map((be_varint, be_varint, be_varint), |(ect0, ect1, ce)| {
        EcnCounts { ect0, ect1, ce }
    })
    .parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<AckFrame> for T {
    fn put_frame(&mut self, frame: &AckFrame) {
        let frame_type = frame.frame_type();
        self.put_frame_type(frame_type);
        self.put_varint(&frame.largest);
        self.put_varint(&frame.delay);

        let ack_range_count = VarInt::try_from(frame.ranges.len()).unwrap();
        self.put_varint(&ack_range_count);
        self.put_varint(&frame.first_range);
        for (gap, ack) in &frame.ranges {
            self.put_varint(gap);
            self.put_varint(ack);
        }
        if let Some(ecn) = &frame.ecn {
            self.put_varint(&ecn.ect0);
            self.put_varint(&ecn.ect1);
            self.put_varint(&ecn.ce);
        }
    }
}

#[cfg(test)]
mod tests {
    use nom::{Parser, combinator::flat_map};

    use super::*;
    use crate::{
        frame::{EncodeSize, FrameType, GetFrameType, io::WriteFrame},
        varint::{VarInt, be_varint},
    };

    #[test]
    fn test_ack_frame() {
        // test frame type, encoding size, and max encoding size
        let mut frame = AckFrame {
            largest: VarInt::from_u32(0x1234),
            delay: VarInt::from_u32(0x1234),
            first_range: VarInt::from_u32(0x1234),
            ranges: vec![(VarInt::from_u32(3), VarInt::from_u32(20))],
            ecn: None,
        };
        assert_eq!(frame.frame_type(), FrameType::Ack(Ecn::None));
        assert_eq!(frame.encoding_size(), 1 + 2 * 3 + 1 + 2);
        assert_eq!(frame.max_encoding_size(), 1 + 4 * 8 + 2 * 8);

        // test set_ecn and take_ecn
        let ecn = EcnCounts {
            ect0: VarInt::from_u32(0x1234),
            ect1: VarInt::from_u32(0x1234),
            ce: VarInt::from_u32(0x1234),
        };
        frame.set_ecn(ecn);
        assert!(frame.ecn.is_some());
        assert_eq!(frame.take_ecn(), Some(ecn));
    }

    #[test]
    fn test_read_ecn_count() {
        let input = vec![0x52, 0x34, 0x52, 0x34, 0x52, 0x34];
        let (input, ecn) = be_ecn_counts(&input).unwrap();
        assert!(input.is_empty());
        assert_eq!(
            ecn,
            EcnCounts {
                ect0: VarInt::from_u32(0x1234),
                ect1: VarInt::from_u32(0x1234),
                ce: VarInt::from_u32(0x1234),
            }
        );
    }

    #[test]
    fn test_read_ack_frame() {
        let input = vec![0x02, 0x52, 0x34, 0x52, 0x34, 0x01, 0x52, 0x34, 3, 20];
        let (input, ack_frame) = flat_map(be_varint, |frame_type| {
            let ack_frame_type: VarInt = FrameType::Ack(Ecn::None).into();
            assert_eq!(frame_type, ack_frame_type);
            ack_frame_with_ecn(Ecn::None)
        })
        .parse(&input)
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(
            ack_frame,
            AckFrame {
                largest: VarInt::from_u32(0x1234),
                delay: VarInt::from_u32(0x1234),
                first_range: VarInt::from_u32(0x1234),
                ranges: vec![(VarInt::from_u32(3), VarInt::from_u32(20))],
                ecn: None,
            }
        );
    }

    #[test]
    fn test_write_ack_frame() {
        let mut buf = Vec::new();
        let frame = AckFrame {
            largest: VarInt::from_u32(0x1234),
            delay: VarInt::from_u32(0x1234),
            first_range: VarInt::from_u32(0x1234),
            ranges: vec![(VarInt::from_u32(3), VarInt::from_u32(20))],
            ecn: Some(EcnCounts {
                ect0: VarInt::from_u32(0x1234),
                ect1: VarInt::from_u32(0x1234),
                ce: VarInt::from_u32(0x1234),
            }),
        };

        buf.put_frame(&frame);
        assert_eq!(
            buf,
            vec![
                0x03, 0x52, 0x34, 0x52, 0x34, 0x01, 0x52, 0x34, 3, 20, // frame
                0x52, 0x34, 0x52, 0x34, 0x52, 0x34 // ecn
            ]
        );
    }

    #[test]
    fn test_ack_frame_into_iter() {
        // let mut frame = AckFrame::new(1000, 0, 0x1234, None).unwrap();
        let frame = AckFrame {
            largest: VarInt::from_u32(1000),
            delay: VarInt::from_u32(0x1234),
            first_range: VarInt::from_u32(0),
            ranges: vec![
                (VarInt::from_u32(0), VarInt::from_u32(2)),
                (VarInt::from_u32(4), VarInt::from_u32(30)),
                (VarInt::from_u32(7), VarInt::from_u32(40)),
            ],
            ecn: None,
        };
        // frame.alternating_gap_and_range(0, 2);
        // frame.alternating_gap_and_range(4, 30);
        // frame.alternating_gap_and_range(7, 40);

        let mut iter = frame.iter();
        assert_eq!(iter.next(), Some(1000..=1000));
        assert_eq!(iter.next(), Some(996..=998));
        assert_eq!(iter.next(), Some(960..=990));
        assert_eq!(iter.next(), Some(911..=951));
        assert_eq!(iter.next(), None);
    }
}
