use super::{
    EncodeSize, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::varint::{VarInt, WriteVarInt, be_varint};

/// PUNCH_Hello Frame {
///     Type (i) = 0x3d7e95,
///     Local Sequence Number (i),
///     Remote Sequence Number (i),
///     Probe Identifier (i),
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchHelloFrame {
    local_seq: VarInt,
    remote_seq: VarInt,
    probe_id: VarInt,
}

impl PunchHelloFrame {
    pub fn new(local_seq: u32, remote_seq: u32, probe_id: u32) -> Self {
        Self { local_seq: VarInt::from_u32(local_seq), remote_seq: VarInt::from_u32(remote_seq), probe_id: VarInt::from_u32(probe_id) }
    }

    pub fn local_seq(&self) -> u32 {
        self.local_seq.into_u64() as u32
    }

    pub fn remote_seq(&self) -> u32 {
        self.remote_seq.into_u64() as u32
    }

    pub fn probe_id(&self) -> u32 {
        self.probe_id.into_u64() as u32
    }
}

impl GetFrameType for PunchHelloFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PunchHello
    }
}

impl EncodeSize for PunchHelloFrame {
    fn max_encoding_size(&self) -> usize {
        4 + 8 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size()
            + self.local_seq.encoding_size()
            + self.remote_seq.encoding_size()
            + self.probe_id.encoding_size()
    }
}

impl<T: bytes::BufMut> WriteFrame<PunchHelloFrame> for T {
    fn put_frame(&mut self, frame: &PunchHelloFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.local_seq);
        self.put_varint(&frame.remote_seq);
        self.put_varint(&frame.probe_id);
    }
}

pub(crate) fn be_punch_hello_frame(input: &[u8]) -> nom::IResult<&[u8], PunchHelloFrame> {
    let (input, local_seq) = be_varint(input)?;
    let (input, remote_seq) = be_varint(input)?;
    let (input, probe_id) = be_varint(input)?;
    Ok((input, PunchHelloFrame { local_seq, remote_seq, probe_id }))
}
