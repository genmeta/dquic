use derive_more::Deref;

use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    varint::{VarInt, WriteVarInt, be_varint},
};
/// NEW_TOKEN frame.
///
/// ```text
/// NEW_TOKEN Frame {
///   Type (i) = 0x07,
///   Token Length (i),
///   Token (..),
/// }
/// ```
///
/// See [NEW_TOKEN Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-new_token-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Deref, Debug, Clone, PartialEq, Eq)]
pub struct NewTokenFrame {
    #[deref]
    token: Vec<u8>,
}

impl super::GetFrameType for NewTokenFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::NewToken
    }
}

impl super::EncodeSize for NewTokenFrame {
    fn max_encoding_size(&self) -> usize {
        // token's length could not exceed 20
        1 + 1 + self.token.len()
    }

    fn encoding_size(&self) -> usize {
        1 + 1 + self.token.len()
    }
}

impl NewTokenFrame {
    /// Create a new [`NewTokenFrame`] with the given token.
    pub fn new(token: Vec<u8>) -> Self {
        Self { token }
    }

    /// Create a new [`NewTokenFrame`] from the given token slice.
    pub fn from_slice(token: &[u8]) -> Self {
        Self {
            token: token.to_vec(),
        }
    }

    /// Return the token of the frame.
    pub fn token(&self) -> &[u8] {
        &self.token
    }
}

/// Parse a NEW_TOKEN frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_new_token_frame(input: &[u8]) -> nom::IResult<&[u8], NewTokenFrame> {
    use nom::{
        Parser,
        bytes::streaming::take,
        combinator::{flat_map, map},
    };
    flat_map(be_varint, |length| {
        map(take(length.into_u64() as usize), NewTokenFrame::from_slice)
    })
    .parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<NewTokenFrame> for T {
    fn put_frame(&mut self, frame: &NewTokenFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&VarInt::from_u32(frame.token.len() as u32));
        self.put_slice(&frame.token);
    }
}
