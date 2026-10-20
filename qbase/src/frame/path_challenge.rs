use derive_more::Deref;
use rand::RngExt;

use crate::frame::{GetFrameType, io::WriteFrameType};
/// PATH_CHALLENGE frame.
///
/// ```text
/// PATH_CHALLENGE Frame {
///   Type (i) = 0x1a,
///   Data (64),
/// }
/// ```
///
/// See [PATH_CHALLENGE Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-path_challenge-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deref)]
pub struct PathChallengeFrame {
    #[deref]
    data: [u8; 8],
}

impl PathChallengeFrame {
    pub fn from_slice(data: &[u8]) -> Self {
        let mut frame = Self { data: [0; 8] };
        frame.data.copy_from_slice(data);
        frame
    }

    pub fn random() -> Self {
        let mut rng = rand::rng();
        let mut data = [0; 8];
        rng.fill(&mut data);
        Self { data }
    }
}

impl super::GetFrameType for PathChallengeFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PathChallenge
    }
}

impl super::EncodeSize for PathChallengeFrame {
    fn max_encoding_size(&self) -> usize {
        1 + self.data.len()
    }

    fn encoding_size(&self) -> usize {
        1 + self.data.len()
    }
}

/// Parse a PATH_CHALLENGE frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_path_challenge_frame(input: &[u8]) -> nom::IResult<&[u8], PathChallengeFrame> {
    use nom::{Parser, bytes::streaming::take, combinator::map};
    map(take(8usize), PathChallengeFrame::from_slice).parse(input)
}

// BufMut write extension for PATH_CHALLENGE_FRAME
impl<T: bytes::BufMut> super::io::WriteFrame<PathChallengeFrame> for T {
    fn put_frame(&mut self, frame: &PathChallengeFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_slice(&frame.data);
    }
}
