use crate::{
    cid::{ConnectionId, WriteConnectionId, be_connection_id},
    frame::{GetFrameType, io::WriteFrameType},
    token::{RESET_TOKEN_SIZE, ResetToken, be_reset_token},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// NEW_CONNECTION_ID frame.
///
/// ```text
/// NEW_CONNECTION_ID Frame {
///   Type (i) = 0x18,
///   Sequence Number (i),
///   Retire Prior To (i),
///   Length (8),
///   Connection ID (8..160),
///   Stateless Reset Token (128),
/// }
/// ```
///
/// See [NEW_CONNECTION_ID Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewConnectionIdFrame {
    sequence: VarInt,
    retire_prior_to: VarInt,
    id: ConnectionId,
    reset_token: ResetToken,
}

impl NewConnectionIdFrame {
    /// Create a new [`NewConnectionIdFrame`].
    pub fn new(cid: ConnectionId, sequence: VarInt, retire_prior_to: VarInt) -> Self {
        let reset_token = ResetToken::random_gen();
        Self {
            sequence,
            retire_prior_to,
            id: cid,
            reset_token,
        }
    }

    /// Return the sequence number of the frame.
    pub fn sequence(&self) -> u64 {
        self.sequence.into_u64()
    }

    /// Return the retire prior to of the frame.
    pub fn retire_prior_to(&self) -> u64 {
        self.retire_prior_to.into_u64()
    }

    /// Return the connection ID of the frame.
    pub fn connection_id(&self) -> &ConnectionId {
        &self.id
    }

    /// Return the reset token of the frame.
    pub fn reset_token(&self) -> &ResetToken {
        &self.reset_token
    }
}

impl super::GetFrameType for NewConnectionIdFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::NewConnectionId
    }
}

impl super::EncodeSize for NewConnectionIdFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8 + 21 + RESET_TOKEN_SIZE
    }

    fn encoding_size(&self) -> usize {
        1 + self.sequence.encoding_size()
            + self.retire_prior_to.encoding_size()
            + 1
            + self.id.len as usize
            + RESET_TOKEN_SIZE
    }
}

/// Parse a NEW_CONNECTION_ID frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_new_connection_id_frame(input: &[u8]) -> nom::IResult<&[u8], NewConnectionIdFrame> {
    let (remain, sequence) = be_varint(input)?;
    let (remain, retire_prior_to) = be_varint(remain)?;
    // The value in the Retire Prior To field MUST be less than or equal to the value in the
    // Sequence Number field. Receiving a value in the Retire Prior To field that is greater
    // than that in the Sequence Number field MUST be treated as a connection error of type
    // FRAME_ENCODING_ERROR.
    if retire_prior_to > sequence {
        // TODO: 这里有信息损失
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    let (remain, cid) = be_connection_id(remain)?;
    if cid.is_empty() {
        // TODO: 这里有信息损失
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    let (remain, reset_token) = be_reset_token(remain)?;
    Ok((
        remain,
        NewConnectionIdFrame {
            sequence,
            retire_prior_to,
            id: cid,
            reset_token,
        },
    ))
}

impl<T: bytes::BufMut> super::io::WriteFrame<NewConnectionIdFrame> for T {
    fn put_frame(&mut self, frame: &NewConnectionIdFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.sequence);
        self.put_varint(&frame.retire_prior_to);
        self.put_connection_id(&frame.id);
        self.put_slice(frame.reset_token.as_slice());
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};

    use super::*;
    use crate::frame::{
        FrameType,
        io::{WriteFrame, WriteFrameType},
    };

    #[test]
    fn test_frame_parsing() {
        let mut buf = BytesMut::new();
        let original_cid = ConnectionId::from_slice(&[1, 2, 3, 4][..]);
        let original_frame =
            NewConnectionIdFrame::new(original_cid, VarInt::from_u32(1), VarInt::from_u32(0));

        // Write frame to buffer
        buf.put_frame(&original_frame);

        // Skip frame type byte
        let (_, parsed_frame) = be_new_connection_id_frame(&buf[1..]).unwrap();

        assert_eq!(parsed_frame.sequence(), original_frame.sequence());
        assert_eq!(
            parsed_frame.retire_prior_to(),
            original_frame.retire_prior_to()
        );
        assert_eq!(parsed_frame.connection_id(), original_frame.connection_id());
        assert_eq!(parsed_frame.reset_token(), original_frame.reset_token());
    }

    #[test]
    fn test_invalid_retire_prior_to() {
        let mut buf = BytesMut::new();
        buf.put_frame_type(FrameType::NewConnectionId);
        buf.put_varint(&VarInt::from_u32(1)); // sequence
        buf.put_varint(&VarInt::from_u32(2)); // retire_prior_to > sequence

        assert!(be_new_connection_id_frame(&buf[1..]).is_err());
    }

    #[test]
    fn test_zero_length_connection_id() {
        let mut buf = BytesMut::new();
        buf.put_frame_type(FrameType::NewConnectionId);
        buf.put_varint(&VarInt::from_u32(1));
        buf.put_varint(&VarInt::from_u32(0));
        buf.put_u8(0); // zero length CID

        assert!(be_new_connection_id_frame(&buf[1..]).is_err());
    }
}
