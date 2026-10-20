use bytes::{BufMut, BytesMut};
use qbase::{
    cid::ConnectionId,
    frame::{
        EncodeSize, FrameType, GetFrameType,
        io::{WriteFrame, WriteFrameType},
        *,
    },
    token::RESET_TOKEN_SIZE,
    varint::{VarInt, WriteVarInt},
};

#[test]
fn test_new_connection_id_frame() {
    let new_cid_frame = NewConnectionIdFrame::new(
        ConnectionId::from_slice(&[1, 2, 3, 4][..]),
        VarInt::from_u32(1),
        VarInt::from_u32(0),
    );
    assert_eq!(new_cid_frame.sequence(), 1);
    assert_eq!(new_cid_frame.retire_prior_to(), 0);
    assert_eq!(
        *new_cid_frame.connection_id(),
        ConnectionId::from_slice(&[1, 2, 3, 4][..])
    );

    assert_eq!(new_cid_frame.frame_type(), FrameType::NewConnectionId);
    assert_eq!(
        new_cid_frame.max_encoding_size(),
        1 + 8 + 8 + 21 + RESET_TOKEN_SIZE
    );
    assert_eq!(new_cid_frame.encoding_size(), 1 + 1 + 1 + 1 + 4 + 16);
}

#[test]
fn test_frame_parsing() {
    let mut buf = BytesMut::new();
    let original_cid = ConnectionId::from_slice(&[1, 2, 3, 4][..]);
    let original_frame =
        NewConnectionIdFrame::new(original_cid, VarInt::from_u32(1), VarInt::from_u32(0));

    // Write frame to buffer
    buf.put_frame(&original_frame);

    let Frame::NewConnectionId(parsed_frame) = super::parse_frame(&buf, FrameType::NewConnectionId)
    else {
        panic!("expected NEW_CONNECTION_ID frame")
    };

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

    assert!(io::be_frame(&buf.freeze(), super::Type::Short(super::OneRtt(0.into()))).is_err());
}

#[test]
fn test_zero_length_connection_id() {
    let mut buf = BytesMut::new();
    buf.put_frame_type(FrameType::NewConnectionId);
    buf.put_varint(&VarInt::from_u32(1));
    buf.put_varint(&VarInt::from_u32(0));
    buf.put_u8(0); // zero length CID

    assert!(io::be_frame(&buf.freeze(), super::Type::Short(super::OneRtt(0.into()))).is_err());
}
