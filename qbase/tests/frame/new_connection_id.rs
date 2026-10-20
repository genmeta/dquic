use qbase::{
    cid::ConnectionId,
    frame::{EncodeSize, FrameType, GetFrameType, *},
    token::RESET_TOKEN_SIZE,
    varint::VarInt,
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
