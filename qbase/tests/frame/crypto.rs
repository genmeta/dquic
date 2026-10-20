use qbase::{
    frame::{
        CryptoFrame, EncodeSize, FrameType, GetFrameType,
        io::{WriteDataFrame, WriteFrameType},
    },
    varint::VarInt,
};

#[test]
fn test_crypto_frame() {
    let frame = CryptoFrame::new(VarInt::from_u32(0), VarInt::from_u32(500));
    assert_eq!(frame.frame_type(), qbase::frame::FrameType::Crypto);
    assert_eq!(frame.max_encoding_size(), 1 + 8 + 8);
    assert_eq!(frame.encoding_size(), 1 + 1 + 2);
    assert_eq!(frame.offset(), 0);
    assert_eq!(frame.len(), 500);
    assert_eq!(frame.range(), 0..500);
}

#[test]
fn test_write_crypto_frame() {
    let mut buf = bytes::BytesMut::new();
    let frame = CryptoFrame::new(VarInt::from_u32(0x1234), VarInt::from_u32(0x5));
    buf.put_data_frame(&frame, b"hello");
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::Crypto);
    expected.extend_from_slice(&[0x52, 0x34, 0x05]);
    expected.extend_from_slice(b"hello");
    assert_eq!(buf, bytes::Bytes::from(expected));
}

#[test]
fn test_encoding_capacity_estimate() {
    assert_eq!(CryptoFrame::estimate_max_capacity(1, 0), None);
    assert_eq!(CryptoFrame::estimate_max_capacity(4, 0), Some(1));
    assert_eq!(CryptoFrame::estimate_max_capacity(4, 64), None);
    assert_eq!(CryptoFrame::estimate_max_capacity(5, 65), Some(1));
    assert_eq!(CryptoFrame::estimate_max_capacity(67, 65), Some(63));
    assert_eq!(CryptoFrame::estimate_max_capacity(68, 65), Some(63));
    assert_eq!(CryptoFrame::estimate_max_capacity(69, 65), Some(64));
    assert_eq!(CryptoFrame::estimate_max_capacity(16387, 65), Some(16382));
    assert_eq!(CryptoFrame::estimate_max_capacity(16388, 65), Some(16383));
    assert_eq!(CryptoFrame::estimate_max_capacity(16389, 65), Some(16383));
    assert_eq!(CryptoFrame::estimate_max_capacity(16390, 65), Some(16383));
    assert_eq!(CryptoFrame::estimate_max_capacity(16391, 65), Some(16384));
}

#[test]
#[should_panic]
fn test_encoding_with_offset_exceeded() {
    CryptoFrame::estimate_max_capacity(60, 1 << 62);
}

#[test]
#[should_panic]
fn test_encoding_with_length_too_large() {
    CryptoFrame::estimate_max_capacity(1 << 31, 20);
}
