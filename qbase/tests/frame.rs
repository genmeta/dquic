#[path = "frame/ack.rs"]
mod ack;
#[path = "frame/add_address.rs"]
mod add_address;
#[path = "frame/connection_close.rs"]
mod connection_close;
#[path = "frame/crypto.rs"]
mod crypto;
#[path = "frame/data_blocked.rs"]
mod data_blocked;
#[path = "frame/datagram.rs"]
mod datagram;
#[path = "frame/error.rs"]
mod error;
#[path = "frame/handshake_done.rs"]
mod handshake_done;
#[path = "frame/max_data.rs"]
mod max_data;
#[path = "frame/max_stream_data.rs"]
mod max_stream_data;
#[path = "frame/max_streams.rs"]
mod max_streams;
#[path = "frame/new_connection_id.rs"]
mod new_connection_id;
#[path = "frame/new_token.rs"]
mod new_token;
#[path = "frame/padding.rs"]
mod padding;
#[path = "frame/path_challenge.rs"]
mod path_challenge;
#[path = "frame/path_response.rs"]
mod path_response;
#[path = "frame/ping.rs"]
mod ping;
#[path = "frame/punch_me_now.rs"]
mod punch_me_now;
#[path = "frame/remove_address.rs"]
mod remove_address;
#[path = "frame/reset_stream.rs"]
mod reset_stream;
#[path = "frame/retire_connection_id.rs"]
mod retire_connection_id;
#[path = "frame/stop_sending.rs"]
mod stop_sending;
#[path = "frame/stream.rs"]
mod stream;
#[path = "frame/stream_data_blocked.rs"]
mod stream_data_blocked;
#[path = "frame/streams_blocked.rs"]
mod streams_blocked;

use std::net::SocketAddr;

use bytes::{Buf, BufMut};
use nom::Parser;
use qbase::{
    frame::{io::WriteFrame, *},
    net::Family,
    packet::{
        PacketContent,
        r#type::{
            Type,
            long::{Type::V1, Ver1},
            short::OneRtt,
        },
    },
    varint::{VarInt, WriteVarInt, be_varint},
};

#[test]
fn test_frame_type_conversion() {
    let frame_types = vec![
        FrameType::Padding,
        FrameType::Ping,
        FrameType::Ack(Ecn::None),
        FrameType::Stream(Offset::Zero, Len::Omit, Fin::No),
        FrameType::MaxData,
        FrameType::ConnectionClose(Layer::Quic),
        FrameType::HandshakeDone,
        FrameType::Datagram(0),
    ];

    for frame_type in frame_types {
        let byte: VarInt = frame_type.into();
        assert_eq!(FrameType::try_from(byte).unwrap(), frame_type);
    }
}

#[test]
fn test_frame_type_specs() {
    assert!(FrameType::Padding.specs().contain(Spec::NonAckEliciting));
    assert!(
        FrameType::Ack(Ecn::None)
            .specs()
            .contain(Spec::CongestionControlFree)
    );
    assert!(
        FrameType::Stream(Offset::Zero, Len::Omit, Fin::No)
            .specs()
            .contain(Spec::FlowControlled)
    );
    assert!(FrameType::PathChallenge.specs().contain(Spec::ProbeNewPath));
}

#[test]
fn test_frame_type_belongs_to() {
    let initial = Type::Long(V1(Ver1::INITIAL));
    assert!(FrameType::Padding.belongs_to(initial));
    assert!(FrameType::Ping.belongs_to(initial));
    assert!(FrameType::Ack(Ecn::None).belongs_to(initial));
    assert!(!FrameType::Stream(Offset::Zero, Len::Omit, Fin::No).belongs_to(initial));
}

#[test]
fn test_frame_reader() {
    let mut buf = bytes::BytesMut::new();
    buf.put_u8(0x00); // PADDING
    buf.put_u8(0x01); // PING

    let packet_type = Type::Long(V1(Ver1::INITIAL));
    let mut reader = FrameReader::new(buf.freeze(), packet_type);

    // Read PADDING frame
    let (frame, frame_type) = reader.next().unwrap().unwrap();
    assert!(matches!(frame, Frame::Padding(_)));
    assert!(frame_type.specs().contain(Spec::NonAckEliciting));

    // Read PING frame
    let (frame, frame_type) = reader.next().unwrap().unwrap();
    assert!(matches!(frame, Frame::Ping(_)));
    assert!(!frame_type.specs().contain(Spec::NonAckEliciting));

    // No more frames
    assert!(reader.next().is_none());
}

#[test]
fn test_invalid_frame_type() {
    assert!(FrameType::try_from(VarInt::from_u32(0xFF)).is_err());
}

#[test]
fn test_frame_reader_parses_add_address_frame() {
    use qbase::frame::io::WriteFrame;

    let add_address = AddAddressFrame::new(
        1,
        "127.0.0.1:4433".parse::<SocketAddr>().unwrap(),
        2,
        qbase::net::NatType::RestrictedPort,
    );
    let expected = add_address;
    let mut buf = bytes::BytesMut::new();
    buf.put_frame(&ReliableFrame::AddAddress(add_address));

    let mut reader = FrameReader::new(buf.freeze(), Type::Short(OneRtt(0.into())));
    let (frame, frame_type) = reader.next().unwrap().unwrap();

    assert_eq!(frame_type, FrameType::AddAddress(Family::V4));
    assert_eq!(frame, Frame::AddAddress(expected));
    assert!(reader.next().is_none());
}

#[test]
fn test_frame_reader_rejects_add_address_frame_in_non_data_packets() {
    use qbase::frame::io::WriteFrame;

    let mut buf = bytes::BytesMut::new();
    buf.put_frame(&ReliableFrame::AddAddress(AddAddressFrame::new(
        7,
        "127.0.0.1:8443".parse::<SocketAddr>().unwrap(),
        4,
        qbase::net::NatType::Dynamic,
    )));

    for packet_type in [
        Type::Long(V1(Ver1::INITIAL)),
        Type::Long(V1(Ver1::HANDSHAKE)),
    ] {
        let mut reader = FrameReader::new(buf.clone().freeze(), packet_type);
        assert_eq!(
            reader.next().unwrap().unwrap_err(),
            Error::WrongType(FrameType::AddAddress(Family::V4), packet_type)
        );
    }
}

#[test]
fn test_manual_unknown_custom_frame_fallback() {
    use qbase::varint::WriteVarInt;

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct UnknownCustomFrame {
        pub seq_num: VarInt,
        pub tire: VarInt,
        pub nat_type: VarInt,
    }

    fn be_unknown_custom_frame(input: &[u8]) -> nom::IResult<&[u8], UnknownCustomFrame> {
        use nom::{combinator::verify, sequence::preceded};
        preceded(
            verify(be_varint, |typ| typ == &VarInt::from_u32(0xff)),
            (be_varint, be_varint, be_varint),
        )
        .map(|(seq_num, tire, nat_type)| UnknownCustomFrame {
            seq_num,
            tire,
            nat_type,
        })
        .parse(input)
    }

    fn parse_unknown_custom_frame(input: &[u8]) -> Result<(usize, UnknownCustomFrame), Error> {
        let origin = input.len();
        let (remain, frame) = be_unknown_custom_frame(input).map_err(|_| {
            Error::IncompleteType(format!("Incomplete frame type from input: {input:?}"))
        })?;
        let consumed = origin - remain.len();
        Ok((consumed, frame))
    }

    impl qbase::frame::io::WriteFrame<UnknownCustomFrame> for bytes::BytesMut {
        fn put_frame(&mut self, frame: &UnknownCustomFrame) {
            self.put_varint(&0xff_u32.into());
            self.put_varint(&frame.seq_num);
            self.put_varint(&frame.tire);
            self.put_varint(&frame.nat_type);
        }
    }

    let mut buf = bytes::BytesMut::new();
    let unknown_custom_frame = UnknownCustomFrame {
        seq_num: VarInt::from_u32(0x01),
        tire: VarInt::from_u32(0x02),
        nat_type: VarInt::from_u32(0x03),
    };
    buf.put_frame(&unknown_custom_frame);
    buf.put_frame(&PaddingFrame);
    buf.put_frame(&PaddingFrame);
    buf.put_frame(&unknown_custom_frame);
    buf.put_varint(&0xfe_u32.into());
    let mut padding_count = 0;
    let mut unknown_custom_count = 0;
    let mut reader = FrameReader::new(buf.freeze(), Type::Short(OneRtt(0.into())));
    loop {
        match reader.next() {
            Some(Ok((frame, typ))) => {
                assert!(matches!(frame, Frame::Padding(_)));
                assert_eq!(typ, FrameType::Padding);
                padding_count += 1;
            }
            Some(Err(_e)) => {
                // Parse the unknown custom frame manually.
                if let Ok((consum, frame)) = parse_unknown_custom_frame(&reader) {
                    reader.advance(consum);
                    assert_eq!(frame, unknown_custom_frame);
                    unknown_custom_count += 1;
                } else {
                    reader.clear();
                }
            }
            None => break,
        };
    }
    assert_eq!(padding_count, 2);
    assert_eq!(unknown_custom_count, 2);
}

#[test]
fn test_frame_reader_stops_at_unknown_custom_frame() {
    let mut buf = bytes::BytesMut::new();
    buf.put_frame(&PaddingFrame);
    buf.put_frame(&PaddingFrame);
    // error frame type
    buf.put_varint(&0xfe_u32.into());
    buf.put_frame(&PaddingFrame);

    let mut padding_count = 0;
    let _ = FrameReader::new(buf.freeze(), Type::Short(OneRtt(0.into()))).try_fold(
        PacketContent::default(),
        |packet_contains, frame| {
            let (frame, frame_type) = frame?;

            assert!(matches!(frame, Frame::Padding(_)));
            assert_eq!(frame_type, FrameType::Padding);
            padding_count += 1;
            Result::<_, Error>::Ok(packet_contains)
        },
    );

    assert_eq!(padding_count, 2);
}

fn parse_frame(input: &[u8], expected_type: FrameType) -> Frame<bytes::Bytes> {
    let (consumed, frame, frame_type) = io::be_frame(
        &bytes::Bytes::copy_from_slice(input),
        Type::Short(OneRtt(0.into())),
    )
    .unwrap();
    assert_eq!(frame_type, expected_type);
    assert_eq!(consumed, input.len());
    frame
}
