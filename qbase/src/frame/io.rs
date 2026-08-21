use bytes::Bytes;

use super::{
    ack::ack_frame_with_ecn, add_address::be_add_address_frame,
    connection_close::connection_close_frame_at_layer, crypto::be_crypto_frame,
    data_blocked::be_data_blocked_frame, datagram::datagram_frame_with_flag,
    max_data::be_max_data_frame, max_stream_data::be_max_stream_data_frame,
    max_streams::max_streams_frame_with_dir, new_connection_id::be_new_connection_id_frame,
    new_token::be_new_token_frame, path_challenge::be_path_challenge_frame,
    path_response::be_path_response_frame, punch_done::be_punch_done_frame,
    punch_hello::be_punch_hello_frame, punch_me_now::be_punch_me_now_frame,
    remove_address::be_remove_address_frame, reset_stream::be_reset_stream_frame,
    retire_connection_id::be_retire_connection_id_frame, stop_sending::be_stop_sending_frame,
    stream::stream_frame_with_flag, stream_data_blocked::be_stream_data_blocked_frame,
    streams_blocked::streams_blocked_frame_with_dir, *,
};
use crate::{ArcReceiving, util::ContinuousData};

/// Return a parser for a complete frame from the raw bytes with the given type,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
///
/// Some frames like [`StreamFrame`] and [`CryptoFrame`] have a data body,
/// which use `bytes::Bytes` to store.
fn complete_frame(
    frame_type: FrameType,
    raw: Bytes,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], Frame> {
    use nom::{Parser, combinator::map};
    move |input: &[u8]| match frame_type {
        FrameType::Padding => Ok((input, Frame::Padding(PaddingFrame))),
        FrameType::Ping => Ok((input, Frame::Ping(PingFrame))),
        FrameType::ConnectionClose(layer) => {
            map(connection_close_frame_at_layer(layer), Frame::Close).parse(input)
        }
        FrameType::NewConnectionId => {
            map(be_new_connection_id_frame, Frame::NewConnectionId).parse(input)
        }
        FrameType::RetireConnectionId => {
            map(be_retire_connection_id_frame, Frame::RetireConnectionId).parse(input)
        }
        FrameType::DataBlocked => map(be_data_blocked_frame, Frame::DataBlocked).parse(input),
        FrameType::MaxData => map(be_max_data_frame, Frame::MaxData).parse(input),
        FrameType::PathChallenge => map(be_path_challenge_frame, Frame::PathChallenge).parse(input),
        FrameType::PathResponse => map(be_path_response_frame, Frame::PathResponse).parse(input),
        FrameType::HandshakeDone => Ok((input, Frame::HandshakeDone(HandshakeDoneFrame))),
        FrameType::NewToken => map(be_new_token_frame, Frame::NewToken).parse(input),
        FrameType::Ack(ecn) => map(ack_frame_with_ecn(ecn), Frame::Ack).parse(input),
        FrameType::ResetStream => {
            map(be_reset_stream_frame, |f| Frame::StreamCtl(f.into())).parse(input)
        }
        FrameType::StopSending => {
            map(be_stop_sending_frame, |f| Frame::StreamCtl(f.into())).parse(input)
        }
        FrameType::MaxStreamData => {
            map(be_max_stream_data_frame, |f| Frame::StreamCtl(f.into())).parse(input)
        }
        FrameType::MaxStreams(dir) => map(max_streams_frame_with_dir(dir), |f| {
            Frame::StreamCtl(f.into())
        })
        .parse(input),
        FrameType::StreamsBlocked(dir) => map(streams_blocked_frame_with_dir(dir), |f| {
            Frame::StreamCtl(f.into())
        })
        .parse(input),
        FrameType::StreamDataBlocked => {
            map(be_stream_data_blocked_frame, |f| Frame::StreamCtl(f.into())).parse(input)
        }
        FrameType::Crypto => {
            let (input, frame) = be_crypto_frame(input)?;
            let start = raw.len() - input.len();
            let len = frame.len() as usize;
            if input.len() < len {
                Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())))
            } else {
                let data = raw.slice(start..start + len);
                Ok((&input[len..], Frame::Crypto(frame, data)))
            }
        }
        FrameType::Stream(offset, len, fin) => {
            let (input, frame) = stream_frame_with_flag(offset, len, fin)(input)?;
            let start = raw.len() - input.len();
            let len = frame.len();
            if input.len() < len {
                Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())))
            } else {
                let data = raw.slice(start..start + len);
                Ok((&input[len..], Frame::Stream(frame, data)))
            }
        }
        FrameType::Datagram(with_len) => {
            let (input, frame) = datagram_frame_with_flag(with_len)(input)?;
            let start = raw.len() - input.len();
            match frame.encode_len() {
                true if frame.len().into_u64() > input.len() as u64 => Err(nom::Err::Incomplete(
                    nom::Needed::new((frame.len().into_u64() - input.len() as u64) as usize),
                )),
                true => {
                    let data = raw.slice(start..start + frame.len().into_u64() as usize);
                    Ok((
                        &input[frame.len().into_u64() as usize..],
                        Frame::Datagram(frame, data),
                    ))
                }
                false => {
                    let data = raw.slice(start..);
                    Ok((&[], Frame::Datagram(frame, data)))
                }
            }
        }
        FrameType::AddAddress(family) => {
            map(be_add_address_frame(family), Frame::AddAddress).parse(input)
        }
        FrameType::RemoveAddress => map(be_remove_address_frame, Frame::RemoveAddress).parse(input),
        FrameType::PunchMeNow(family) => {
            map(be_punch_me_now_frame(family), Frame::PunchMeNow).parse(input)
        }
        FrameType::PunchHello => map(be_punch_hello_frame, Frame::PunchHello).parse(input),
        FrameType::PunchDone => map(be_punch_done_frame, Frame::PunchDone).parse(input),
    }
}

/// Parse a frame type from the raw bytes, [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_frame(raw: &Bytes, packet_type: Type) -> Result<(usize, Frame, FrameType), Error> {
    let input = raw.as_ref();
    let (remain, frame_type) = be_frame_type(input)?;
    if !frame_type.belongs_to(packet_type) {
        return Err(Error::WrongType(frame_type, packet_type));
    }

    let (remain, frame) = complete_frame(frame_type, raw.clone())(remain).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => {
            nom::Err::Error(Error::IncompleteFrame(frame_type, ne.to_string()))
        }
        nom::Err::Error(ne) => {
            // may be TooLarge in MaxStreamsFrame/CryptoFrame/StreamFrame,
            // or may be Verify in NewConnectionIdFrame,
            // or may be Alt in ConnectionCloseFrame
            nom::Err::Error(Error::ParseError(
                frame_type,
                ne.code.description().to_owned(),
            ))
        }
        _ => unreachable!("parsing frame never fails"),
    })?;
    Ok((input.len() - remain.len(), frame, frame_type))
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write all kinds of frames.
pub trait WriteFrame<F>: bytes::BufMut {
    /// Write a frame to the buffer.
    fn put_frame(&mut self, frame: &F);
}

impl<B: BufMut, D: ContinuousData> WriteFrame<Frame<D>> for B
where
    D: ContinuousData,
    B: BufMut + ?Sized,
    for<'b> &'b mut B: crate::util::WriteData<D>,
{
    fn put_frame(&mut self, frame: &Frame<D>) {
        #[inline(always)]
        fn put<F, B: WriteFrame<F> + ?Sized>(buf: &mut B, frame: &F) {
            buf.put_frame(frame);
        }
        let mut buf = self;
        match frame {
            Frame::Padding(f) => put(&mut buf, f),
            Frame::Ping(f) => put(&mut buf, f),
            Frame::Ack(f) => put(&mut buf, f),
            Frame::Close(f) => put(&mut buf, f),
            Frame::NewToken(f) => put(&mut buf, f),
            Frame::MaxData(f) => put(&mut buf, f),
            Frame::DataBlocked(f) => put(&mut buf, f),
            Frame::AddAddress(f) => put(&mut buf, f),
            Frame::RemoveAddress(f) => put(&mut buf, f),
            Frame::PunchMeNow(f) => put(&mut buf, f),
            Frame::PunchHello(f) => put(&mut buf, f),
            Frame::PunchDone(f) => put(&mut buf, f),
            Frame::NewConnectionId(f) => put(&mut buf, f),
            Frame::RetireConnectionId(f) => put(&mut buf, f),
            Frame::HandshakeDone(f) => put(&mut buf, f),
            Frame::PathChallenge(f) => put(&mut buf, f),
            Frame::PathResponse(f) => put(&mut buf, f),
            Frame::StreamCtl(f) => put(&mut buf, f),
            Frame::Stream(f, d) => buf.put_data_frame(f, d),
            Frame::Crypto(f, d) => buf.put_data_frame(f, d),
            Frame::Datagram(f, d) => buf.put_data_frame(f, d),
        }
    }
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write frame with data.
pub trait WriteDataFrame<F, D: ContinuousData>: bytes::BufMut {
    /// Write a frame and its data to the buffer.
    fn put_data_frame(&mut self, frame: &F, data: &D);
}

/// A [`bytes::BufMut`] extension trait to write [`FrameType`].
pub trait WriteFrameType: bytes::BufMut {
    /// Write a frame type to the buffer.
    fn put_frame_type(&mut self, frame_type: FrameType);
}

impl<T: BufMut> WriteFrameType for T {
    fn put_frame_type(&mut self, frame_type: FrameType) {
        use crate::varint::WriteVarInt;
        let fty: VarInt = frame_type.into();
        self.put_varint(&fty);
    }
}

/// Some modules that need send specific frames can implement `SendFrame` trait directly.
///
/// Alternatively, a temporary buffer that stores certain frames can also implement this trait,
/// But additional processing is required to ensure that the frames in the buffer are eventually
/// sent to the peer.
pub trait SendFrame<T> {
    /// Need send the frames to the peer
    fn send_frame<I: IntoIterator<Item = T>>(&self, iter: I);
}

/// Some modules that need receive specific frames can implement `ReceiveFrame` trait directly.
///
/// Alternatively, a temporary buffer that stores certain frames can also implement this trait,
/// But additional processing is required to ensure that the frames in the buffer are eventually
/// delivered to the corresponding modules.
pub trait ReceiveFrame<T> {
    type Output;

    /// Receive the frames from the peer
    fn recv_frame(&self, frame: T) -> Result<Self::Output, crate::error::Error>;
}

impl<F> ReceiveFrame<F> for ArcReceiving<F> {
    type Output = ();

    fn recv_frame(&self, frame: F) -> Result<Self::Output, crate::error::Error> {
        self.obtain(frame);
        Ok(())
    }
}
