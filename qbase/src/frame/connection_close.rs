use std::borrow::Cow;

use derive_more::From;
use nom::bytes::complete::take;

use super::FrameType;
use crate::{
    error::{ErrorFrameType, ErrorKind},
    frame::{GetFrameType, be_frame_type, io::WriteFrameType},
    varint::{VarInt, be_varint},
};

/// Layer flag for CONNECTION_CLOSE frames
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Layer {
    /// QUIC transport layer (0x1c)
    Quic,
    /// Application layer (0x1d)
    App,
}

impl From<Layer> for u8 {
    fn from(layer: Layer) -> u8 {
        match layer {
            Layer::Quic => 0,
            Layer::App => 1,
        }
    }
}

impl From<u8> for Layer {
    fn from(value: u8) -> Self {
        match value & 0x01 {
            0 => Layer::Quic,
            _ => Layer::App,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCloseFrame {
    error_code: VarInt,
    reason: Cow<'static, str>,
}

impl AppCloseFrame {
    /// Return the error code of the frame.
    pub fn error_code(&self) -> u64 {
        self.error_code.into_u64()
    }

    /// Return the reason of the frame.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Otherwise, information about the application state might be revealed.
    ///
    /// Endpoints MUST clear the value of the Reason Phrase field and SHOULD use
    /// the APPLICATION_ERROR code when converting to a CONNECTION_CLOSE of type 0x1c.
    ///
    /// See [section-10.2.3-3](https://datatracker.ietf.org/doc/html/rfc9000#section-10.2.3-3)
    /// of [QUIC](https://datatracker.ietf.org/doc/html/rfc9000) for more details.
    pub fn conceal(&self) -> QuicCloseFrame {
        QuicCloseFrame {
            error_kind: ErrorKind::Application,
            frame_type: ErrorFrameType::V1(FrameType::Padding),
            reason: Cow::Borrowed(""),
        }
    }
}

impl From<AppCloseFrame> for QuicCloseFrame {
    fn from(_: AppCloseFrame) -> Self {
        QuicCloseFrame {
            error_kind: ErrorKind::Application,
            frame_type: ErrorFrameType::V1(FrameType::Padding),
            reason: Cow::Borrowed(""),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicCloseFrame {
    error_kind: ErrorKind,
    frame_type: ErrorFrameType,
    reason: Cow<'static, str>,
}

impl QuicCloseFrame {
    /// Return the error kind of the frame.
    pub fn error_kind(&self) -> ErrorKind {
        self.error_kind
    }

    /// Return the frame type of the frame.
    pub fn frame_type(&self) -> ErrorFrameType {
        self.frame_type
    }

    /// Return the reason of the frame.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// CONNECTION_CLOSE Frame.
///
/// ```text
/// CONNECTION_CLOSE Frame {
///   Type (i) = 0x1c..0x1d,
///   Error Code (i),
///   [Frame Type (i)],
///   Reason Phrase Length (i),
///   Reason Phrase (..),
/// }
/// ```
///
/// See [connection close frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-connection-close-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, From, PartialEq, Eq)]
pub enum ConnectionCloseFrame {
    App(AppCloseFrame),
    Quic(QuicCloseFrame),
}

impl super::GetFrameType for ConnectionCloseFrame {
    fn frame_type(&self) -> FrameType {
        match self {
            ConnectionCloseFrame::App(_) => FrameType::ConnectionClose(Layer::App),
            ConnectionCloseFrame::Quic(_) => FrameType::ConnectionClose(Layer::Quic),
        }
    }
}

impl super::EncodeSize for ConnectionCloseFrame {
    fn max_encoding_size(&self) -> usize {
        // reason's length could not exceed 16KB, so it can be encoded in 2 bytes.
        match self {
            ConnectionCloseFrame::App(frame) => 1 + 8 + 2 + frame.reason.len(),
            ConnectionCloseFrame::Quic(frame) => 1 + 8 + 8 + 2 + frame.reason.len(),
        }
    }

    fn encoding_size(&self) -> usize {
        match self {
            ConnectionCloseFrame::App(frame) => {
                1 + frame.error_code.encoding_size()
                    // reason's length could not exceed 16KB.
                    + VarInt::try_from(frame.reason.len()).unwrap().encoding_size()
                    + frame.reason.len()
            }
            ConnectionCloseFrame::Quic(frame) => {
                1 + VarInt::from(frame.error_kind).encoding_size() + 1
                    // reason's length could not exceed 16KB.
                    + VarInt::try_from(frame.reason.len()).unwrap().encoding_size()
                    + frame.reason.len()
            }
        }
    }
}

impl ConnectionCloseFrame {
    /// Create a new `ConnectionCloseFrame` at QUIC layer.
    pub fn new_quic(
        error_kind: ErrorKind,
        frame_type: ErrorFrameType,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::Quic(QuicCloseFrame {
            error_kind,
            frame_type,
            reason: reason.into(),
        })
    }

    /// Create a new `ConnectionCloseFrame` at application layer.
    pub fn new_app(error_code: VarInt, reason: impl Into<Cow<'static, str>>) -> Self {
        Self::App(AppCloseFrame {
            error_code,
            reason: reason.into(),
        })
    }
}

fn be_app_close_frame(input: &[u8]) -> nom::IResult<&[u8], AppCloseFrame> {
    let (remain, error_code) = be_varint(input)?;
    let (remain, reason_length) = be_varint(remain)?;
    let (remain, reason) = take(reason_length)(remain)?;
    let cow = String::from_utf8_lossy(reason).into_owned();
    Ok((
        remain,
        AppCloseFrame {
            error_code,
            reason: Cow::Owned(cow),
        },
    ))
}

fn be_quic_close_frame(input: &[u8]) -> nom::IResult<&[u8], QuicCloseFrame> {
    let (remain, error_code) = be_varint(input)?;
    let error_kind = ErrorKind::try_from(error_code)
        .map_err(|_e| nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Alt)))?;
    let (remain, frame_type) = be_frame_type(remain)
        .map_err(|_e| nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Alt)))?;
    let (remain, reason_length) = be_varint(remain)?;
    let (remain, reason) = take(reason_length)(remain)?;
    let cow = String::from_utf8_lossy(reason).into_owned();
    Ok((
        remain,
        QuicCloseFrame {
            error_kind,
            frame_type: frame_type.into(),
            reason: Cow::Owned(cow),
        },
    ))
}

/// Return a parser for a CONNECTION_CLOSE frame with the given layer.
///
/// The `layer` parameter specifies which type of CONNECTION_CLOSE frame to parse:
/// - `Layer::Conn`: Parse a QUIC transport layer CONNECTION_CLOSE frame (0x1c)
/// - `Layer::App`: Parse an application layer CONNECTION_CLOSE frame (0x1d)
///
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn connection_close_frame_at_layer(
    layer: Layer,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], ConnectionCloseFrame> {
    move |input: &[u8]| match layer {
        Layer::App => {
            be_app_close_frame(input).map(|(remain, app)| (remain, ConnectionCloseFrame::App(app)))
        }
        Layer::Quic => be_quic_close_frame(input)
            .map(|(remain, quic)| (remain, ConnectionCloseFrame::Quic(quic))),
    }
}

impl<T: bytes::BufMut> super::io::WriteFrame<ConnectionCloseFrame> for T {
    fn put_frame(&mut self, frame: &ConnectionCloseFrame) {
        use crate::varint::WriteVarInt;
        self.put_frame_type(frame.frame_type());
        match frame {
            ConnectionCloseFrame::App(frame) => {
                self.put_varint(&frame.error_code);
                let len = frame.reason.len().min(self.remaining_mut());
                self.put_varint(&VarInt::from_u32(len as u32));
                self.put_slice(&frame.reason.as_bytes()[..len]);
            }
            ConnectionCloseFrame::Quic(frame) => {
                self.put_varint(&frame.error_kind.into());
                self.put_varint(&frame.frame_type.into());
                let len = frame.reason.len().min(self.remaining_mut());
                self.put_varint(&VarInt::from_u32(len as u32));
                self.put_slice(&frame.reason.as_bytes()[..len]);
            }
        }
    }
}
