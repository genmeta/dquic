use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use qbase::{
    ArcReceiving,
    error::{ErrorKind, QuicError},
};
use qrecovery::crypto::CryptoStream;
use qtls::{TlsLimits, incoming::ClientHello};
use tokio::io::AsyncReadExt;

use crate::{CloseReason, Error, Paths};

/// Accumulate Initial CRYPTO until a server can be selected from ClientHello.
#[derive(Clone)]
pub struct Interceptor {
    buffer: Arc<Mutex<Option<BytesMut>>>,
    result: ArcReceiving<Result<ClientHello, Error>>,
    max_bytes: usize,
}

impl Interceptor {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Some(BytesMut::new()))),
            result: ArcReceiving::default(),
            max_bytes: TlsLimits::default().max_handshake_bytes,
        }
    }

    /// Append contiguous bytes read from the Initial CRYPTO stream.
    ///
    /// The first complete result or error wakes [`Self::read`]. Later input is ignored.
    /// Returns whether interception has completed.
    pub fn write(&self, bytes: impl AsRef<[u8]>) -> bool {
        let result = {
            let mut slot = self.buffer.lock().unwrap();
            let Some(buffer) = slot.as_mut() else {
                return true;
            };
            let inspected = match buffer.len().checked_add(bytes.as_ref().len()) {
                Some(received) if received <= self.max_bytes => {
                    buffer.extend_from_slice(bytes.as_ref());
                    qtls::incoming::client_hello(buffer, self.max_bytes)
                        .map_err(crate::tls::tls_error)
                }
                _ => Err(crate::tls::tls_error(
                    qtls::PeerTlsError::ResourceLimit {
                        resource: "ClientHello bytes",
                        limit: self.max_bytes,
                    }
                    .into(),
                )),
            };
            match inspected {
                Ok(None) => None,
                Ok(Some(hello)) => {
                    *slot = None;
                    Some(Ok(hello))
                }
                Err(error) => {
                    *slot = None;
                    Some(Err(error))
                }
            }
        };
        if let Some(result) = result {
            self.result.set(result);
            true
        } else {
            false
        }
    }

    /// Consume the interceptor once a complete ClientHello is available.
    pub async fn read(self) -> Result<ClientHello, Error> {
        match self.result.await {
            Ok(Some(result)) => result,
            Ok(None) => Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "ClientHello was already read",
            )
            .into()),
            Err(_) => Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "ClientHello interception was cancelled",
            )
            .into()),
        }
    }
}

impl Default for Interceptor {
    fn default() -> Self {
        Self::new()
    }
}

/// Feed Initial CRYPTO into the interceptor until ClientHello or a read failure.
pub(super) async fn read_crypto_stream_to_interceptor(
    interceptor: Interceptor,
    stream: CryptoStream,
    paths: Arc<Paths>,
) {
    let terminator = paths.terminator.clone();
    let mut reader = stream.reader();
    let mut buffer = [0; 4096];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                terminator.close(
                    CloseReason::Internal(QuicError::with_default_fty(
                        ErrorKind::ProtocolViolation,
                        "Initial CRYPTO ended before ClientHello",
                    )),
                    paths.closing_pto(),
                );
                break;
            }
            Ok(length) if interceptor.write(&buffer[..length]) => break,
            Ok(_) => {}
            Err(error) => {
                terminator.close(
                    CloseReason::Internal(QuicError::with_default_fty(
                        ErrorKind::Internal,
                        error.to_string(),
                    )),
                    paths.closing_pto(),
                );
                break;
            }
        }
    }
}
