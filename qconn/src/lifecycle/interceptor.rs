use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use qbase::{
    ArcReceiving,
    error::{ErrorKind, QuicError},
};
use qtls::{TlsLimits, incoming::ClientHello};

use crate::Error;

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
                _ => Err(limit_error(self.max_bytes)),
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
            Ok(None) => Err(internal_error("ClientHello was already read")),
            Err(_) => Err(internal_error("ClientHello interception was cancelled")),
        }
    }
}

impl Default for Interceptor {
    fn default() -> Self {
        Self::new()
    }
}

fn limit_error(limit: usize) -> Error {
    crate::tls::tls_error(
        qtls::PeerTlsError::ResourceLimit {
            resource: "ClientHello bytes",
            limit,
        }
        .into(),
    )
}

fn internal_error(reason: &'static str) -> Error {
    QuicError::with_default_fty(ErrorKind::Internal, reason).into()
}
