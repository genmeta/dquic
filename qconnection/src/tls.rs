//! Async views of independent TLS outputs. No packet or connection state lives here.
use std::{
    collections::VecDeque,
    future::poll_fn,
    sync::{Arc, Mutex},
    task::{Poll, Waker},
};

use bytes::{Bytes, BytesMut};
use qbase::{
    ArcReceiving, Epoch,
    error::{Error, ErrorKind, QuicError},
    param::{ClientParameters, ServerParameters, WriteParameters},
};
use qtls::{HandshakeSummary, InstalledKeys, TlsEvent, TlsHandshake};
use qtransport::space::Space;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::CloseReason;

/// One reader for CRYPTO output, and one growing coroutine for handshake results.
#[derive(Clone)]
pub struct TlsContext(Arc<Mutex<Result<Tls, Error>>>);

enum Backend {
    Handshake(Box<TlsHandshake>),
    Established(Box<qtls::EstablishedTls>),
    // Used only while moving the completed handshake into Established under the lock.
    Closed,
}

struct Tls {
    backend: Backend,
    messages: VecDeque<(Epoch, Bytes)>,
    keys: VecDeque<InstalledKeys>,
    client_hello: Option<(Option<Arc<str>>, Bytes)>,
    server_parameters: Option<Bytes>,
    summary: Option<HandshakeSummary>,
    pending_bytes: usize,
    max_pending_bytes: usize,
    message_waker: Option<Waker>,
    level_wakers: [Option<Waker>; 3],
    key_waker: Option<Waker>,
    client_hello_waker: Option<Waker>,
    server_parameters_waker: Option<Waker>,
    finished_waker: Option<Waker>,
}

impl TlsContext {
    pub fn client(
        endpoint: &qtls::TlsClient,
        server_name: qtls::ServerName<'static>,
        parameters: &ClientParameters,
    ) -> Result<Self, Error> {
        let max_pending_bytes = endpoint.max_flight_bytes();
        let mut encoded = BytesMut::new();
        encoded.put_parameters(parameters);
        let tls = endpoint
            .start(qtls::ClientStart {
                server_name,
                quic_version: qtls::QuicVersion::V1,
                local_transport_parameters: encoded.freeze(),
            })
            .map_err(tls_error)?;
        Self::new(tls, max_pending_bytes)
    }

    pub fn server(
        endpoint: &qtls::TlsServer,
        version: qtls::QuicVersion,
        parameters: Bytes,
        hello: qtls::incoming::ClientHello,
    ) -> Result<(Self, Arc<ClientParameters>), Error> {
        let client_parameters = Arc::new(ClientParameters::parse_from_bytes(
            hello.transport_parameters(),
        )?);
        let tls = endpoint.start(version, parameters).map_err(tls_error)?;
        let context = Self::new(tls, endpoint.max_flight_bytes())?;
        context.write_msg(Epoch::Initial, hello.encoded())?;
        if let Ok(tls) = context.0.lock().unwrap().as_mut() {
            tls.client_hello = None;
        }
        Ok((context, client_parameters))
    }

    /// Wrap a configured client or server backend. Server endpoint selection is external.
    /// The byte limit bounds TLS output waiting for the CRYPTO writer, independently of
    /// the backend's limits on received handshake messages and individual output flights.
    pub fn new(tls: TlsHandshake, max_pending_bytes: usize) -> Result<Self, Error> {
        let mut tls = Tls {
            backend: Backend::Handshake(Box::new(tls)),
            messages: VecDeque::new(),
            keys: VecDeque::new(),
            client_hello: None,
            server_parameters: None,
            summary: None,
            pending_bytes: 0,
            max_pending_bytes,
            message_waker: None,
            level_wakers: [None, None, None],
            key_waker: None,
            client_hello_waker: None,
            server_parameters_waker: None,
            finished_waker: None,
        };
        tls.collect()?;
        Ok(Self(Arc::new(Mutex::new(Ok(tls)))))
    }

    /// Read output bytes, not necessarily one complete TLS message. Cancellation is safe.
    pub async fn read_msg(&self) -> Result<(Epoch, Bytes), Error> {
        poll_fn(|cx| {
            let mut guard = self.0.lock().unwrap();
            let tls = match guard.as_mut() {
                Ok(tls) => tls,
                Err(error) => return Poll::Ready(Err(error.clone())),
            };
            if let Some((level, bytes)) = tls.messages.pop_front() {
                tls.pending_bytes -= bytes.len();
                Poll::Ready(Ok((level, bytes)))
            } else {
                tls.message_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }

    pub(crate) async fn read_msg_at(&self, level: Epoch) -> Result<Bytes, Error> {
        poll_fn(|cx| {
            let mut guard = self.0.lock().unwrap();
            let tls = match guard.as_mut() {
                Ok(tls) => tls,
                Err(error) => return Poll::Ready(Err(error.clone())),
            };
            if let Some(index) = tls
                .messages
                .iter()
                .position(|(message_level, _)| *message_level == level)
            {
                let (_, bytes) = tls.messages.remove(index).unwrap();
                tls.pending_bytes -= bytes.len();
                Poll::Ready(Ok(bytes))
            } else {
                tls.level_wakers[level] = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }

    pub(crate) fn try_read_msg_at(&self, level: Epoch) -> Result<Option<Bytes>, Error> {
        let mut guard = self.0.lock().unwrap();
        let tls = guard.as_mut().map_err(|error| error.clone())?;
        let Some(index) = tls
            .messages
            .iter()
            .position(|(message_level, _)| *message_level == level)
        else {
            return Ok(None);
        };
        let (_, bytes) = tls.messages.remove(index).unwrap();
        tls.pending_bytes -= bytes.len();
        Ok(Some(bytes))
    }

    /// Feed contiguous CRYPTO input and publish all resulting facts without awaiting consumers.
    pub fn write_msg(&self, level: Epoch, bytes: &[u8]) -> Result<(), Error> {
        let mut guard = self.0.lock().unwrap();
        let tls = guard.as_mut().map_err(|error| error.clone())?;
        let result = tls.write(level, bytes);
        if let Err(error) = &result {
            tls.wake_all();
            *guard = Err(error.clone());
        }
        result
    }

    /// Wait for server parameters in EncryptedExtensions, after installing Handshake keys.
    pub async fn read_server_parameters(&self) -> Result<ServerParameters, Error> {
        let bytes = poll_fn(|cx| {
            let mut guard = self.0.lock().unwrap();
            let tls = match guard.as_mut() {
                Ok(tls) => tls,
                Err(error) => return Poll::Ready(Err(error.clone())),
            };
            if let Some(parameters) = tls.server_parameters.take() {
                Poll::Ready(Ok(parameters))
            } else {
                tls.server_parameters_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await?;
        Ok(ServerParameters::parse_from_bytes(&bytes)?)
    }

    /// The caller has already selected/configured the server TLS endpoint.
    /// A missing SNI is preserved for the caller's endpoint policy to decide.
    pub async fn read_client_hello(&self) -> Result<(Option<Arc<str>>, ClientParameters), Error> {
        let (name, bytes) = poll_fn(|cx| {
            let mut guard = self.0.lock().unwrap();
            let tls = match guard.as_mut() {
                Ok(tls) => tls,
                Err(error) => return Poll::Ready(Err(error.clone())),
            };
            if let Some(hello) = tls.client_hello.take() {
                Poll::Ready(Ok(hello))
            } else {
                tls.client_hello_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await?;
        Ok((name, ClientParameters::parse_from_bytes(&bytes)?))
    }

    /// Consume the next key installation; cancelling a pending wait consumes nothing.
    pub async fn read_keys(&self) -> Result<InstalledKeys, Error> {
        poll_fn(|cx| {
            let mut guard = self.0.lock().unwrap();
            let tls = match guard.as_mut() {
                Ok(tls) => tls,
                Err(error) => return Poll::Ready(Err(error.clone())),
            };
            if let Some(keys) = tls.keys.pop_front() {
                Poll::Ready(Ok(keys))
            } else {
                tls.key_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }

    /// Consume the authenticated result. This does not wait for QUIC HANDSHAKE_DONE.
    pub async fn finished(&self) -> Result<HandshakeSummary, Error> {
        poll_fn(|cx| {
            let mut guard = self.0.lock().unwrap();
            let tls = match guard.as_mut() {
                Ok(tls) => tls,
                Err(error) => return Poll::Ready(Err(error.clone())),
            };
            if let Some(summary) = tls.summary.take() {
                Poll::Ready(Ok(summary))
            } else {
                tls.finished_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }

    /// Wake every TLS consumer and release queued bytes and key material.
    pub fn on_error(&self, error: Error) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(tls) = guard.as_mut() {
            tls.wake_all();
            *guard = Err(error);
        }
    }
}

impl Tls {
    fn write(&mut self, level: Epoch, bytes: &[u8]) -> Result<(), Error> {
        match &mut self.backend {
            Backend::Handshake(tls) => tls.receive_crypto(level, bytes).map_err(tls_error)?,
            Backend::Established(tls) => {
                if level != Epoch::Data {
                    return Err(QuicError::with_default_fty(
                        ErrorKind::ProtocolViolation,
                        "post-handshake CRYPTO at an earlier encryption level",
                    )
                    .into());
                }
                return tls.receive_post_handshake(bytes).map_err(tls_error);
            }
            Backend::Closed => unreachable!("backend is moved under the context lock"),
        }
        self.collect()
    }

    fn collect(&mut self) -> Result<(), Error> {
        while let Backend::Handshake(tls) = &mut self.backend {
            let Some(event) = tls.next_event() else { break };
            match event {
                TlsEvent::WriteCrypto {
                    epoch: level,
                    bytes,
                } => {
                    if bytes.len() > self.max_pending_bytes - self.pending_bytes {
                        return Err(QuicError::with_default_fty(
                            ErrorKind::CryptoBufferExceeded,
                            "pending TLS output exceeds its byte limit",
                        )
                        .into());
                    }
                    self.pending_bytes += bytes.len();
                    self.messages.push_back((level, bytes));
                    if let Some(waker) = self.message_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = self.level_wakers[level].take() {
                        waker.wake();
                    }
                }
                TlsEvent::InstallKeys(keys) => {
                    self.keys.push_back(keys);
                    if let Some(waker) = self.key_waker.take() {
                        waker.wake();
                    }
                }
                TlsEvent::ClientHello {
                    server_name,
                    transport_parameters,
                } => {
                    self.client_hello = Some((server_name, transport_parameters));
                    if let Some(waker) = self.client_hello_waker.take() {
                        waker.wake();
                    }
                }
                TlsEvent::ServerTransportParameters(parameters) => {
                    self.server_parameters = Some(parameters);
                    if let Some(waker) = self.server_parameters_waker.take() {
                        waker.wake();
                    }
                }
                TlsEvent::HandshakeComplete(summary) => {
                    self.summary = Some(summary);
                    if let Some(waker) = self.finished_waker.take() {
                        waker.wake();
                    }
                }
                TlsEvent::Alert(alert) => return Err(tls_error(qtls::TlsError::Alert(alert))),
            }
        }
        if matches!(&self.backend, Backend::Handshake(tls) if tls.is_complete()) {
            let Backend::Handshake(tls) = std::mem::replace(&mut self.backend, Backend::Closed)
            else {
                unreachable!()
            };
            self.backend = Backend::Established(Box::new(tls.finish().expect("completed TLS")));
        }
        Ok(())
    }

    fn wake_all(&mut self) {
        for waker in [
            self.message_waker.take(),
            self.key_waker.take(),
            self.client_hello_waker.take(),
            self.server_parameters_waker.take(),
            self.finished_waker.take(),
        ]
        .into_iter()
        .flatten()
        {
            waker.wake();
        }
        for waker in self.level_wakers.iter_mut().filter_map(Option::take) {
            waker.wake();
        }
    }
}

pub(crate) fn tls_error(error: qtls::TlsError) -> Error {
    let kind = match &error {
        qtls::TlsError::Alert(alert) => ErrorKind::Crypto(alert.description()),
        qtls::TlsError::Peer(qtls::PeerTlsError::ResourceLimit { .. }) => {
            ErrorKind::CryptoBufferExceeded
        }
        qtls::TlsError::Peer(_) => ErrorKind::Crypto(40),
        _ => ErrorKind::Internal,
    };
    QuicError::with_default_fty(kind, error.to_string()).into()
}

/// One detached input coroutine per space. Retiring the reader ends only that space.
pub fn read_space_to_tls<K>(
    tls: TlsContext,
    space: &Space<K>,
    closed: ArcReceiving<CloseReason>,
) -> impl Future<Output = ()> + Send + 'static + use<K> {
    let epoch = space.epoch;
    let mut reader = space.crypto.reader();
    async move {
        let mut buffer = [0; 4096];
        while let Ok(length) = reader.read(&mut buffer).await {
            if length == 0 {
                break;
            }
            if let Err(error) = tls.write_msg(epoch, &buffer[..length]) {
                closed.with(error.into());
                break;
            }
        }
    }
}

/// One detached TLS output coroutine per space.
pub(crate) fn read_tls_to_space<K>(
    tls: TlsContext,
    space: &Space<K>,
    closed: ArcReceiving<CloseReason>,
) -> impl Future<Output = ()> + Send + 'static + use<K> {
    let epoch = space.epoch;
    let stream = space.crypto.clone();
    async move {
        loop {
            let bytes = match tls.read_msg_at(epoch).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    stream.on_error(&error);
                    closed.with(error.into());
                    break;
                }
            };
            if let Err(error) = stream.writer().write_all(&bytes).await {
                tls.on_error(
                    QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
                );
            }
        }
    }
}
