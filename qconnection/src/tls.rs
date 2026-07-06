mod authority;
mod client_auth;

use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

pub use authority::{LocalAuthority, RemoteAuthority, SignError, VerifyError};
pub use client_auth::{
    AcceptAllClientAuther, ArcSendLock, AuthClient, ClientAuthorityVerifyResult,
    ClientNameVerifyResult,
};
use futures::{future::poll_fn, never::Never};
use qbase::{
    Epoch,
    error::{Error, ErrorKind, QuicError},
    packet::keys::{ArcKeys, ArcOneRttKeys, ArcZeroRttKeys, DirectionalKeys},
    param::{ArcParameters, ClientParameters, ParameterId, ServerParameters, WriteParameters},
};
use qrecovery::crypto::CryptoStream;
use rustls::{
    ClientConfig, HandshakeKind, ServerConfig, SignatureScheme,
    client::ResolvesClientCert,
    quic::{ClientConnection, KeyChange, ServerConnection},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Handshake, tls::client_auth::ClientNameAuther};

pub enum TlsSession {
    Client(ClientTlsSession),
    Server(ServerTlsSession),
}

pub const QUIC_VERSION: rustls::quic::Version = rustls::quic::Version::V1;

impl TlsSession {
    fn poll_read_hs(&mut self, cx: &mut Context, buf: &mut Vec<u8>) -> Poll<Option<KeyChange>> {
        match match self {
            TlsSession::Client(session) => session.tls_conn.write_hs(buf),
            TlsSession::Server(session) => session.tls_conn.write_hs(buf),
        } {
            None if buf.is_empty() => {
                match self {
                    TlsSession::Client(session) => session.read_waker = Some(cx.waker().clone()),
                    TlsSession::Server(session) => session.read_waker = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
            key_change => Poll::Ready(key_change),
        }
    }

    fn write_hs(&mut self, buf: &[u8]) -> Result<(), rustls::Error> {
        match self {
            TlsSession::Client(ClientTlsSession { tls_conn, .. }) => tls_conn.read_hs(buf)?,
            TlsSession::Server(ServerTlsSession { tls_conn, .. }) => tls_conn.read_hs(buf)?,
        }
        if let Some(waker) = match self {
            TlsSession::Client(ClientTlsSession { read_waker, .. }) => read_waker.take(),
            TlsSession::Server(ServerTlsSession { read_waker, .. }) => read_waker.take(),
        } {
            waker.wake();
        }
        Ok(())
    }

    fn alert(&self) -> Option<rustls::AlertDescription> {
        match self {
            TlsSession::Client(session) => session.tls_conn.alert(),
            TlsSession::Server(session) => session.tls_conn.alert(),
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            TlsSession::Client(session) => session.tls_conn.is_handshaking(),
            TlsSession::Server(session) => session.tls_conn.is_handshaking(),
        }
    }

    fn handshake_kind(&self) -> Option<HandshakeKind> {
        match self {
            TlsSession::Client(session) => session.tls_conn.handshake_kind(),
            TlsSession::Server(session) => session.tls_conn.handshake_kind(),
        }
    }

    fn is_finished(&self) -> bool {
        !self.is_handshaking() && self.handshake_kind().is_some()
    }

    fn r#yield(&self) -> TlsHandshakeInfo {
        const INCOMPLETE: &str = "";
        match self {
            TlsSession::Client(tls_session) => TlsHandshakeInfo::Client {
                zero_rtt_accepted: tls_session.zero_rtt_accepted.expect(INCOMPLETE),
                local_authority: tls_session.local_authority().clone(),
                remote_authority: tls_session.remote_authority.clone().expect(INCOMPLETE),
            },
            TlsSession::Server(tls_session) => TlsHandshakeInfo::Server {
                local_authority: tls_session.local_authority().clone().expect(INCOMPLETE),
                remote_authority: tls_session.remote_authority.clone(),
            },
        }
    }
}

pub struct ClientTlsSession {
    server_name: String,
    tls_conn: ClientConnection,
    read_waker: Option<Waker>,

    // shared with ClientCertResolver
    local_authority: Arc<Mutex<Option<LocalAuthority>>>,
    zero_rtt_accepted: Option<bool>,
    remote_authority: Option<RemoteAuthority>,
}

#[derive(Debug, Clone)]
struct ClientCertResolver {
    client_name: Arc<str>,
    inner: Arc<dyn ResolvesClientCert>,
    client_authority: Arc<Mutex<Option<LocalAuthority>>>,
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.inner
            .resolve(root_hint_subjects, sigschemes)
            .inspect(|resolved_cert| {
                let client_authority =
                    LocalAuthority::new(self.client_name.clone(), resolved_cert.clone());
                let old = self
                    .client_authority
                    .lock()
                    .unwrap()
                    .replace(client_authority);
                assert!(
                    old.is_none(),
                    "unreachable: qconnection::tls::ClientCertResolver resolve only once"
                )
            })
    }

    fn only_raw_public_keys(&self) -> bool {
        self.inner.only_raw_public_keys()
    }

    fn has_certs(&self) -> bool {
        self.inner.has_certs()
    }
}

impl ClientTlsSession {
    pub fn init(
        server_name: String,
        mut tls_config: Arc<ClientConfig>,
        client_params: &ClientParameters,
    ) -> Result<Self, rustls::Error> {
        let mut params_buf = Vec::with_capacity(1024);
        params_buf.put_parameters(client_params);

        let local_authority = Arc::new(Mutex::new(None));
        // 通过注入ServerCertResolver实现CertifiedKey向上传递
        if let Some(client_name) = client_params.get::<String>(ParameterId::ClientName) {
            let tls_config = Arc::make_mut(&mut tls_config);
            tls_config.client_auth_cert_resolver = Arc::new(ClientCertResolver {
                client_name: client_name.into(),
                inner: tls_config.client_auth_cert_resolver.clone(),
                client_authority: local_authority.clone(),
            });
        };

        let name = rustls::pki_types::ServerName::try_from(server_name.clone())
            .map_err(|e| rustls::Error::Other(rustls::OtherError(Arc::new(e))))?;
        let tls_conn = ClientConnection::new(tls_config, QUIC_VERSION, name, params_buf)?;

        let tls_session = Self {
            local_authority,
            server_name,
            tls_conn,
            read_waker: None,
            zero_rtt_accepted: None,
            remote_authority: None,
        };
        Ok(tls_session)
    }

    fn local_authority(&self) -> MutexGuard<'_, Option<LocalAuthority>> {
        self.local_authority.lock().expect("Poison")
    }

    #[must_use]
    pub fn load_zero_rtt(&self) -> Option<(ServerParameters, DirectionalKeys)> {
        match (
            self.tls_conn.quic_transport_parameters(),
            self.tls_conn.zero_rtt_keys(),
        ) {
            (Some(raw_params), Some(keys)) => {
                let params = ServerParameters::parse_from_bytes(raw_params).ok()?;
                Some((params, keys.into()))
            }
            _ => None,
        }
    }

    fn try_process_sh(&mut self) {
        self.remote_authority = (self.tls_conn.peer_certificates())
            .map(|cert| RemoteAuthority::new(self.server_name.as_str().into(), Arc::from(cert)))
    }

    fn try_process_ee(&mut self, parameters: &ArcParameters) -> Result<(), Error> {
        let Some(handshake_kind) = self.tls_conn.handshake_kind() else {
            return Ok(());
        };
        let raw_params = self
            .tls_conn
            .quic_transport_parameters()
            .expect("Parameters must be known at this point");
        let mut parameters = parameters.lock_guard()?;
        let remebered = parameters.remembered().cloned();
        let params = ServerParameters::parse_from_bytes(raw_params)?;
        self.zero_rtt_accepted = Some(
            matches!(remebered, Some(remembered) if remembered.is_0rtt_accepted(&params))
                && matches!(handshake_kind, rustls::HandshakeKind::Resumed),
        );
        parameters.recv_remote_params(params)?;
        Ok(())
    }
}

impl Drop for ClientTlsSession {
    fn drop(&mut self) {
        if let Some(read_waker) = self.read_waker.take() {
            read_waker.wake();
        }
    }
}

pub struct ServerTlsSession {
    client_auther: Box<dyn AuthClient>,
    tls_conn: ServerConnection,
    read_waker: Option<Waker>,

    // shared with ServerCertResolver
    local_authority: Arc<Mutex<Option<LocalAuthority>>>,
    client_name: Option<Arc<str>>,
    send_lock: ArcSendLock,
    remote_authority: Option<RemoteAuthority>,
}

#[derive(Debug, Clone)]
struct ServerCertResolver {
    inner: Arc<dyn ResolvesServerCert>,
    server_authority: Arc<Mutex<Option<LocalAuthority>>>,
}

impl ResolvesServerCert for ServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?.into();
        self.inner.resolve(client_hello).inspect(|resolved_cert| {
            let server_authority = LocalAuthority::new(server_name, resolved_cert.clone());
            let old = self
                .server_authority
                .lock()
                .unwrap()
                .replace(server_authority);
            assert!(
                old.is_none(),
                "unreachable: qconnection::tls::ServerCertResolver resolve only once"
            )
        })
    }

    fn only_raw_public_keys(&self) -> bool {
        self.inner.only_raw_public_keys()
    }
}

impl ServerTlsSession {
    pub fn init(
        mut tls_config: Arc<ServerConfig>,
        server_params: &ServerParameters,
        client_auther: Box<dyn AuthClient>,
    ) -> Result<Self, rustls::Error> {
        let mut params_buf = Vec::with_capacity(1024);
        params_buf.put_parameters(server_params);

        let local_authority = Arc::new(Mutex::new(None));
        // 通过注入ServerCertResolver实现CertifiedKey向上传递
        {
            let tls_config = Arc::make_mut(&mut tls_config);
            tls_config.cert_resolver = Arc::new(ServerCertResolver {
                inner: tls_config.cert_resolver.clone(),
                server_authority: local_authority.clone(),
            });
        };
        let tls_conn = ServerConnection::new(tls_config, QUIC_VERSION, params_buf)?;

        let tls_session = Self {
            client_auther,
            tls_conn,
            read_waker: None,
            local_authority,
            client_name: None,
            send_lock: ArcSendLock::new(),
            remote_authority: None,
        };
        Ok(tls_session)
    }

    pub fn send_lock(&self) -> &ArcSendLock {
        &self.send_lock
    }

    fn local_authority(&self) -> MutexGuard<'_, Option<LocalAuthority>> {
        self.local_authority.lock().expect("Poison")
    }

    pub fn server_name(&self) -> Option<String> {
        Some(self.local_authority().as_ref()?.name().to_owned())
    }

    fn try_process_ch(
        &mut self,
        parameters: &ArcParameters,
        zero_rtt_keys: &ArcZeroRttKeys,
    ) -> Result<(), Error> {
        let client_params = ClientParameters::parse_from_bytes(
            self.tls_conn
                .quic_transport_parameters()
                .expect("Client parameters must be present in ClientHello"),
        )?;

        let client_name = client_params.get::<String>(ParameterId::ClientName);

        let server_authority = self.local_authority().clone().ok_or_else(|| {
            QuicError::with_default_fty(ErrorKind::ConnectionRefused, "missing SNI in client hello")
        })?;

        match self
            .client_auther
            .verify_client_name(&server_authority, client_name.as_deref())
        {
            ClientNameVerifyResult::Accept => {
                self.send_lock.grant_permit();
                tracing::debug!(
                    target: "dquic",
                    client_name = ?client_name.as_deref(),
                    "client name verification accepted"
                );
                self.client_name = client_name.map(Arc::from);
                parameters.lock_guard()?.recv_remote_params(client_params)?;

                match self.tls_conn.zero_rtt_keys() {
                    Some(keys) => zero_rtt_keys.set_keys(keys.into()),
                    None => _ = zero_rtt_keys.invalid(),
                }

                Ok(())
            }
            ClientNameVerifyResult::Refuse(reason) => {
                self.send_lock.grant_permit();
                tracing::debug!(
                    target: "dquic",
                    server_name = %server_authority.name(),
                    client_name = ?client_name.as_deref(),
                    ?reason,
                    "client name verification failed, refusing connection"
                );
                Err(Error::Quic(QuicError::with_default_fty(
                    ErrorKind::ConnectionRefused,
                    reason,
                )))
            }
            ClientNameVerifyResult::SilentRefuse(reason) => {
                tracing::debug!(
                    target: "dquic",
                    server_name = %server_authority.name(),
                    client_name = ?client_name.as_deref(),
                    ?reason,
                    "client name verification failed, refusing connection silently"
                );
                Err(Error::Quic(QuicError::with_default_fty(
                    ErrorKind::ConnectionRefused,
                    "",
                )))
            }
        }
    }

    fn try_process_cert(&mut self) -> Result<(), Error> {
        let Some(client_name) = self.client_name.as_ref() else {
            return Ok(());
        };
        let Some(client_cert) = self.tls_conn.peer_certificates().map(Arc::from) else {
            return Ok(());
        };

        let client_authority = RemoteAuthority::new(client_name.clone(), client_cert);

        let server_authority = self
            .local_authority()
            .clone()
            .expect("Server name must be known at this point");

        match (ClientNameAuther, &self.client_auther)
            .verify_client_authority(&server_authority, &client_authority)
        {
            ClientAuthorityVerifyResult::Accept => {
                self.remote_authority = Some(client_authority);
                Ok(())
            }
            ClientAuthorityVerifyResult::Refuse(reason) => {
                tracing::debug!(
                    target: "dquic",
                    server_name = %server_authority.name(),
                    ?self.client_name,
                    ?reason,
                    "client certificate verification failed, refusing connection"
                );
                Err(Error::Quic(QuicError::with_default_fty(
                    ErrorKind::ConnectionRefused,
                    reason,
                )))
            }
        }
    }
}

impl Drop for ServerTlsSession {
    fn drop(&mut self) {
        if let Some(read_waker) = self.read_waker.take() {
            read_waker.wake();
        }
    }
}

#[derive(Debug, Clone)]
pub enum TlsHandshakeInfo {
    Client {
        local_authority: Option<LocalAuthority>,
        remote_authority: RemoteAuthority,
        zero_rtt_accepted: bool,
    },
    Server {
        local_authority: LocalAuthority,
        remote_authority: Option<RemoteAuthority>,
    },
}

impl TlsHandshakeInfo {
    pub fn zero_rtt_accepted(&self) -> Option<bool> {
        match self {
            TlsHandshakeInfo::Client {
                zero_rtt_accepted, ..
            } => Some(*zero_rtt_accepted),
            TlsHandshakeInfo::Server { .. } => None,
        }
    }
}

enum InfoState {
    Demand(Vec<Waker>),
    Ready(Arc<TlsHandshakeInfo>),
}

impl InfoState {
    fn set(&mut self, info: Arc<TlsHandshakeInfo>) {
        // wakers woken in drop
        *self = Self::Ready(info);
    }

    fn poll_get(&mut self, cx: &mut Context) -> Poll<Arc<TlsHandshakeInfo>> {
        match self {
            InfoState::Demand(wakers) => {
                wakers.push(cx.waker().clone());
                Poll::Pending
            }
            InfoState::Ready(tls_handshake_info) => Poll::Ready(tls_handshake_info.clone()),
        }
    }

    fn get(&self) -> Option<&Arc<TlsHandshakeInfo>> {
        match self {
            InfoState::Demand(..) => None,
            InfoState::Ready(tls_handshake_info) => Some(tls_handshake_info),
        }
    }
}

impl Default for InfoState {
    fn default() -> Self {
        Self::Demand(vec![])
    }
}

impl Drop for InfoState {
    fn drop(&mut self) {
        if let Self::Demand(wakers) = self {
            for waker in wakers.drain(..) {
                waker.wake();
            }
        }
    }
}

pub struct TlsHandshake {
    session: TlsSession,
    info: InfoState,
}

#[derive(Clone)]
pub struct ArcTlsHandshake(Arc<Mutex<Result<TlsHandshake, Error>>>);

impl ArcTlsHandshake {
    pub fn new(session: TlsSession) -> ArcTlsHandshake {
        Self(Arc::new(Mutex::new(Ok(TlsHandshake {
            session,
            info: Default::default(),
        }))))
    }

    fn state(&self) -> MutexGuard<'_, Result<TlsHandshake, Error>> {
        self.0.lock().unwrap()
    }

    async fn read_hs(&self, buf: &mut Vec<u8>) -> Result<Option<KeyChange>, Error> {
        poll_fn(|cx| {
            let mut tls_handshake = self.state();
            match tls_handshake.as_mut() {
                Ok(state) => state.session.poll_read_hs(cx, buf).map(Ok),
                Err(e) => Poll::Ready(Err(e.clone())),
            }
        })
        .await
    }

    fn write_hs(&self, buf: &[u8]) -> Result<(), Error> {
        let mut tls_handshake = self.state();
        let tls_handshake = tls_handshake.as_mut().map_err(|e| e.clone())?;
        match tls_handshake.session.write_hs(buf) {
            Ok(_) => Ok(()),
            Err(error) => {
                let error_kind = match tls_handshake.session.alert() {
                    Some(alert) => ErrorKind::Crypto(alert.into()),
                    None => ErrorKind::ProtocolViolation,
                };
                Err(Error::Quic(QuicError::with_default_fty(
                    error_kind,
                    format!("tls error: {error}"),
                )))
            }
        }
    }

    pub fn info(
        &self,
    ) -> impl Future<Output = Result<Arc<TlsHandshakeInfo>, Error>> + Unpin + use<'_> {
        poll_fn(|cx| {
            let mut tls_handshake = self.state();
            match tls_handshake.as_mut() {
                Ok(state) => state.info.poll_get(cx).map(Ok),
                Err(e) => Poll::Ready(Err(e.clone())),
            }
        })
    }

    pub fn is_finished(&self) -> Result<bool, Error> {
        let tls_handshake = self.state();
        match tls_handshake.as_ref() {
            Ok(state) => Ok(state.session.is_finished()),
            Err(e) => Err(e.clone()),
        }
    }

    pub fn server_name(&self) -> Result<Option<String>, Error> {
        let tls_handshake = self.state();
        let tls_handshake = tls_handshake.as_ref().map_err(|error| error.clone())?;
        Ok(match &tls_handshake.session {
            TlsSession::Client(session) => Some(session.server_name.clone()),
            TlsSession::Server(session) => session.server_name(),
        })
    }

    pub fn on_conn_error(&self, error: &Error) {
        *self.state() = Err(error.clone())
    }

    fn try_process_tls_message(
        &self,
        parameters: &ArcParameters,
        zero_rtt_keys: &ArcZeroRttKeys,
    ) -> Result<Option<Arc<TlsHandshakeInfo>>, Error> {
        let mut state = self.state();
        let tls_handshake = state.as_mut().map_err(|e| e.clone())?;

        match &mut tls_handshake.session {
            TlsSession::Client(session) => {
                if session.remote_authority.is_none() {
                    session.try_process_sh();
                }
                if !parameters.lock_guard()?.is_remote_params_received() {
                    session.try_process_ee(parameters)?;
                }
            }
            TlsSession::Server(session) => {
                if !parameters.lock_guard()?.is_remote_params_received() {
                    session.try_process_ch(parameters, zero_rtt_keys)?;
                }
                if session.remote_authority.is_none() {
                    session.try_process_cert()?;
                }
            }
        }

        if tls_handshake.session.is_finished() && tls_handshake.info.get().is_none() {
            let info = Arc::new(tls_handshake.session.r#yield());
            tracing::debug!(target: "dquic", "tls handshake finished");
            tls_handshake.info.set(info.clone());
            return Ok(Some(info));
        }

        Ok(None)
    }

    pub fn start(
        self,
        parameters: ArcParameters,
        quic_handshake: Handshake,
        crypto_streams: [CryptoStream; 3],
        (handshake_keys, zero_rtt_keys, one_rtt_keys): (ArcKeys, ArcZeroRttKeys, ArcOneRttKeys),
        on_handshake_conmplete: impl FnOnce(&TlsHandshakeInfo) -> Result<(), Error> + Send + 'static,
    ) -> impl futures::Future<Output = Result<(), Error>> + Send + 'static {
        let mut on_handshake_conmplete = Some(on_handshake_conmplete);

        let crypto_read_task = |epoch: Epoch| {
            let tls_handshake = self.clone();
            let mut stream_reader = crypto_streams[epoch].reader();
            async move {
                let mut buf = [0; 2048];
                while let Ok(read) = stream_reader.read(&mut buf).await {
                    tls_handshake.write_hs(&buf[..read])?;
                }
                Result::<_, Error>::Ok(())
            }
        };

        let [initial_read_task, handshake_read_task, data_read_task] =
            Epoch::EPOCHS.map(|epoch: Epoch| crypto_read_task(epoch));

        let mut crypto_writers =
            Epoch::EPOCHS.map(|epoch: Epoch| crypto_streams[epoch].writer().clone());

        let crypto_write_task = async move {
            let mut buf = Vec::with_capacity(2048);
            let mut cur_epoch = Epoch::Initial;
            loop {
                let key_change = self.read_hs(&mut buf).await?;
                if !buf.is_empty() {
                    // error: crypto buffer offset overflow
                    (crypto_writers[cur_epoch].write_all(&buf).await).map_err(|e| {
                        QuicError::with_default_fty(ErrorKind::Internal, format!("{e:?}"))
                    })?;
                    buf.clear();
                }
                match key_change {
                    Some(KeyChange::Handshake { keys }) => {
                        handshake_keys.set_keys(keys.into());
                        quic_handshake.got_handshake_key();
                        cur_epoch = Epoch::Handshake;
                    }
                    Some(KeyChange::OneRtt { keys, next }) => {
                        one_rtt_keys.set_keys(keys, next);
                        cur_epoch = Epoch::Data;
                    }
                    None => {}
                };
                if let Some(info) = self.try_process_tls_message(&parameters, &zero_rtt_keys)? {
                    (on_handshake_conmplete.take().expect("TLS complete twice"))(&info)?;
                }
            }
        };

        // rustc: error[E0282]: type annotations needed
        let crypto_write_task = async move {
            let result: Result<Never, Error> = crypto_write_task.await;
            result
        };

        async move {
            tokio::try_join!(
                initial_read_task,
                handshake_read_task,
                data_read_task,
                crypto_write_task,
            )?;
            Ok(())
        }
    }
}
