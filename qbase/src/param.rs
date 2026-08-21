use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Duration,
};

use crate::{
    cid::ConnectionId,
    error::{Error, ErrorKind, QuicError},
    frame::FrameType,
    role::Role,
};

pub mod core;
pub mod error;
pub mod handy;
pub mod io;
pub mod preferred_address;

pub use self::{
    core::{
        ClientParameters, ParameterId, ParameterValue, ParameterValueType, PeerParameters,
        ServerParameters,
    },
    io::*,
};

/// Requires that the connection IDs in the transport parameters of
/// the received Initial packet must match those used during the
/// connection establishment process.
///
/// For the Initial packet received by the server from the client,
/// the initial_source_connection_id in the client's Transport
/// parameters must match the source connection id in that Initial packet.
/// For the Initial packet received by the client from the server,
/// not only must the server's Transport parameter
/// initial_source_connection_id match the source connection id
/// in that Initial packet,
/// but also requires that the original_destination_connection_id matches the
/// destination connection id in the first packet sent by the client.
/// Specifically, if the server has responded with a Retry packet,
/// then the server's Transport parameter retry_source_connection_id
/// must match the source connection id in that Retry packet.
///
/// See [Authenticating Connection IDs](https://datatracker.ietf.org/doc/html/rfc9000#name-authenticating-connection-i)
/// of [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000)
/// for more details.
///
/// Whether client or server, after receiving the Initial packet from
/// the peer, these requirements must be set;
/// then after parsing the peer's Transport parameters, verify that
/// all these requirements are met.
/// If not met, it is considered a TransportParameters error.
#[derive(Debug, Clone, Copy)]
enum Requirements {
    Client {
        initial_scid: Option<ConnectionId>,
        retry_scid: Option<ConnectionId>,
        origin_dcid: ConnectionId,
    },
    Server {
        initial_scid: Option<ConnectionId>,
    },
}

/// Transport parameters for QUIC.
/// The transport parameters are used to negotiate the initial
/// settings of a QUIC connection.
///
/// They are exchanged in the Initial packets of the handshake,
/// including client and server transport parameters.
/// Client transport parameters and server transport parameters
/// exist independently and are not merged.
/// They each constrain the behavior of the remote peer.
///
/// For different roles, local transport parameters and remote
/// transport parameters differ.
/// For example, as a client, the local transport parameters
/// are client parameters, while remote transport parameters
/// are server parameters. The same applies to the server.
///
/// Note that client transport parameters and server transport
/// parameters are different, as some transport parameters can
/// only appear in server transport parameters.
/// Therefore, for a QUIC connection, the transport parameter
/// sets for both ends are defined as follows.
#[derive(Debug)]
pub struct Parameters {
    state: u8,
    client: Arc<ClientParameters>,
    server: Arc<ServerParameters>,
    remembered: Option<Arc<ServerParameters>>,
    requirements: Requirements,
    wakers: Vec<Waker>,
}

impl Drop for Parameters {
    fn drop(&mut self) {
        self.wake_all();
    }
}

impl Parameters {
    const CLIENT_READY: u8 = 1;
    const SERVER_READY: u8 = 2;

    /// Creates a new client transport parameters, with the client
    /// parameters and remembered server parameters if exist.
    ///
    /// It will wait for the server transport parameters to be
    /// received and parsed.
    pub fn new_client(
        client: ClientParameters,
        remembered: Option<ServerParameters>,
        origin_dcid: ConnectionId,
    ) -> Self {
        Self {
            state: Self::CLIENT_READY,
            client: Arc::new(client),
            server: Arc::default(),
            remembered: remembered.map(Arc::new),
            requirements: Requirements::Client {
                origin_dcid,
                initial_scid: None,
                retry_scid: None,
            },
            wakers: Vec::with_capacity(2),
        }
    }

    /// Creates a new server transport parameters, with the server
    /// parameters.
    ///
    /// It will wait for the client transport parameters to be
    /// received and parsed.
    pub fn new_server(server: ServerParameters) -> Self {
        Self {
            state: Self::SERVER_READY,
            client: Arc::default(),
            server: Arc::new(server),
            remembered: None,
            requirements: Requirements::Server { initial_scid: None },
            wakers: Vec::with_capacity(2),
        }
    }

    pub fn role(&self) -> Role {
        match self.requirements {
            Requirements::Client { .. } => Role::Client,
            Requirements::Server { .. } => Role::Server,
        }
    }

    pub fn client(&self) -> Option<&Arc<ClientParameters>> {
        if self.state & Self::CLIENT_READY != 0 {
            Some(&self.client)
        } else {
            None
        }
    }

    pub fn server(&self) -> Option<&Arc<ServerParameters>> {
        if self.state & Self::SERVER_READY != 0 {
            Some(&self.server)
        } else {
            None
        }
    }

    /// Returns the remembered server transport parameters if exist,
    /// which means the client connected the server, and stored the
    /// server transport parameters.
    ///
    /// It is meaningful only for the client, to send early data
    /// with 0Rtt packets before receving the server transport params.
    pub fn remembered(&self) -> Option<&Arc<ServerParameters>> {
        self.remembered.as_ref()
    }

    pub fn get_local<V: TryFrom<ParameterValue>>(&self, id: ParameterId) -> Option<V> {
        match self.role() {
            Role::Client => self.client()?.get(id),
            Role::Server => self.server()?.get(id),
        }
    }

    pub fn get_remote<V: TryFrom<ParameterValue>>(&self, id: ParameterId) -> Option<V> {
        match self.role() {
            Role::Client => self.server()?.get(id),
            Role::Server => self.client()?.get(id),
        }
    }

    // fn set_retry_scid(&mut self, cid: ConnectionId) {
    //     assert_eq!(self.role(), Role::Server);
    //     self.server.set_retry_source_connection_id(cid);
    // }

    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.state == Self::CLIENT_READY | Self::SERVER_READY {
            Poll::Ready(())
        } else {
            self.wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn is_remote_params_received(&self) -> bool {
        match self.role() {
            Role::Client => !self.server.is_empty(),
            Role::Server => !self.client.is_empty(),
        }
    }

    /// Returns true if the remote transport parameters have been received and authed.
    ///
    /// It is usually used to avoid processing remote transport parameters
    /// more than once.
    pub fn is_remote_params_ready(&self) -> bool {
        self.state == Self::CLIENT_READY | Self::SERVER_READY
    }

    /// Being called when the remote transport parameters are received.
    /// It will parse and check the remote transport parameters,
    /// and wake all the wakers waiting for the remote transport parameters
    /// if the remote transport parameters are valid.
    pub fn recv_remote_params(
        &mut self,
        params: impl Into<PeerParameters>,
    ) -> Result<(), QuicError> {
        match params.into() {
            PeerParameters::Client(p) => {
                assert_eq!(self.role(), Role::Server);
                assert!(self.client.is_empty());
                self.client = Arc::new(p);
            }
            PeerParameters::Server(p) => {
                assert_eq!(self.role(), Role::Client);
                assert!(self.server.is_empty());
                self.server = Arc::new(p);
            }
        }

        // Because TLS and packet parsing are in parallel,
        // the scid of the peer end may not be set when the transmission parameters of the peer are obtained.
        // Therefore, if the scid of the other end is not set, authentication will not be performed first,
        // and authentication will be performed when it is set.
        if self.authenticate_cids()? {
            self.state = Self::CLIENT_READY | Self::SERVER_READY;
            self.remembered.take();
            self.wake_all();
            return Ok(());
        }

        Ok(())
    }

    fn wake_all(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    /// No matter the client or server, after receiving the Initial
    /// packet from the peer, the initial_source_connection_id in
    /// the remote transport parameters must equal the source connection
    /// id in the received Initial packet.
    ///
    /// If the peer's transmission parameters have not been verified,
    /// it will be verified here. If verification fails, this method will
    /// return Err.
    pub fn initial_scid_from_peer_need_equal(
        &mut self,
        cid: ConnectionId,
    ) -> Result<(), QuicError> {
        let initial_scid = match &mut self.requirements {
            Requirements::Client { initial_scid, .. } => initial_scid,
            Requirements::Server { initial_scid } => initial_scid,
        };
        assert!(initial_scid.replace(cid).is_none());

        // Because the TLS handshak and packet parsing are in parallel,
        // the scid of the peer end may not be set when the transmission parameters of the peer are obtained.
        // Therefore, if the scid of the other end is not set, authentication will not be performed first,
        // and authentication will be performed when it is set.
        if self.is_remote_params_received() && self.authenticate_cids()? {
            self.state = Self::CLIENT_READY | Self::SERVER_READY;
            self.remembered.take();
            self.wake_all();
            return Ok(());
        }

        Ok(())
    }

    /// After receiving the Retry packet from the server, the
    /// retry_source_connection_id in the server transport parameters
    /// must equal the source connection id in the Retry packet.
    pub fn retry_scid_from_server_need_equal(&mut self, cid: ConnectionId) {
        match &mut self.requirements {
            Requirements::Client { retry_scid, .. } => *retry_scid = Some(cid),
            Requirements::Server { .. } => panic!("server shuold never call this"),
        }
    }

    pub fn initial_scid_from_peer(&self) -> Option<ConnectionId> {
        match self.requirements {
            Requirements::Client { initial_scid, .. } => initial_scid,
            Requirements::Server { initial_scid, .. } => initial_scid,
        }
    }

    fn authenticate_cids(&self) -> Result<bool, QuicError> {
        fn param_error(reason: &'static str) -> QuicError {
            QuicError::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto.into(),
                reason,
            )
        }

        // Because TLS and packet parsing are in parallel,
        // the scid of the peer end may not be set when the transmission parameters of the peer are obtained.
        // Therefore, if the scid of the other end is not set, authentication will not be performed first,
        // and authentication will be performed when it is set.
        match self.requirements {
            Requirements::Client {
                initial_scid,
                retry_scid: _,
                origin_dcid,
            } => {
                let Some(initial_scid) = initial_scid else {
                    return Ok(false);
                };
                if self
                    .server
                    .get::<ConnectionId>(ParameterId::InitialSourceConnectionId)
                    .expect("this value must be set")
                    != initial_scid
                {
                    return Err(param_error(
                        "Initial Source Connection ID from server mismatch",
                    ));
                }
                // 并不正确，要和intiial_scid一样地去验证
                // if self.server.retry_source_connection_id() != retry_scid {
                //     return Err(param_error("Retry Source Connection ID mismatch"));
                // }
                if self
                    .server
                    .get::<ConnectionId>(ParameterId::OriginalDestinationConnectionId)
                    .expect("this value must be set")
                    != origin_dcid
                {
                    return Err(param_error("Original Destination Connection ID mismatch"));
                }
                Ok(true)
            }
            Requirements::Server { initial_scid } => {
                let Some(initial_scid) = initial_scid else {
                    return Ok(false);
                };
                if self
                    .client
                    .get::<ConnectionId>(ParameterId::InitialSourceConnectionId)
                    .expect("this value must be set")
                    != initial_scid
                {
                    return Err(param_error(
                        "Initial Source Connection ID from client mismatch",
                    ));
                }
                Ok(true)
            }
        }
    }

    /// Returns None if the remote parameters are not ready.
    pub fn negotiated_max_idle_timeout(&self) -> Option<Duration> {
        let local_max_idle_timeout = self.get_local(ParameterId::MaxIdleTimeout)?;
        let remote_max_idle_timeout = self.get_remote(ParameterId::MaxIdleTimeout)?;

        Some(match (local_max_idle_timeout, remote_max_idle_timeout) {
            // rfc: https://datatracker.ietf.org/doc/html/rfc9000#name-idle-timeout
            // Each endpoint advertises a max_idle_timeout, but the effective value
            // at an endpoint is computed as the minimum of the two advertised
            // values (or the sole advertised value, if only one endpoint advertises
            // a non-zero value). By announcing a max_idle_timeout, an endpoint
            // commits to initiating an immediate close (Section 10.2) if
            // it abandons the connection prior to the effective value.
            (Duration::ZERO, Duration::ZERO) => Duration::MAX,
            (Duration::ZERO, d) | (d, Duration::ZERO) => d,
            // rfc: https://datatracker.ietf.org/doc/html/rfc9000#name-idle-timeout
            // If a max_idle_timeout is specified by either endpoint in its
            // transport parameters (Section 18.2), the connection is silently
            // closed and its state is discarded when it remains idle for longer
            // than the minimum of the max_idle_timeout value advertised by both
            // endpoints.
            (d1, d2) => d1.min(d2),
        })
    }
}

/// Shared transport parameter sets for both endpoints.
///
/// The local transport parameters are set initially, while
/// the remote transport parameters must wait until they are
/// received through network transmission and can be parsed.
/// After parsing, the peer parameters must be immediately
/// verified to ensure they meet the requirements and validity
/// checks.
///
/// Note that a connection error may occur before receiving
/// the remote transport parameters, such as network unreachable.
/// In such cases, the entire connection parameters will be
/// converted into an error state.
#[derive(Debug, Clone)]
pub struct ArcParameters(Arc<Mutex<Result<Parameters, Error>>>);

// ArcParameters::lock_guard(&self) -> Result<ArcParametersGuard, Error>;
// pub struct ArcParametersGuard: impl Deref<Target = Parameters>

pub struct ParametersGuard<'a>(MutexGuard<'a, Result<Parameters, Error>>);

impl Deref for ParametersGuard<'_> {
    type Target = Parameters;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("parameters must be valid")
    }
}

impl DerefMut for ParametersGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("parameters must be valid")
    }
}

impl From<Parameters> for ArcParameters {
    fn from(params: Parameters) -> Self {
        Self(Arc::new(Mutex::new(Ok(params))))
    }
}

impl ArcParameters {
    #[inline]
    pub fn lock_guard(&self) -> Result<ParametersGuard<'_>, Error> {
        let guard = self.0.lock().unwrap();
        match guard.as_ref() {
            Ok(_) => Ok(ParametersGuard(guard)),
            Err(e) => Err(e.clone()),
        }
    }

    #[inline]
    pub async fn remote_ready(&self) -> Result<ParametersGuard<'_>, Error> {
        std::future::poll_fn(|cx| {
            let mut parameters = self.lock_guard()?;
            parameters.poll_ready(cx).map(|()| Ok(parameters))
        })
        .await
    }

    // /// Sets the retry source connection ID in the server
    // /// transport parameters.
    // ///
    // /// It is meaningful only for the client, because only
    // /// server can send the Retry packet.
    // pub fn set_retry_scid(&self, cid: ConnectionId) {
    //     let mut guard = self.0.lock().unwrap();
    //     if let Ok(params) = guard.deref_mut() {
    //         params.set_retry_scid(cid);
    //     }
    // }

    /// When some connection error occurred, convert this parameters
    /// into error state.
    pub fn on_conn_error(&self, error: &Error) {
        let mut guard = self.0.lock().unwrap();
        if guard.deref_mut().is_ok() {
            *guard = Err(error.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::varint::VarInt;

    fn create_test_client_params() -> ClientParameters {
        let mut params = ClientParameters::default();
        params
            .set(
                ParameterId::InitialSourceConnectionId,
                ConnectionId::from_slice(b"client_test"),
            )
            .unwrap();
        params
    }

    fn create_test_server_params() -> ServerParameters {
        let mut params = ServerParameters::default();
        params
            .set(
                ParameterId::InitialSourceConnectionId,
                ConnectionId::from_slice(b"server_test"),
            )
            .unwrap();
        params
            .set(
                ParameterId::OriginalDestinationConnectionId,
                ConnectionId::from_slice(b"original"),
            )
            .unwrap();
        params
    }

    #[test]
    fn test_parameters_new() {
        let client_params = create_test_client_params();
        let params =
            Parameters::new_client(client_params, None, ConnectionId::from_slice(b"odcid"));
        assert_eq!(params.role(), Role::Client);
        assert_eq!(params.state, Parameters::CLIENT_READY);

        let server_params = create_test_server_params();
        let params = Parameters::new_server(server_params);
        assert_eq!(params.role(), Role::Server);
        assert_eq!(params.state, Parameters::SERVER_READY);
    }

    #[test]
    fn test_authenticate_cids() {
        let client_params = create_test_client_params();

        let odcid = ConnectionId::from_slice(b"odcid");

        let mut params = Parameters::new_client(client_params, None, odcid);

        let server_cid = ConnectionId::from_slice(b"server_test");
        params
            .initial_scid_from_peer_need_equal(server_cid)
            .unwrap();

        params.server = Arc::new({
            let mut server_params = ServerParameters::default();
            server_params
                .set(ParameterId::InitialSourceConnectionId, server_cid)
                .unwrap();
            server_params
                .set(ParameterId::OriginalDestinationConnectionId, odcid)
                .unwrap();
            server_params
        });

        assert!(params.authenticate_cids().is_ok());
    }

    #[test]
    fn test_parameters_as_client() {
        let client_params = create_test_client_params();
        let arc_params = ArcParameters::from(Parameters::new_client(
            client_params,
            None,
            ConnectionId::from_slice(b"odcid"),
        ));

        // Test accessing parameters through lock_guard
        let guard = arc_params.lock_guard().unwrap();

        // Test local params
        assert!(matches!(
            guard.get_local::<VarInt>(ParameterId::MaxUdpPayloadSize),
            Some(value) if value.into_u64() >= 1200
        ));

        // Test remembered params
        assert!(guard.remembered().is_none());
    }

    #[test]
    fn test_validate_remote_params() {
        // Test invalid max_udp_payload_size
        assert_eq!(
            ClientParameters::parse_from_bytes(&[
                1, 1, 0, // max_idle_timeout
                3, 2, 0x43, 0xE8, // max_udp_payload_size: 1000
                4, 1, 0, // initial_max_data
                5, 1, 0, // initial_max_stream_data_bidi_local
                6, 1, 0, // initial_max_stream_data_bidi_remote
                7, 1, 0, // initial_max_stream_data_uni
                8, 1, 0, // initial_max_streams_bidi
                9, 1, 0, // initial_max_streams_uni
                10, 1, 3, // ack_delay_exponent
                11, 1, 25, // max_ack_delay
                14, 1, 2, // active_connection_id_limit
                15, 0, // initial_source_connection_id
                32, 4, 128, 0, 255, 255, // max_datagram_frame_size
            ]),
            Err(QuicError::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto.into(),
                "MaxUdpPayloadSize's value 1000 is out of bounds 1200..=65527",
            ))
        );
    }

    #[test]
    fn test_write_parameters() {
        let client_params = create_test_client_params();
        let params = ArcParameters::from(Parameters::new_client(
            client_params,
            None,
            ConnectionId::from_slice(b"odcid"),
        ));

        // Test that we can access the parameters
        let guard = params.lock_guard().unwrap();
        assert_eq!(guard.role(), Role::Client);
    }

    #[test]
    fn negotiated_idle_timeout_covers_all_zero_and_nonzero_combinations() {
        fn negotiated(local: Duration, remote: Duration) -> Duration {
            let mut client = create_test_client_params();
            client
                .set(ParameterId::MaxIdleTimeout, local)
                .expect("valid idle timeout");
            let mut server = create_test_server_params();
            server
                .set(ParameterId::MaxIdleTimeout, remote)
                .expect("valid idle timeout");

            let mut params =
                Parameters::new_client(client, None, ConnectionId::from_slice(b"odcid"));
            params.server = Arc::new(server);
            params.state = Parameters::CLIENT_READY | Parameters::SERVER_READY;
            params
                .negotiated_max_idle_timeout()
                .expect("both parameter sets are ready")
        }

        let short = Duration::from_secs(3);
        let long = Duration::from_secs(9);
        assert_eq!(negotiated(Duration::ZERO, Duration::ZERO), Duration::MAX);
        assert_eq!(negotiated(Duration::ZERO, short), short);
        assert_eq!(negotiated(short, Duration::ZERO), short);
        assert_eq!(negotiated(long, short), short);
    }

    #[tokio::test]
    async fn test_arc_parameters_error_handling() {
        let arc_params = ArcParameters::from(Parameters::new_client(
            create_test_client_params(),
            None,
            ConnectionId::from_slice(b"odcid"),
        ));

        // Simulate connection error
        let error = QuicError::new(
            ErrorKind::TransportParameter,
            FrameType::Crypto.into(),
            "test error",
        )
        .into();
        arc_params.on_conn_error(&error);

        assert!(arc_params.lock_guard().is_err());
    }
}
