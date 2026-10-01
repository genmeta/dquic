//! Complete, immutable transport parameters for both endpoints.
//!
//! CID requirements are collected independently during the handshake, before
//! both parameter sets are available. Parameter access never waits for the peer.
use std::{sync::Arc, time::Duration};

use crate::{
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
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
/// Whether client or server, construct these requirements with the SCID from
/// the peer's first authenticated Initial packet;
/// then after parsing the peer's Transport parameters, verify that
/// all these requirements are met.
/// If not met, it is considered a TransportParameters error.
#[derive(Debug, Clone, Copy)]
pub enum Requirements {
    Server {
        initial_scid: ConnectionId,
        retry_scid: Option<ConnectionId>,
        origin_dcid: ConnectionId,
    },
    Client {
        initial_scid: ConnectionId,
    },
}

impl Requirements {
    pub fn require_server(initial_scid: ConnectionId, origin_dcid: ConnectionId) -> Self {
        Self::Server {
            initial_scid,
            retry_scid: None,
            origin_dcid,
        }
    }

    pub fn require_client(initial_scid: ConnectionId) -> Self {
        Self::Client { initial_scid }
    }

    /// Record the SCID from an accepted Retry packet for later authentication.
    pub fn retry_scid_from_server_need_equal(&mut self, cid: ConnectionId) -> &mut Self {
        match self {
            Self::Server { retry_scid, .. } => *retry_scid = Some(cid),
            _ => unreachable!("not for server side"),
        }
        self
    }
}

#[derive(Debug, Clone)]
pub struct ArcParameters {
    role: Role,
    client: Arc<ClientParameters>,
    server: Arc<ServerParameters>,
    remembered: Option<Arc<ServerParameters>>,
}

fn param_error(reason: &'static str) -> QuicError {
    QuicError::new(
        ErrorKind::TransportParameter,
        FrameType::Crypto.into(),
        reason,
    )
}

impl ArcParameters {
    /// Both parameter sets are available immediately. Configure packet CID
    /// observations and authenticate them before exposing the connection.
    pub fn new(role: Role, client: Arc<ClientParameters>, server: Arc<ServerParameters>) -> Self {
        Self {
            role,
            client,
            server,
            remembered: None,
        }
    }

    /// Retain the client's previous server parameters as historical data.
    /// Current remote parameters are always available through `remote`.
    pub fn with_remembered(mut self, remembered: Option<Arc<ServerParameters>>) -> Self {
        assert_eq!(self.role(), Role::Client);
        self.remembered = remembered;
        self
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn client(&self) -> &ClientParameters {
        &self.client
    }

    pub fn server(&self) -> &ServerParameters {
        &self.server
    }

    pub fn remembered(&self) -> Option<&Arc<ServerParameters>> {
        self.remembered.as_ref()
    }

    pub fn local<V: TryFrom<ParameterValue>>(&self, id: ParameterId) -> V {
        match self.role() {
            Role::Client => self.client.get(id),
            Role::Server => self.server.get(id),
        }
    }

    pub fn remote<V: TryFrom<ParameterValue>>(&self, id: ParameterId) -> V {
        match self.role() {
            Role::Client => self.server.get(id),
            Role::Server => self.client.get(id),
        }
    }

    /// Authenticate the peer's parameters against independently collected CID
    /// requirements. Growing coroutines record the Initial SCID before calling this.
    pub fn authenticate_cids(&self, requirements: Requirements) -> Result<(), QuicError> {
        match (self.role, requirements) {
            (
                Role::Client,
                Requirements::Server {
                    initial_scid,
                    retry_scid,
                    origin_dcid,
                },
            ) => {
                if self
                    .server
                    .try_get::<ConnectionId>(ParameterId::InitialSourceConnectionId)
                    != Some(initial_scid)
                {
                    return Err(param_error(
                        "Initial Source Connection ID from server mismatch",
                    ));
                }
                if self
                    .server
                    .try_get::<ConnectionId>(ParameterId::OriginalDestinationConnectionId)
                    != Some(origin_dcid)
                {
                    return Err(param_error("Original Destination Connection ID mismatch"));
                }
                if self
                    .server
                    .try_get::<ConnectionId>(ParameterId::RetrySourceConnectionId)
                    != retry_scid
                {
                    return Err(param_error("Retry Source Connection ID mismatch"));
                }
            }
            (Role::Server, Requirements::Client { initial_scid }) => {
                if self
                    .client
                    .try_get::<ConnectionId>(ParameterId::InitialSourceConnectionId)
                    != Some(initial_scid)
                {
                    return Err(param_error(
                        "Initial Source Connection ID from client mismatch",
                    ));
                }
            }
            _ => {
                return Err(param_error(
                    "Connection ID requirements do not match endpoint role",
                ));
            }
        }
        Ok(())
    }

    /// The minimum nonzero advertised timeout, or `Duration::MAX` if disabled
    /// by both endpoints (RFC 9000, section 10.1).
    pub fn negotiated_max_idle_timeout(&self) -> Duration {
        match (
            self.local(ParameterId::MaxIdleTimeout),
            self.remote(ParameterId::MaxIdleTimeout),
        ) {
            (Duration::ZERO, Duration::ZERO) => Duration::MAX,
            (Duration::ZERO, d) | (d, Duration::ZERO) => d,
            (d1, d2) => d1.min(d2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters(role: Role) -> ArcParameters {
        let mut client = ClientParameters::default();
        client
            .set(
                ParameterId::InitialSourceConnectionId,
                ConnectionId::from_slice(b"client"),
            )
            .unwrap();
        client.set(ParameterId::InitialMaxData, 11u32).unwrap();
        let mut server = ServerParameters::default();
        server
            .set(
                ParameterId::InitialSourceConnectionId,
                ConnectionId::from_slice(b"server"),
            )
            .unwrap();
        server
            .set(
                ParameterId::OriginalDestinationConnectionId,
                ConnectionId::from_slice(b"origin"),
            )
            .unwrap();
        server.set(ParameterId::InitialMaxData, 22u32).unwrap();
        ArcParameters::new(role, Arc::new(client), Arc::new(server))
    }

    fn requirements(role: Role, initial_scid: ConnectionId) -> Requirements {
        match role {
            Role::Client => {
                Requirements::require_server(initial_scid, ConnectionId::from_slice(b"origin"))
            }
            Role::Server => Requirements::require_client(initial_scid),
        }
    }

    #[test]
    fn both_parameter_sets_are_immediately_available_for_both_roles() {
        for role in [Role::Client, Role::Server] {
            let params = parameters(role);
            assert_eq!(params.client().get::<u64>(ParameterId::InitialMaxData), 11);
            assert_eq!(params.server().get::<u64>(ParameterId::InitialMaxData), 22);
            let expected = if role == Role::Client {
                (11, 22)
            } else {
                (22, 11)
            };
            assert_eq!(
                (
                    params.local::<u64>(ParameterId::InitialMaxData),
                    params.remote::<u64>(ParameterId::InitialMaxData)
                ),
                expected
            );
            assert!(params.remembered().is_none());
        }
    }

    #[test]
    fn requirements_can_be_prepared_before_parameters() {
        for (role, cid) in [(Role::Client, b"server"), (Role::Server, b"client")] {
            let requirements = requirements(role, ConnectionId::from_slice(cid));
            let params = parameters(role);
            assert_eq!(params.authenticate_cids(requirements), Ok(()));
            assert_eq!(params.clone().authenticate_cids(requirements), Ok(()));
        }
    }

    #[test]
    fn initial_cid_mismatches_return_transport_parameter_errors() {
        for role in [Role::Client, Role::Server] {
            let requirements = requirements(role, ConnectionId::from_slice(b"wrong"));
            let params = parameters(role);
            let reason = if role == Role::Client {
                "Initial Source Connection ID from server mismatch"
            } else {
                "Initial Source Connection ID from client mismatch"
            };
            assert_eq!(
                params.authenticate_cids(requirements),
                Err(param_error(reason))
            );
        }
    }

    #[test]
    fn missing_initial_cids_return_errors_instead_of_panicking() {
        for role in [Role::Client, Role::Server] {
            let requirements = requirements(role, ConnectionId::default());
            let mut params = parameters(role);
            match role {
                Role::Client => params.server = Arc::default(),
                Role::Server => params.client = Arc::default(),
            }
            assert!(params.authenticate_cids(requirements).is_err());
        }
    }

    #[test]
    fn original_dcid_requires_an_independent_matching_observation() {
        let requirements = Requirements::require_server(
            ConnectionId::from_slice(b"server"),
            ConnectionId::from_slice(b"wrong"),
        );
        let mut params = parameters(Role::Client);
        assert_eq!(
            params.authenticate_cids(requirements),
            Err(param_error("Original Destination Connection ID mismatch"))
        );

        let requirements = Requirements::require_server(
            ConnectionId::from_slice(b"server"),
            ConnectionId::from_slice(b"origin"),
        );
        Arc::make_mut(&mut params.server)
            .map
            .remove(&ParameterId::OriginalDestinationConnectionId);
        assert!(params.authenticate_cids(requirements).is_err());
    }

    #[test]
    fn retry_cid_must_match_presence_and_value() {
        let retry = ConnectionId::from_slice(b"retry");
        for advertised in [None, Some(retry), Some(ConnectionId::from_slice(b"wrong"))] {
            for received_retry in [false, true] {
                let mut requirements =
                    requirements(Role::Client, ConnectionId::from_slice(b"server"));
                if received_retry {
                    requirements.retry_scid_from_server_need_equal(retry);
                }
                let mut params = parameters(Role::Client);
                if let Some(cid) = advertised {
                    Arc::make_mut(&mut params.server)
                        .set(ParameterId::RetrySourceConnectionId, cid)
                        .unwrap();
                }
                let expected = if advertised == received_retry.then_some(retry) {
                    Ok(())
                } else {
                    Err(param_error("Retry Source Connection ID mismatch"))
                };
                assert_eq!(params.authenticate_cids(requirements), expected);
            }
        }
    }

    #[test]
    fn requirements_must_match_the_endpoint_role() {
        for role in [Role::Client, Role::Server] {
            let wrong_role = if role == Role::Client {
                Role::Server
            } else {
                Role::Client
            };
            let requirements = requirements(
                wrong_role,
                ConnectionId::from_slice(if wrong_role == Role::Client {
                    b"server"
                } else {
                    b"client"
                }),
            );
            let params = parameters(role);
            assert!(params.authenticate_cids(requirements).is_err());
        }
    }

    #[test]
    fn remembered_parameters_survive_authentication_and_cloning() {
        let requirements = requirements(Role::Client, ConnectionId::from_slice(b"server"));
        let remembered = Arc::new(ServerParameters::default());
        let params = parameters(Role::Client).with_remembered(Some(remembered.clone()));
        assert_eq!(params.authenticate_cids(requirements), Ok(()));
        let cloned = params.clone();
        assert!(Arc::ptr_eq(params.remembered().unwrap(), &remembered));
        assert!(Arc::ptr_eq(cloned.remembered().unwrap(), &remembered));
        assert_eq!(params.remote::<u64>(ParameterId::InitialMaxData), 22);
        assert!(params.with_remembered(None).remembered().is_none());
    }

    #[test]
    fn idle_timeout_is_symmetric_and_uses_the_minimum_nonzero_value() {
        let short = Duration::from_secs(3);
        let long = Duration::from_secs(9);
        for role in [Role::Client, Role::Server] {
            for (client, server, expected) in [
                (Duration::ZERO, Duration::ZERO, Duration::MAX),
                (Duration::ZERO, short, short),
                (short, Duration::ZERO, short),
                (short, long, short),
                (long, short, short),
            ] {
                let mut params = parameters(role);
                Arc::make_mut(&mut params.client)
                    .set(ParameterId::MaxIdleTimeout, client)
                    .unwrap();
                Arc::make_mut(&mut params.server)
                    .set(ParameterId::MaxIdleTimeout, server)
                    .unwrap();
                assert_eq!(params.negotiated_max_idle_timeout(), expected);
            }
        }
    }

    #[test]
    fn get_returns_defaults_and_try_get_preserves_absence() {
        let mut params = ClientParameters::new();
        assert_eq!(params.get::<u64>(ParameterId::InitialMaxData), 0);
        assert!(!params.get::<bool>(ParameterId::DisableActiveMigration));
        assert_eq!(
            params.try_get::<ConnectionId>(ParameterId::InitialSourceConnectionId),
            None
        );

        let scid = ConnectionId::from_slice(b"client");
        params
            .set(ParameterId::InitialSourceConnectionId, scid)
            .unwrap();
        assert_eq!(
            params.get::<ConnectionId>(ParameterId::InitialSourceConnectionId),
            scid
        );
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
}
