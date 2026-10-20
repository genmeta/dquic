#[path = "param/io.rs"]
mod io;

use std::{sync::Arc, time::Duration};

use qbase::{
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::FrameType,
    param::*,
    role::Role,
};

#[test]
fn local_defaults_advertise_usable_flow_control_and_role_timeouts() {
    fn check<R>(params: &core::Parameters<R>, timeout: u64) {
        for (id, expected) in [
            (ParameterId::InitialMaxStreamsBidi, 100),
            (ParameterId::InitialMaxStreamsUni, 100),
            (ParameterId::InitialMaxData, 1 << 20),
            (ParameterId::InitialMaxStreamDataBidiLocal, 1 << 20),
            (ParameterId::InitialMaxStreamDataBidiRemote, 1 << 20),
            (ParameterId::InitialMaxStreamDataUni, 1 << 20),
            (ParameterId::ActiveConnectionIdLimit, 10),
        ] {
            assert!(params.contains(id), "{id:?} must be advertised");
            assert_eq!(params.get::<u64>(id), expected);
        }
        assert_eq!(
            params.get::<Duration>(ParameterId::MaxIdleTimeout),
            Duration::from_secs(timeout)
        );
        assert!(!params.contains(ParameterId::InitialSourceConnectionId));
    }
    check(&ClientParameters::default(), 20);
    check(&ServerParameters::default(), 30);
}

#[test]
fn absent_peer_parameters_keep_protocol_defaults() {
    fn check<R>(params: &core::Parameters<R>) {
        assert!(!params.contains(ParameterId::InitialMaxData));
        assert_eq!(params.get::<u64>(ParameterId::InitialMaxData), 0);
        assert_eq!(params.get::<u64>(ParameterId::InitialMaxStreamsBidi), 0);
        assert_eq!(params.get::<u64>(ParameterId::ActiveConnectionIdLimit), 2);
        assert_eq!(
            params.get::<Duration>(ParameterId::MaxIdleTimeout),
            Duration::ZERO
        );
    }
    check(&ClientParameters::parse_from_bytes(&[15, 0]).unwrap());
    check(&ServerParameters::parse_from_bytes(&[0, 0, 15, 0]).unwrap());
    check(&ServerParameters::try_from_remembered_bytes(&[]).unwrap());
}

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
            Err(QuicError::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto.into(),
                reason
            ))
        );
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
