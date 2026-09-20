mod common;

use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    param::{ClientParameters, ParameterId, WriteParameters},
};
use qconn::{BelongsTo, Interceptor, Scope, ServerRegistry};
use qtls::{ClientStart, CryptoLevel, QuicVersion, TlsEvent};

#[tokio::test]
async fn interceptor_upgrades_a_fragmented_client_hello_into_server_tls() {
    let (client_parameters, _) = common::parameters();
    let client = common::client_without_alpn();
    let mut endpoint = common::quic_endpoint();
    endpoint
        .listen(Scope::Loopback | Scope::Internal, |_| {})
        .unwrap();
    let mut encoded_client_parameters = BytesMut::new();
    encoded_client_parameters.put_parameters(&client_parameters);
    let mut client = client
        .start(ClientStart {
            server_name: "localhost".try_into().unwrap(),
            quic_version: QuicVersion::V1,
            local_transport_parameters: encoded_client_parameters.freeze(),
        })
        .unwrap();
    let Some(TlsEvent::WriteCrypto { level, bytes }) = client.next_event() else {
        panic!("client must emit ClientHello first")
    };
    assert_eq!(level, CryptoLevel::Initial);

    let interceptor = Interceptor::new();
    let writer = interceptor.clone();
    let waiting = tokio::spawn(interceptor.read());
    for chunk in bytes.chunks(3) {
        writer.write(chunk);
    }
    let hello = waiting.await.unwrap().unwrap();
    assert_eq!(hello.server_name(), Some("localhost"));
    let parsed = ClientParameters::parse_from_bytes(hello.transport_parameters()).unwrap();
    assert_eq!(
        parsed.get::<ConnectionId>(ParameterId::InitialSourceConnectionId),
        client_parameters.get::<ConnectionId>(ParameterId::InitialSourceConnectionId)
    );

    let server = ServerRegistry::global()
        .get(hello.server_name().unwrap())
        .unwrap();
    assert!(
        "127.0.0.1:4433"
            .parse::<SocketAddr>()
            .unwrap()
            .belongs_to(server.scopes)
    );
    let scid = ConnectionId::from_slice(b"server00");
    let odcid = ConnectionId::from_slice(b"original");
    let (tls, intercepted_parameters, connection_parameters) =
        server.start(QuicVersion::V1, hello, scid, odcid).unwrap();
    assert_eq!(
        intercepted_parameters.get::<ConnectionId>(ParameterId::InitialSourceConnectionId),
        client_parameters.get::<ConnectionId>(ParameterId::InitialSourceConnectionId)
    );
    assert_eq!(
        connection_parameters.get::<ConnectionId>(ParameterId::InitialSourceConnectionId),
        Some(scid)
    );
    assert_eq!(
        connection_parameters.get::<ConnectionId>(ParameterId::OriginalDestinationConnectionId),
        Some(odcid)
    );
    assert!(matches!(
        tls.read_keys().await.unwrap(),
        qtls::InstalledKeys::Handshake(_)
    ));

    let initial_max_data = server
        .server_parameters
        .get::<qbase::varint::VarInt>(ParameterId::InitialMaxData);
    endpoint
        .set_server_parameters(ParameterId::InitialMaxData, 123_456u32)
        .unwrap();
    assert_eq!(
        server
            .server_parameters
            .get::<qbase::varint::VarInt>(ParameterId::InitialMaxData),
        initial_max_data
    );
    endpoint.listen(Scope::External, |_| {}).unwrap();
    let updated = ServerRegistry::global().get("localhost").unwrap();
    assert!(!Arc::ptr_eq(&server, &updated));
    assert_eq!(
        updated
            .server_parameters
            .get::<qbase::varint::VarInt>(ParameterId::InitialMaxData),
        endpoint
            .server_parameters
            .get::<qbase::varint::VarInt>(ParameterId::InitialMaxData)
    );
    assert!(
        "1.1.1.1:4433"
            .parse::<SocketAddr>()
            .unwrap()
            .belongs_to(updated.scopes)
    );
    assert!(ServerRegistry::global().remove("localhost").is_some());
}

#[test]
fn listen_scope_distinguishes_peer_address_classes() {
    let address = |value: &str| value.parse::<SocketAddr>().unwrap();
    let local = Scope::Loopback | Scope::Internal;

    assert!(address("127.0.0.1:4433").belongs_to(local));
    assert!(address("192.168.1.1:4433").belongs_to(local));
    assert!(!address("1.1.1.1:4433").belongs_to(local));
    assert!(address("1.1.1.1:4433").belongs_to(Scope::External.into()));
}
