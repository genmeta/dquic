# dquic

`dquic` is the public entry point for the QUIC connection APIs implemented by
`qconnection`. It re-exports all public `qconnection` APIs, including
`QuicEndpoint`, `Connected`, `Accepted`, `ArcConnection`, `Server`, and
`ServerRegistry`.

The crate also exports `Endpoint`, `LocalAuthority`, `RemoteAuthority`, stream
types, stream errors, and `VarInt` at its root. The `qbase`, `qconnection`,
`qprotocol`, `qresolve`, `qtls`, and `qtransport` crates are available through
their own namespaces for parameter configuration, network registration,
resolution, TLS, and lower-level connection wiring.

```no_run
use dquic::{Connected, Endpoint, Error, QuicEndpoint};
use std::sync::Arc;

async fn connect(identity: Arc<Endpoint>, peer: String) -> Result<Connected, Error> {
    let endpoint = QuicEndpoint::new(identity);
    endpoint.connect(peer).await
}

async fn connect_anonymously(peer: String) -> Result<Connected, Error> {
    dquic::connect_anonymously(
        peer,
        dquic::qbase::param::handy::client_parameters(),
        vec![b"h3".to_vec()],
    ).await
}
```

`QuicEndpoint` always requires local credentials and supports connecting and listening.
The independent `connect_anonymously` function only initiates connections; it omits
client credentials and still verifies the server. Both paths use the same internal
connection lifecycle. Named endpoints configure `alpn` (default `h3`); anonymous calls
supply client parameters and ALPN explicitly. `Connected` and `Accepted` report the
actual handshake identities. Dropping a pending connect future closes its unclaimed
connection and stops discovery through the normal lifecycle.

Before connecting or listening, configure trust with `qtls::RootCerts`, register
sockets with `qprotocol::Dock` and `qprotocol::QuicProtocol`, publish local
addresses in `qprotocol::AddressBook`, and add name resolution sources through
`qresolve::Resolver::add`. The global resolver starts empty.

See the [connection API documentation](../qconnection/README.md) and the
[runnable traversal examples](../qconnection/examples/traversal/README.md)
for the complete setup.
