# dquic

`dquic` is the public entry point for the QUIC connection APIs implemented by
`qconnection`. It re-exports all public `qconnection` APIs, including
`QuicEndpoint`, `Connected`, `Accepted`, `ArcConnection`, `Server`, and
`ServerRegistry`.

The crate also exports endpoint identities, stream types and errors, `Role`, transport
parameters, `Dock`, `UdpSocket`, `AddressBook`, `Resolver`, `SystemResolver`,
`RootCerts`, `CertificateDer`, `PrivateKeyDer`, and `default_provider` at its root. The `qbase`, `qconnection`,
`qprotocol`, `qresolve`, `qtls`, and `qtransport` crates are available through
their own namespaces for parameter configuration, network registration,
resolution, TLS, and lower-level connection wiring.

```no_run
use dquic::{Anonymous, Connected, Endpoint, Error, QuicEndpoint};
use std::sync::Arc;

async fn connect(identity: Arc<Endpoint>, peer: String) -> Result<Connected, Error> {
    let endpoint: QuicEndpoint = identity.into();
    endpoint.connect(peer).await
}

async fn anonymous_request(peer: String) -> Result<Connected, Error> {
    let endpoint: QuicEndpoint = Anonymous.into();
    endpoint.connect(peer).await
}
```

`Endpoint`, `Option<Endpoint>`, their `Arc` forms, and `Anonymous` convert into
`QuicEndpoint`. All connections use `QuicEndpoint::connect`; anonymous endpoints
omit client credentials and still verify the server. Listening requires an identity:
an anonymous endpoint logs a warning and returns `Ok(())` without registering a listener.
The `listen` callback receives `Accepted` only after a successful handshake. Handshake
failures are logged and cleaned up internally; `listen` itself still returns local
configuration errors.
Endpoints use `ClientParameters::default()` and `ServerParameters::default()`:
100 streams per direction, 1 MiB connection/stream windows, 10 active connection IDs,
and client/server idle timeouts of 20/30 seconds. `new()` creates empty parameter sets
with protocol defaults for missing fields. ALPN defaults to `h3`. Configure transport parameters with
`set_parameters(role, id, value)`. `Connected` and `Accepted` report the actual
handshake identities. Dropping a pending connect future closes its unclaimed
connection and stops discovery through the normal lifecycle.

Before connecting or listening, configure trust with `qtls::RootCerts`, register
sockets with `qprotocol::Dock` and `qprotocol::QuicProtocol`, publish local
addresses in `qprotocol::AddressBook`, and add name resolution sources through
`qresolve::Resolver::add`. The global resolver starts empty.

See the [connection API documentation](../qconnection/README.md) and the
[runnable traversal examples](../qconnection/examples/traversal/README.md)
for the complete setup.

## Echo examples

[echo-server.rs](examples/echo-server.rs) and [echo-client.rs](examples/echo-client.rs)
use only `dquic` exports for QUIC, sockets, resolution and certificates. Tokio supplies
the runtime, Ctrl-C handling and async I/O extensions; no direct `q*` or Rustls imports are needed.

Run these commands in separate terminals:

```sh
cargo run -p dquic --example echo-server
cargo run -p dquic --example echo-client
```

The server listens on `127.0.0.1:4433`. The anonymous client verifies `localhost`,
connects, opens a bidirectional stream, writes `hello, dquic!`, and calls `shutdown()`
to send FIN. The server reads until EOF, writes the echo and shuts down its write half.
The client reads through the server's FIN, checks the reply and calls `close()`.
The server remains available for further clients; stop it with Ctrl-C.

The generated DER keychain in `examples/keychain` is embedded at compile time. It
contains an example CA certificate, a localhost server certificate, an unencrypted
PKCS#8 private key and a signed OCSP response. These public test credentials are for
local examples only and expire in October 2036. Regenerate them with OpenSSL 3 and
rebuild both examples:

```sh
sh dquic/examples/keychain/generate.sh
```

The script creates a fresh CA and server key, verifies the certificate and OCSP,
then discards its temporary CA private key and signing database.
