# Interop validation

Validated locally on macOS x86_64 on 25 November 2026. The Docker image and
official Runner matrix have not been run on this host.

## Workspace regression

```sh
cargo test --offline --workspace -- --test-threads=1
cargo test --offline --workspace --features dquic/interop-test -- --test-threads=1
cargo clippy --offline -p dquic -p qtls -p qbase -p qconnection \
  --all-targets --features dquic/interop-test -- -D warnings
cargo fmt --all -- --check
```

Default workspace: 1001 tests and doctests passed, 8 ignored. With
`dquic/interop-test`: 1006 passed, 8 ignored. Clippy, formatting, whitespace
checks and shell syntax checks passed. UDP tests require permission to bind
local sockets; a sandbox denial must not be interpreted as a protocol failure.

The new interop tests cover binary files, concurrent HTTP/0.9 streams, FIN,
oversized requests, path containment, and 128 streams over a real QUIC connection
with small receive windows and no OCSP. TLS tests check both feature settings,
invalid supplied OCSP and invalid certificates. A subprocess test verifies that
the client and server log identical NSS secrets when enabled, and that setting
SSLKEYLOGFILE alone does not enable logging.

## Native command line checks

Separate dquic server and client processes passed `handshake`, `transfer` and
`multiconnect`. File contents matched for a 1 KiB file, a 2259000-byte binary
file and an empty file. `multiconnect` produced a distinct TLS Client Random for
each downloaded file. Disabling `--keylog` produced no client key log even with
SSLKEYLOGFILE set. Unknown TESTCASE values returned 127 in both roles.

## Cross implementation checks

The peer was aioquic 1.3.0, installed in a temporary Python environment without
adding project dependencies. Tests used QUIC v1, ALPN `hq-interop`, the local
test CA and a server certificate without OCSP.

| Client | Server | Result |
| --- | --- | --- |
| dquic | aioquic 1.3.0 | handshake, concurrent transfer and multiconnect passed; downloaded contents matched |
| aioquic 1.3.0 | dquic | Handshake timed out; this direction is not validated |

In the failing direction, aioquic remained in `CLIENT_EXPECT_SERVER_HELLO`.
It received a 1200-byte Initial packet, then Handshake packets, and reported
that the Handshake decryption key was unavailable. The dquic server generated
TLS secrets. These observations locate the failure before application data;
they do not establish the root cause. No transport workaround was added to
hide this failure.

To reproduce the failing direction, start the server as shown in README.md,
then run the following using aioquic 1.3.0 and the matching CA:

```python
import asyncio
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion

async def main():
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["hq-interop"],
        server_name="localhost",
        cafile="/tmp/interop-certs/ca.pem",
        supported_versions=[QuicProtocolVersion.VERSION_1],
        idle_timeout=8,
    )
    async with connect("127.0.0.1", 4433, configuration=config):
        print("handshake completed")

asyncio.run(main())
```

Local validation logs are under `/private/tmp/dquic-interop-research/`.
Detailed packet-type and TLS-state diagnostics for the failing direction are in
`/private/var/folders/hl/2bs_7sn16hl7xl29kx4ncf9c0000gn/T/dquic-aioquic-w0du683i/`.
