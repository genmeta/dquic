# Interop validation

Validated locally on macOS x86_64 on 25 November 2026. The Docker image and
official Runner matrix have not been run on this host.

## Workspace regression

```sh
cargo test --offline --workspace -- --test-threads=1
CARGO_INCREMENTAL=0 cargo test --offline --workspace --features dquic/interop-test -- --test-threads=1
cargo clippy --offline -p dquic -p qbase -p qprotocol -p qconnection -p qtransport \
  --all-targets --features dquic/interop-test -- -D warnings
cargo fmt --all -- --check
```

Default workspace: 1010 tests and doctests passed, 8 ignored. With
`dquic/interop-test`: 1015 passed, 8 ignored. Clippy, formatting, whitespace
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
| aioquic 1.3.0 | dquic | handshake and concurrent transfer passed; all three downloaded contents matched |

The handshake timeout was caused by anti-amplification accounting. aioquic's
Initial occupies only a prefix of a 1200-byte UDP datagram; the rest is padding
outside the protected packet. dquic counted only the parsed packet. Its first
ACK-only Initial consumed enough credit to block the queued ServerHello.
The fix passes the full datagram length as a plain `usize` credit on the first
packet; subsequent packets carry zero. Known paths count it before decryption
or packet-number checks, including when every packet is discarded. See
[RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1).
The regression test sends one ClientHello in a 600-byte protected packet plus
600 bytes of external padding, requires ServerHello without further client
traffic, and checks the three-times amplification bound. It timed out before
the fix and passes afterward. Additional tests verify coalesced packets count
once, duplicate datagrams count once each, and discarded packets on known paths
still contribute received bytes. No shared counter or pending-credit cache is
used. An invalid packet from an unknown path contributes no credit; a valid
packet can admit that path and count only its own attached credit. In particular,
if an invalid first packet on an unknown path carried the datagram credit, a
later valid packet carrying zero does not recover it.

After this fix, aioquic completed the handshake but file transfer stalled when
it set the Spin Bit in subsequent ACK packets. The datagram classifier treated
them as Forward packets. dquic now also checks the following byte's high bit:
all locally issued CIDs have it set; the v0 Forward type never does. The Forward
wire encoding and dquic's disabled Spin behavior remain intact. Regression tests
cover all protected low-bit combinations, marked DCID boundaries, delivery over
a real UDP socket, and the CID generator's marking invariant.

There is no standard transport parameter asking the peer to disable Spin.
Disabling Spin is unilateral and does not require transmitting zero, so a
disable switch alone cannot provide this distinction. See
[RFC 9000 section 17.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.4).
The successful run used the unmodified aioquic implementation, including its
normal Spin behavior, with 1 KiB, 2259000-byte and empty files and small windows.

To check the formerly failing handshake direction, start the server as shown
in README.md, then run the following using aioquic 1.3.0 and the matching CA:

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
Packet, TLS-state and aioquic QLOG diagnostics for the successful bidirectional
run are in
`/private/var/folders/hl/2bs_7sn16hl7xl29kx4ncf9c0000gn/T/dquic-aioquic-kk91g7na/`.
