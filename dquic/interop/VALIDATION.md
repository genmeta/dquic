# Interop validation

Native checks were run on macOS x86_64 on 25 November 2026. The container and
official Runner matrix are also exercised on GitHub-hosted Ubuntu 24.04; see
the GitHub Actions results below.

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

## GitHub Actions

The [workflow](../../.github/workflows/interop.yml) builds the endpoint image
once, runs the feature-enabled workspace regression, and tests dquic against
quic-go, ngtcp2, quiche, quinn and aioquic in both directions. The 13 required
scenarios are listed in [README.md](README.md#github-actions). Missing,
unsupported, null and failed results all fail the job; no failure is converted
to a passing or skipped result. Performance measurements are opt-in and were
not enabled for these correctness runs.

The Runner is pinned to `ee53e50e1ed33b7871bf67bdb0a7de7d173dd8bb`. Peer images
use the upstream manifest's tags; exact image IDs/digests, Docker/tshark versions,
JSON results, logs, pcaps and key logs are retained in each `interop-PEER`
artifact. The endpoint image contains its resolved Cargo.lock.

### First run

[Run 45535675173](https://github.com/genmeta/dquic/actions/runs/45535675173)
tested commit `24e5d0e0cdd61f94f37eb0d312f763403e9cf2a5`.

* Linux image build succeeded.
* Feature-enabled workspace: 1024 Rust tests/doctests passed, 23 ignored.
* Result checker: 5 tests passed.
* Of the 65 client-direction scenarios, 50 succeeded and 15 failed.
* All 65 server-direction scenarios were blocked by the simulator readiness
  probe. These did not exercise dquic's QUIC handshake.

| Peer server | dquic client passed | Failed scenarios |
| --- | --- | --- |
| quic-go | 12/13 | amplificationlimit |
| quinn | 12/13 | amplificationlimit |
| aioquic | 11/13 | amplificationlimit, rebind-addr |
| quiche | 8/13 | amplificationlimit, handshakeloss, handshakecorruption, rebind-port, rebind-addr |
| ngtcp2 | 7/13 | transfer, blackhole, amplificationlimit, transferloss, rebind-port, rebind-addr |

### Readiness correction and rerun

The simulator's `wait-for-it-quic` sends a padded packet with version
`0x57414954` and requires a Version Negotiation response. dquic currently drops
unsupported versions, so the simulator stopped before starting its network
scenario. This was a readiness prerequisite, not a completed handshake test.
The [upstream probe](https://github.com/quic-interop/quic-network-simulator/blob/master/sim/wait-for-it-quic/wait-for-it.go)
defines this behavior.

`ci.py` now supplies a Compose override that disables only this preliminary
probe when dquic is the server. Actual handshake and transfer checks remain
mandatory, and peer servers retain the upstream probe. A regression test failed
before this correction and passes afterward. The checker now has 6 tests.
No QUIC or TLS production code was changed by this integration.

[Run 45538251490](https://github.com/genmeta/dquic/actions/runs/45538251490)
tested commit `17cea2cbf94030d9117f12448563255b303eea14` with this correction and
Rust debug logs. All ten client/server directions produced complete results:
**105 succeeded, 24 failed, 1 unsupported, out of 130 checks**. The workflow
correctly finished with failure. Image build, the 1024-test Linux workspace
regression (23 ignored), and all 6 checker tests passed.

| Peer | dquic client succeeded | dquic server succeeded |
| --- | --- | --- |
| quic-go | 12/13 | 10/13 |
| quinn | 12/13 | 11/13 |
| aioquic | 11/13 | 12/13 |
| quiche | 8/13 | 11/13 |
| ngtcp2 | 6/13 | 12/13 |

All ten basic handshakes, long-RTT checks and IPv6 checks passed. The
`amplificationlimit` input remains blocked in all ten directions by the retained
TLS limits described below. Nine results are failed; ngtcp2-client to dquic-server
is unsupported because the Runner cannot find a TLS key log to verify that
case. Unsupported is not counted as a pass.

The other 15 failed checks are:

| Client | Server | Failed checks |
| --- | --- | --- |
| dquic | ngtcp2 | transfer, blackhole, transferloss, transfercorruption, rebind-port, rebind-addr |
| dquic | quiche | handshakeloss, handshakecorruption, rebind-port, rebind-addr |
| dquic | aioquic | handshakecorruption |
| quic-go | dquic | rebind-port, rebind-addr |
| quiche | dquic | multiplexing |
| quinn | dquic | handshakecorruption |

Some pressure scenarios changed result between runs: aioquic-server address
rebinding passed on rerun while its handshake-corruption case failed, and
ngtcp2-server transfer corruption changed from passing to failing. These runs
do not establish stable success for those cases. No retries or relaxed checks
were added to obtain a green status.

### Failure evidence and scope

* `amplificationlimit`: the Runner creates a nine-certificate chain. qtls's
  default `max_certificates` is eight, and the installed WebPKI path builder
  also has a six-intermediate depth bound. The first run's client fails with
  TLS alert 42; server-direction logs on rerun include TLS alert 49 when the
  local chain cannot be selected. This does not demonstrate an amplification accounting violation:
  certificate validation prevents this test from completing. Per the user's
  decision, retain TLS validation and these limits, and report the failure.
  The existing padded-Initial anti-amplification regression still passes.
* quiche's high-loss/corruption failures end with `no acknowledgment after 7
  PTOs`. Some handshakes complete before this failure. The exact recovery defect
  has not been isolated.
* ngtcp2's failed transfer receives all three GET requests, completes the first
  2 MiB response, then dquic reaches its connection idle timeout while waiting
  for the other responses. The exact stall cause has not been isolated.
* quiche/ngtcp2 rebinding logs include successful PATH_CHALLENGE/PATH_RESPONSE
  validation before the eventual transfer/idle failure. A failed overall test
  therefore does not imply path validation is entirely absent.
* aioquic's first-run `rebind-addr` transfer downloads the full 10 MiB file. The Runner
  rejects the peer server's first packet on a new path because it contains an
  ACK without PATH_CHALLENGE. This remains a failed protocol check even though
  file transfer succeeds; attribution beyond this observation is not established.
* On rerun, quic-go-client rebinding fails with dquic-server reporting `no
  acknowledgment after 7 PTOs`. quiche-client multiplexing stalls until idle
  timeout, while quinn-client handshake corruption reports a request timeout.
  These are retained failures, not attributed to missing protocol features
  without further isolation.

The workflow is deliberately strict and is not yet evidence that every selected
scenario passes. Passing native tests or a subset of peers must not be reported
as an all-green interoperability matrix.

### Build cache and PR reporting (2026-11-25)

[Run 45549214528](https://github.com/genmeta/dquic/actions/runs/45549214528)
validated the dependency-layer cache and smaller release image on Linux with
Rust 1.88.0 and cargo-chef 0.1.78. Every build used a separate BuildKit builder
and restored the GitHub Actions cache:

| Change | Complete build step | Cargo packages compiled |
| --- | ---: | --- |
| Same source, warm cache | 12 seconds | None |
| Interop documentation only | 7 seconds | None |
| Real Rust program content | 98 seconds | 13 workspace packages, about 22 seconds of Cargo compilation |

The source check changed the CLI description and verified the new description
in the exported image. A 64 KiB HTTP/0.9 loopback transfer, byte comparison,
both TLS key logs and the preserved Cargo.lock also passed. The compressed image
artifact was 78,305,576 bytes, versus 111,440,572 bytes in
[the original PR image job](https://github.com/genmeta/dquic/actions/runs/45545894214/job/138975304153),
using the same Docker exporter and zstd command (about 30% smaller).
These are hosted-runner build measurements, not QUIC throughput measurements.

All 11 Python checks and 6 comment API mock tests passed, along with actionlint
for both interop workflows. Rendering the earlier real 130-check artifacts
preserved the exact 105 passed / 24 failed / 1 unsupported counts. Skipped
body-edit runs, obsolete commits and older results cannot replace newer PR
comments. Missing or invalid matrices remain missing.

The comment publisher uses trusted default-branch code and JSON-only artifacts.
Actual automatic bot publication starts after `interop-report.yml` lands on
`main`, as required by GitHub's `workflow_run` trigger. No main merge or live PR
comment was performed for this validation. The protocol failures above remain
unchanged by this build/reporting work.

### Protocol corrections (2026-11-25)

Three corrections address failures observed in the original PR matrix:

* A zero-length peer CID is now available to every path through independent
  path cells. Previously the first path consumed the only empty CID and a
  rebound path waited indefinitely for another CID. Retiring these cells never
  emits RETIRE_CONNECTION_ID, and NEW_CONNECTION_ID from such a peer is rejected
  as a protocol violation. See
  [RFC 9000 section 5.1.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1).
* PTO exponential backoff now multiplies the entire smoothed-RTT plus variance
  expression. Missing parentheses previously left the smoothed RTT outside
  the multiplier. The regression reproduced 165 ms instead of the expected
  198 ms on the first backoff. See
  [RFC 9002 section 6.2.1](https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1).
* The interop adapter uses a 1 MiB connection window, 64 KiB stream windows and
  32 initial bidirectional streams. A single-variable connection-window
  experiment passed ngtcp2 transfer and multiplexing in both directions in
  [run 45551631387](https://github.com/genmeta/dquic/actions/runs/45551631387).
  The initial-stream-limit experiment passed quiche's original 1999-file
  multiplexing test in both directions in
  [run 45552887860](https://github.com/genmeta/dquic/actions/runs/45552887860).
  Packet captures showed truncated request writes without FIN in the failing
  quiche-client case; its
  [HTTP/0.9 example](https://github.com/cloudflare/quiche/blob/master/apps/src/common.rs)
  does not retry partial stream writes.
  These adapter settings avoid that peer-client behavior without accepting
  incomplete HTTP requests. Production endpoint defaults are unchanged.

Both new CID tests and the PTO test failed before their respective corrections
and passed afterward. The 23 CID tests, 649 affected-crate tests (one ignored),
38 congestion tests and all five native interop tests passed on macOS. Native
interop still includes 128 simultaneous streams with 64 KiB connection and
32 KiB stream receive windows. Clippy for the changed crates, formatting,
whitespace checks, 11 Python checks, six comment tests and actionlint passed.
The full Linux feature-enabled workspace regression passed 1027 Rust tests and
doctests, with 23 ignored.

The TLS chain limits and Forward/spin-bit classification are unchanged. All 13
official scenarios remain required in each direction, including the known
long-chain amplification-limit failure; no retry or relaxed result check was
introduced.

### Long certificate chains (2026-11-25)

The latest pre-fix [run 45562876988](https://github.com/genmeta/dquic/actions/runs/45562876988)
completed 130 checks: 118 succeeded, 11 failed and one was unsupported. Nine
failures and the unsupported result were amplification-limit cases; the other
two failures were dquic-client/quiche-server rebinding.

The user authorized resolving the long-chain limitation. qtls defaults to at
most 16 supplied certificates and depends on qrustls 0.23.46, which uses the
published qwebpki 0.103.17 package. The
[genmeta fork](https://github.com/genmeta/rustls-webpki/commit/e22c7f4) is based
on upstream's 0.103.17 stable branch and raises the intermediate-depth bound
from 6 to 16. Upstream validation and work budgets remain enabled. Consumers
resolve these registry dependencies normally, without vendor files, Git
dependencies or an application-level Cargo patch.

Regression tests reproduced the local certificate-count rejection and,
independently, WebPKI's depth rejection with an explicit larger qtls limit.
After the correction, mutual authentication with 9 and 16 certificates and
valid OCSP succeeds. Invalid intermediate signatures, unknown roots, name
constraints and configured local/peer count and byte limits still fail.
The default native workspace passed 1016 tests/doctests; the feature-enabled
workspace passed 1021, with eight ignored in each build. Clippy for qtls/dquic,
workspace formatting, 11 Python checks and six comment tests passed.
The qwebpki fork passed 415 Ring tests and 430 AWS-LC tests (two ignored in
each build), including 16-intermediate success and 17-intermediate rejection.
qrustls passed 232 unit tests, 259 API tests and 15 doctests (five ignored).
The official Linux matrix must be rerun before claiming that the
amplification-limit scenario passes.

The independent [quic-go/quiche control run 45557873049](https://github.com/genmeta/dquic/actions/runs/45557873049)
also fails both rebinding tests without dquic. In the dquic/quiche port-rebind
capture, stream bytes 388736..424828 never arrive, while bytes
424828..2000593 arrive after successful path validation. The quic-go control
also retains stream gaps. This supports investigating quiche's old-path
recovery; it does not establish a tested upstream fix. The production matrix
continues to require both rebinding checks without retries or exclusions.
