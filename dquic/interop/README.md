# QUIC Interop endpoint

The `interop` example implements HTTP/0.9 over QUIC using `hq-interop` ALPN.
It shares dquic's connection and transport implementation. Its source, tests and
container entry point live in this directory.
See [validation results](VALIDATION.md) for completed checks and the
aioquic-client to dquic-server handshake fix.

## Features and key logging

Build with `interop-test` to allow peers and local credentials without OCSP.
Without this feature, missing OCSP remains an error. Certificate names, chains,
signatures and validity are still checked, and supplied OCSP is always validated.
The workspace supports chains of up to 16 supplied certificates by default,
including the Runner's nine-certificate amplification test. It uses a
[WebPKI depth patch](../../vendor/rustls-webpki/UPSTREAM.md); certificate byte
limits and all other validation rules remain enabled.
Cargo features apply to every use of the enabled crate within the same build;
use a separate build for normal deployments.

TLS key logging is a runtime API, available without `interop-test`:

```rust,no_run
let mut endpoint = dquic::QuicEndpoint::anonymous();
endpoint.set_keylog(true);
// Subsequent connect/listen calls write NSS secrets to SSLKEYLOGFILE, if set.
endpoint.set_keylog(false);
```

The default is disabled. `SSLKEYLOGFILE` alone does not enable logging.
The example's `--keylog` flag calls this API; the container entry point enables
it for Runner packet analysis. Key log files can decrypt captured traffic.

## Build and test

Run from the repository root:

```sh
cargo build -p dquic --example interop --features interop-test
cargo test -p dquic --test interop --features interop-test
cargo test -p qtls --tests -- --test-threads=1
cargo test -p qtls --features interop-test --tests -- --test-threads=1
```

The interop tests include a real loopback QUIC connection without OCSP, binary
file transfers over 128 streams, small receive windows, FIN handling and file
root containment. They do not require Docker.

## Runner contract

`ROLE` is `client` or `server`. Supported `TESTCASE` values are `handshake`,
`transfer` and `multiconnect`; other values exit 127. Client errors exit 1;
completed downloads exit 0. The server keeps serving until stopped.

The server loads `/certs/cert.pem` and `/certs/priv.key`, trusts `/certs/ca.pem`,
and serves `/www` on UDP 443. It registers the Runner SNI names `server`,
`server4`, `server6` and `server46`. The client trusts the same CA, reads
space-separated HTTPS URLs from `REQUESTS`, and saves each URL's basename in
`/downloads`. Completed files are renamed from `.part` only after response FIN.
Duplicate basenames are rejected. URL paths are literal file paths; query
strings and fragments are not supported.

`handshake` and `transfer` use one connection per origin and concurrent streams.
`multiconnect` establishes a new connection for every file. Initial receive
windows are 64 KiB per stream and 1 MiB per connection, with 32 initial
bidirectional streams. Temporary sockets
publish only Direct addresses, without STUN bootstrap or NAT Candidates, so
the adapter does not advertise dquic traversal frames to standard peers.

dquic keeps its Forward marker at `0x20`. For short datagrams, the high bit of
the following byte distinguishes a dquic-issued DCID from a v0 Forward type:
issued CIDs always start with a set high bit, while the Forward type does not.
This lets standard peers send either Spin Bit value without changing the
Forward encoding or requiring Spin Bit negotiation. Initial packets use long
headers, so their original DCID does not need this mark.

Defaults bind the Runner's concrete IPv4 and IPv6 addresses. For local testing,
override `--bind`, `--certs`, `--www`, `--downloads`, and `--name` as needed:

```sh
# Server, using a PEM certificate directory containing ca.pem, cert.pem, priv.key
ROLE=server TESTCASE=transfer SSLKEYLOGFILE=/tmp/server.keys \
  target/debug/examples/interop --bind 127.0.0.1:4433 --name localhost \
  --certs /tmp/interop-certs --www /tmp/interop-www --keylog

# Client, in another terminal
ROLE=client TESTCASE=transfer SSLKEYLOGFILE=/tmp/client.keys \
  REQUESTS='https://localhost:4433/file.bin' \
  target/debug/examples/interop --bind 127.0.0.1:0 \
  --certs /tmp/interop-certs --downloads /tmp/interop-downloads --keylog
```

## Container

Build from the repository root with a current Docker/BuildKit installation:

```sh
docker build --platform linux/amd64 -f dquic/interop/Dockerfile \
  -t dquic-interop:local .
```

The Dockerfile-specific ignore file keeps local build output, agent settings
and credentials out of the build context. It follows the
[Docker build context convention](https://docs.docker.com/build/concepts/context/#filename-and-location).
The image retains the resolved Cargo.lock at `/usr/local/share/dquic/Cargo.lock`.
Pin base image digests and preserve the lockfile for repeatable benchmarks.

The build uses pinned `cargo-chef` 0.1.78 to cache third-party dependencies
separately from project sources. Workflow files and reporting scripts do not
enter the build context; `dquic/README.md` remains because the library includes
it. The final executable is built from the real sources with the planner's
original lockfile and `--locked`, after restoring local package versions.
This container alone disables release debug symbols to reduce cache and image
transfers; workspace profiles, tracing and TLS key logging are unchanged.
Actions exports intermediate layers with `mode=max`, builds the image once,
and shares a zstd artifact without recompressing it. Source changes can reuse
dependency layers when manifests and dependency resolution stay unchanged.
GitHub's branch cache access rules still apply: main builds seed the cache
available to PRs; a new PR cannot reuse another feature branch's private cache.

Add the following member to the Runner's `implementations_quic.json`:

```json
"dquic": {
  "image": "dquic-interop:local",
  "url": "https://github.com/genmeta/dquic",
  "role": "both"
}
```

Then run both directions from the Runner checkout:

```sh
python3 run.py -s quic-go -c dquic -t handshake,transfer -n quic-go,dquic
python3 run.py -s dquic -c quic-go -t handshake,transfer -n quic-go,dquic
```

The endpoint base image provides `/setup.sh` and `/wait-for-it.sh`.
`CLIENT_PARAMS` and `SERVER_PARAMS` accept whitespace-separated example options.
Server and client diagnostics are saved to `/logs/interop.log`.
Set `RUST_LOG=debug` when diagnosing handshake or transport failures.

Several Runner tests map to the endpoint's `transfer` behavior; supporting that
behavior does not declare those tests passed. Retry, resumption, 0-RTT, HTTP/3,
v2, explicit key-update initiation and preferred-address migration are not
implemented here. Version Negotiation responses are also not implemented.
QLOGDIR export is not wired by this adapter. The Docker image
and cross-implementation matrix run on Linux in the workflow below.

## GitHub Actions

[QUIC interop](../../.github/workflows/interop.yml) runs on pushes to `main`,
manual dispatch, and pull requests to `main` whose title contains `[interop]`.
For example: `fix: handle packet loss [interop]`. Adding the marker by editing
the title starts CI; subsequent commits and reopening the PR rerun it while
the marker remains. PR body edits neither rerun nor cancel it, and do not replace
the result comment. Untagged PRs skip the jobs. The endpoint image is built once
for `linux/amd64` and reused by five parallel peer jobs: quic-go,
ngtcp2, quiche, quinn and aioquic. No registry credentials are needed.

Each peer job runs both client/server directions through the official
[Interop Runner](https://github.com/quic-interop/quic-interop-runner), pinned to
`ee53e50e1ed33b7871bf67bdb0a7de7d173dd8bb`. Required scenarios are:

* `handshake`, `transfer`, `longrtt`, `multiplexing`, `blackhole`;
* `amplificationlimit`, `handshakeloss`, `transferloss`;
* `handshakecorruption`, `transfercorruption`, `ipv6`;
* `rebind-port`, `rebind-addr`.

All 130 selected checks must succeed. A failed, unsupported, missing, duplicate
or unrun result fails CI. Automatic conversion of failures to unsupported is
disabled. The workspace regression also runs with `dquic/interop-test` enabled.
The unsupported features listed above, and the ECN scenario requiring ECN
marking/validation, are outside this required set. A green workflow only covers
the selected scenarios.

The simulator normally probes server readiness with an unknown QUIC version
and requires a Version Negotiation response. For dquic servers, `ci.py`
disables this preliminary probe using a Compose override; actual handshake and
transfer tests must still succeed. Peer servers retain the upstream probe.
The override also enables Rust debug logs. It does not change Runner test checks.

Enable `measurements` in a manual run to add upstream `goodput` and
`crosstraffic` measurements in both directions (five repetitions each). Their
results must also succeed; values are reported without a speed threshold.
Shared Actions machines and the simulated 10 Mbps link are useful for regression
checks, but hardware throughput comparisons require a dedicated benchmark host.

Each job publishes a result table in its Actions summary and an `interop-PEER`
artifact containing JSON results, endpoint diagnostics, packet captures, TLS
key logs, image IDs/digests and tool versions. The temporary CA and generated
traffic are only for these tests. Artifacts expire after seven days.

The interop endpoint advertises a 1 MiB connection receive window, 64 KiB
bidirectional stream receive windows and 32 initially available bidirectional
streams. The transfer inputs (2, 3 and 5 MiB) still require window updates, and
the 1999-file multiplexing test still requires MAX_STREAMS increases. The larger
connection window avoids ngtcp2's small-window transfer stall. The conservative
initial stream limit avoids partial request writes that quiche's HTTP/0.9
example client does not retry. These are adapter settings; native tests retain
their smaller windows and larger stream sets.

[QUIC interop report](../../.github/workflows/interop-report.yml) creates or
updates one bot comment on opted-in PRs, including fork PRs. It shows pass,
failure, unsupported and missing counts, all individual checks, regression
and image status, the tested commit and links to full artifacts. Older commits
and runs cannot overwrite newer results. Missing or invalid JSON stays missing.
The reporting workflow runs trusted default-branch code and reads only JSON
artifacts from the test run. It must first be merged into `main` before GitHub
can trigger its `workflow_run` event. No additional token secret is needed.

To run the same matrix entry locally with Docker and a recent tshark installed:

```sh
git clone https://github.com/quic-interop/quic-interop-runner target/interop-runner
git -C target/interop-runner checkout ee53e50e1ed33b7871bf67bdb0a7de7d173dd8bb
python3 -m pip install -r target/interop-runner/requirements.txt
docker build -f dquic/interop/Dockerfile -t dquic-interop:local .
python3 dquic/interop/ci.py target/interop-runner quic-go
```

Use a new `--output` directory for each rerun; Runner log directories must not
already exist. Add `--measurements` to include the performance checks.
