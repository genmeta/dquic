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
windows are 64 KiB per stream and 128 KiB per connection. Temporary sockets
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
implemented here. QLOGDIR export is not wired by this adapter. The Docker image
and cross-implementation matrix must be verified on a Docker-capable Linux host.
