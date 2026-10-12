# Changelog

## [0.8.1] - 2026-10-12

### Fixed

- Convert Android's signed IPv6 packet-info interface index to the unsigned
  socket scope ID without changing the UDP or QUIC interfaces.

### Published crates

- `qudp` v0.8.1
- `dquic` v0.8.1

Unchanged workspace crates remain on their existing published versions.

## [0.8.0] - 2026-10-12

### Added

- Introduce `qtls` for connection-independent QUIC TLS 1.3 handshakes,
  certificate and OCSP validation, and session resumption storage.
- Introduce `qtransport` for packet spaces, routing, path state, packet
  protection, recovery feedback, and connection shutdown.
- Add streaming DNS discovery and scoped AddressBook subscriptions for
  selecting connection paths and advertising NAT traversal candidates.
- Add `Anonymous` endpoints for clients that omit client credentials while
  still verifying the server's identity and OCSP response.
- Add a standalone STUN server with optional forwarding, deployment examples,
  and an isolated Docker NAT traversal test matrix.

### Changed

- Rebuild `qconnection` around sequential handshake phases, shared transport
  components, and connection-scoped hole punching.
- Make `dquic` the public entry point for `QuicEndpoint`, `Connected`, `Accepted`,
  and the related connection, socket, resolver, and TLS APIs.
- Remove the previous `dquic` Client/Server builder APIs, `qinterface`, and
  `h3-shim`. Applications must migrate to `QuicEndpoint` and explicitly configure
  trust roots, socket registrations, local addresses, and resolution sources;
  see [the public API guide](dquic/README.md).
- Use the crates.io `qrustls =0.23.45` package for the custom TLS backend and
  restore CI publication of the full workspace dependency chain.
- Require peer certificate OCSP validation by default. Servers can explicitly
  allow missing client OCSP during rollouts with
  `TlsServer::with_optional_client_ocsp`; supplied responses are still validated.
- Update dependencies and move affected crates to new minor versions for the
  public API and shared-type changes.

### Fixed

- Coordinate path CID allocation and retirement, selecting the handshake path
  before assigning its peer CID.
- Prevent duplicate server connections when concurrent Initial packets carry
  the same original destination connection ID.
- Select registered endpoints by endpoint kind and address family, and reject
  candidate pairs that mix loopback and non-loopback addresses.
- Refine path validation, ACK and congestion feedback, stream scheduling, and
  recovery ticks across handshake transitions and path changes.
- Preserve pending packet data across partial UDP sends and wake concurrent
  senders when sockets become writable.
- Clean up cancelled connection attempts and propagate connection termination
  to waiting stream and transport tasks.

### Published crates

- `qmacro` v0.6.0
- `qtls` v0.1.0 (first release)
- `qbase` v0.7.0
- `qdatagram` v0.7.0
- `qevent` v0.7.0
- `qresolve` v0.9.0
- `qudp` v0.8.0
- `qprotocol` v0.7.0
- `qcongestion` v0.7.0
- `qrecovery` v0.7.0
- `qtransport` v0.1.0 (first release)
- `qtraversal` v0.8.0
- `qconnection` v0.9.0
- `dquic` v0.8.0

## [0.7.2] - 2026-08-24

### Added

- Add STUN transaction handling to `qprotocol`.

### Fixed

- Schedule keepalive traffic per path while respecting the connection-wide
  deferred-idle deadline.
- Let an unresponsive path time out without terminating healthy paths, and
  recover its outstanding 1-RTT data on the surviving paths.
- Discard obsolete Initial and Handshake recovery state at the corresponding
  handshake transitions.
- Preserve reliable frames that do not fit in the current packet for the next
  transmission attempt.

### Published crates

- `qbase` v0.6.4
- `qevent` v0.6.2
- `qudp` v0.7.2
- `qinterface` v0.7.2
- `qprotocol` v0.6.1
- `qdatagram` v0.6.2
- `qresolve` v0.8.1
- `qcongestion` v0.6.2
- `qrecovery` v0.6.2
- `qtraversal` v0.7.2
- `qconnection` v0.8.2
- `dquic` v0.7.2

## [0.7.1] - 2026-08-11

### Changed

- Promote the validated 0.7.1 beta line to a stable release without additional
  protocol changes.

### Published crates

- `qbase` v0.6.3
- `qevent` v0.6.1
- `qudp` v0.7.1
- `qinterface` v0.7.1
- `qdatagram` v0.6.1
- `qresolve` v0.8.0
- `qcongestion` v0.6.1
- `qrecovery` v0.6.1
- `qtraversal` v0.7.1
- `qconnection` v0.8.1
- `dquic` v0.7.1

## [0.7.1-beta.1] - 2026-08-11

### Fixed

- Bound received-packet ACK journals by evicting the oldest ranges instead of
  coupling receive-history retention to peer ACK progress.
- Preserve path-local ACK triggers and ensure each ACK's largest packet number
  belongs to the path that sends it.
- Process sparse multipath ACK ranges without assuming globally contiguous
  packet numbers.
- Preserve the configured STUN server address through traversal handling.

### Published crates

- `qbase` v0.6.3-beta.1
- `qevent` v0.6.1-beta.1
- `qudp` v0.7.1-beta.1
- `qinterface` v0.7.1-beta.1
- `qdatagram` v0.6.1-beta.1
- `qresolve` v0.8.0-beta.1
- `qcongestion` v0.6.1-beta.1
- `qrecovery` v0.6.1-beta.1
- `qtraversal` v0.7.1-beta.1
- `qconnection` v0.8.1-beta.1
- `dquic` v0.7.1-beta.1
