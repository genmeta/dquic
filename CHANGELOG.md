# Changelog

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
