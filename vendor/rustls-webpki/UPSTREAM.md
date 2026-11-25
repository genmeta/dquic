# WebPKI depth patch

Source: the published `rustls-webpki` 0.103.15 crate from
<https://crates.io/crates/rustls-webpki/0.103.15>.
The original source, manifest, README and ISC license are preserved.
The published crate records upstream revision
`c14836d8de33c0ad0ac7dcb28fe9aade20831a4d`.

The only source change is `MAX_SUB_CA_COUNT` in `src/verify_cert.rs`, raised
from 6 to 16. The official QUIC Interop Runner sends a leaf and eight
intermediate certificates in its amplification-limit test. qtls defaults to
at most 16 supplied certificates and retains its certificate-byte limits.
Signature verification, name constraints, EKU, validity, path-length
constraints and path-building work budgets remain unchanged.

The workspace's `[patch.crates-io]` selects this source for both rustls and
qrustls. Cargo patches apply at the consuming workspace root: applications
using published dquic crates must also apply this patch until the change is
available through an upstream release or the qrustls dependency. Verify that
the patch is still selected when updating dependencies. Tests in
`qtls/tests/handshake/long_chain.rs` cover mutual authentication and rejection
of invalid chains.
