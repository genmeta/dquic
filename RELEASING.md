# Publishing dquic through CI

Releases use `.github/workflows/publish-crates.yml`. Pull requests, pushes to
`main`, and manual workflow runs on branches perform validation and a publish dry run.
Pushing a `v*` release tag performs the actual crates.io upload and creates the
GitHub Release. Do not publish this workspace from a local machine.

## Versions for v0.8.0

| Crate | Previous published version | Prepared version |
| --- | --- | --- |
| qmacro | 0.5.1 | 0.6.0 |
| qtls | first release | 0.1.0 |
| qbase | 0.6.4 | 0.7.0 |
| qdatagram | 0.6.2 | 0.7.0 |
| qevent | 0.6.2 | 0.7.0 |
| qresolve | 0.8.1 | 0.9.0 |
| qudp | 0.7.2 | 0.8.0 |
| qprotocol | 0.6.1 | 0.7.0 |
| qcongestion | 0.6.2 | 0.7.0 |
| qrecovery | 0.6.2 | 0.7.0 |
| qtransport | first release | 0.1.0 |
| qtraversal | 0.7.2 | 0.8.0 |
| qconnection | 0.8.2 | 0.9.0 |
| dquic | 0.7.2 | 0.8.0 |

The connection refactor changes public APIs and shared types, so the affected
existing crates move to new minor versions. `qmacro` also changes accepted macro
argument syntax compared with the published 0.5.1 package. New crates start at
0.1.0. The workflow publishes the selected packages in dependency order.

`qtls` and the TLS test dependencies use the published `qrustls =0.23.45` package;
no sibling checkout or Git dependency is required. Test certificates needed by
each crate are included under that crate's `tests/keychain/` directory. These are
public test fixtures, not credentials for deployment.

## CI authentication

For the first release of `qtls` and `qtransport`, configure the repository Actions
secret `CARGO_REGISTRY_TOKEN` with a crates.io API token permitted to create those
crates. The workflow uses that token only for crates that do not yet exist on
crates.io. New versions of existing crates, including `dquic 0.8.0`, always use
OIDC through `rust-lang/crates-io-auth-action@v1`, even when the secret is present.
It fails explicitly if a release requires a new crate but no token is
configured; it does not silently skip the crate and publish its dependents.

After the first release, configure Trusted Publishing for the new crates using
repository `genmeta/dquic` and workflow `publish-crates.yml`. The bootstrap secret
can then be removed if all workspace crates are configured for Trusted Publishing.

## Release procedure

1. Commit the reviewed release changes and open a pull request. Confirm the
   existing Rust checks and the `Publish crates.io` dry run pass in CI.
2. Confirm the CI authentication above is ready, then merge the release commit
   into `main` and wait for its checks to pass.
3. Tag that checked commit and push the tag:

   ```sh
   git tag -a v0.8.0 -m 'Release dquic 0.8.0'
   git push origin v0.8.0
   ```

4. Follow the `Publish crates.io` workflow through upload and GitHub Release
   creation. If a transient failure interrupts publication, rerun the workflow:
   its existing version checks skip versions already uploaded.

Local checks may use `cargo test --workspace --all-features --all-targets --
--test-threads=1`, `cargo +1.88.0 check --workspace`, and `cargo package`. Actual
publication stays in CI. A local package check with uncommitted changes requires
`--allow-dirty`; the CI checkout must be clean.
