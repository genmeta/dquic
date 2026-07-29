<p align="center">
  <a href="https://github.com/genmeta/dquic" title="DQuic">
    <img src="images/dquic-logo.svg" width="300" alt="DQuic">
  </a>
</p>
<h3 align="center">A QUIC implementation extended for peer-to-peer communication and multipath transport</h3>

[![License: Apache-2.0](https://img.shields.io/github/license/genmeta/dquic)](https://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/genmeta/dquic/rust.yml)](https://github.com/genmeta/dquic/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/genmeta/dquic/graph/badge.svg)](https://codecov.io/gh/genmeta/dquic)
[![crates.io](https://img.shields.io/crates/v/dquic.svg)](https://crates.io/crates/dquic)
[![Documentation](https://docs.rs/dquic/badge.svg)](https://docs.rs/dquic/)
[![Dependencies](https://img.shields.io/deps-rs/repo/github/genmeta/dquic)](https://github.com/genmeta/dquic/network/dependencies)
![MSRV](https://img.shields.io/crates/msrv/dquic)

**English** | [简体中文](README_CN.md)

**Is the Internet truly omniconnectible?** At the level of underlying network topology, paths exist; at the connection layer, connectivity is still only partial. Being reachable requires listening for incoming connections, and that capability has largely remained a server-side privilege. This is why phones rarely connect directly to one another: direct communication between clients still relies on server-side assistance.

**Why?** Most client endpoints reside behind private networks or NATs and have no public IP address on which to listen. Yet a private-network endpoint can also gain that capability when it is paired with a public delegate endpoint that forwards packets on its behalf. The cost is simply that the receiving address is no longer the private endpoint's IP address alone: it is a compound endpoint address that contains the private endpoint's publicly mapped address and the address of its public delegate endpoint.

DQuic applies this `ep-&EP` pairing model so that ordinary endpoints can listen for incoming connections and establish peer-to-peer connectivity. A public delegate endpoint is not a full-featured TURN server such as coturn; it only forwards packets to the intended private-network endpoint according to the extended endpoint address. **It need not be permanently deployed infrastructure or a central server that remains online indefinitely.** This makes decentralized, connection-layer omniconnectivity possible. This is **the Omniconnectible Internet**.

<p align="center">
  <img src="images/dquic-connectivity-en.png" alt="DQuic extends cloud-centric partial connectivity into omniconnectivity between endpoints">
</p>

## Endpoint Addresses

In DQuic, **a connection peer is no longer limited to a server**. Any endpoint with an Endpoint Address can communicate as a peer. An Endpoint Address has the following form:

```rust,ignore
pub enum EndpointAddr {
    Direct {
        addr: SocketAddr,
    },
    Agent {
        agent: SocketAddr,
        outer: SocketAddr,
    },
}
```

> [!NOTE]
>
> An Endpoint Address describes an endpoint's currently reachable network address. A public endpoint uses `EndpointAddr::Direct`, consisting of an IP address and port. A private-network endpoint uses `EndpointAddr::Agent`, which combines the public delegate endpoint's reachable address with the private endpoint's own publicly mapped address. DDns uses E records (Endpoint Address Records) to resolve a name to one or more current `EndpointAddr` values. See the [DDns Protocol Documentation](https://docs.dhttp.net/en/docs/protocol/ddns) and the [open-source DDns implementation](https://github.com/genmeta/ddns).

## Peer-to-Peer Communication

Building on the [Using QUIC to traverse NATs](https://datatracker.ietf.org/doc/html/draft-seemann-quic-nat-traversal-02) draft, DQuic implements a complete NAT traversal capability for DQuic connections. The draft remains at an early stage: it defines relevant extension frames but does not fully specify how NAT traversal coordinates with QUIC. With the `ep-&EP` pair model, DQuic uses the `Agent` form of an Endpoint Address to represent the delegate route and integrates STUN, relay, and signaling capabilities into the DQuic connection workflow to establish peer-to-peer connections between private-network endpoints.

In this model, a private-network endpoint `ep` pairs with at least one public endpoint `EP`; `&EP` serves as `ep`'s public delegate endpoint. The two communicating endpoints first use their respective Endpoint Addresses to establish an initial reachable path, then exchange candidate addresses and attempt to establish a peer-to-peer path.

A validated peer-to-peer path is added to the current connection and can become the preferred transport path. If a direct path cannot be established, the connection can continue over the relayed path through the public delegate endpoint.

> For more information, see the [DQuic Protocol Documentation](https://docs.dhttp.net/en/docs/protocol/dquic).

## Multipath Transport

An endpoint may simultaneously use Wi-Fi, cellular, and Ethernet networks and may have both IPv4 and IPv6 protocol stacks. Two endpoints can therefore have multiple transport paths between them. Rather than directly following the MP-QUIC draft, DQuic implements a hybrid multipath transport scheme. It relies on independent packet transmission on each path and partial ordering among packet numbers, and schedules packets according to path priority and send-buffer trends.

Standard QUIC establishes a connection handshake over a single initial path. A DQuic connection can instead attempt multiple paths in parallel and complete the handshake over the fastest responding path, improving both connection establishment latency and the likelihood of success. Each path can subsequently attempt NAT traversal independently, further increasing the chance that the connection establishes a peer-to-peer path. When the network changes, QUIC connection migration allows NAT traversal to be retried over new paths without tearing down the overall connection.

As IPv6 adoption expands, DQuic can use a direct IPv6 path whenever both endpoints can communicate over IPv6, without NAT traversal on that path.

> For more information, see the [DQuic Protocol Documentation](https://docs.dhttp.net/en/docs/protocol/dquic).

## Open Connectivity and Security

You may reasonably worry that exposing private-network devices to the public Internet through `EndpointAddr` and DQuic is unsafe. Exposing a private device's SSH port to the public Internet through VPN-style solutions and protecting it with a weak password is indeed dangerous. DQuic addresses a different model. Its security does not come merely from avoiding VPN-style network exposure, nor only from QUIC's secure transport design. DQuic, DDns, and DHttp assign each endpoint a name and a PKI-backed certificate, so endpoints authenticate one another with mTLS instead of relying on weak passwords.

Private-network devices must become publicly reachable to participate in open connectivity, but public reachability does not itself mean unrestricted access. It also requires firewall and access-policy controls. Open connectivity does not mean that every endpoint may access every other endpoint: only authorized identities should be accepted. After DQuic establishes a connection, name-centered mTLS identity verification and access policies can provide finer-grained and more stable protection than policies based on IP addresses alone.

> IP addresses carry some identity information, but they are highly variable, and address spoofing remains possible. By comparison, PKI-backed certificates provide stronger verifiable identity, and certificate forgery is much rarer in practice.

## Quick Start

Add DQuic to your `Cargo.toml`:

```toml
[dependencies]
dquic = "0.7.0-beta.4"
```

For complete usage instructions and runnable examples, see:

- [DQuic Usage Documentation](https://docs.dhttp.net/en/docs/protocol/dquic)
- [Client, server, and Stream examples](dquic/examples)
- [HTTP/3 examples](h3-shim/examples)

## Contributing

Contributions and discussions around DQuic usage and improvement are welcome. Use [GitHub Issues](https://github.com/genmeta/dquic/issues) to share ideas, suggest improvements, or report problems. If you have implemented an improvement, pull requests are welcome. Before contributing code, read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report security issues by following the process in [SECURITY.md](SECURITY.md).
