<p align="center">
  <a href="https://github.com/genmeta/dquic" title="DQuic">
    <img src="images/dquic-logo.svg" width="348" height="96" alt="DQuic">
  </a>
</p>
<h3 align="center">A QUIC extension that enables peer-to-peer communication and multipath transport.</h3>

[![Crates.io](https://img.shields.io/crates/v/dquic?label=crates.io)](https://crates.io/crates/dquic)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-dhttp.net-ff9900.svg)](https://docs.dhttp.net/en/docs/protocol/dquic)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-dea584.svg)](https://www.rust-lang.org/)

**English** | [简体中文](README_CN.md)

**The Internet connects networks, but not every endpoint.** The Internet now spans the globe, yet servers remain the endpoints that can reliably accept incoming connections. Ordinary endpoints—including computers, phones, NAS systems, and Raspberry Pi boards—are online but can usually only initiate outbound connections. Endpoint communication, message synchronization, and data transfer therefore still depend on cloud servers, creating cloud-centric **partial connectivity** rather than endpoint-to-endpoint **full connectivity**.

DQuic introduces public delegate endpoints for endpoints in private networks, giving ordinary endpoints a publicly reachable entry point through which they can establish connections with one another. **A public delegate is neither permanently deployed infrastructure nor a central server that must remain online indefinitely.** Any endpoint with public Internet reachability and the required capabilities can assume this role while online. This model makes a decentralized Internet possible, with ordinary public endpoints participating anonymously and collectively providing communication assistance.

<p align="center">
  <img src="images/dquic-connectivity-en.png" alt="DQuic extends cloud-centric partial connectivity into full connectivity between endpoints">
</p>

## Peer-to-Peer Communication

In DQuic, **a direct path is no longer a prerequisite for establishing a connection**. Two endpoints that cannot yet communicate directly can first establish a connection over an initial path, then attempt to obtain a direct path within that connection. This mechanism draws on the in-connection NAT traversal approach proposed by [Using QUIC to traverse NATs](https://datatracker.ietf.org/doc/html/draft-seemann-quic-nat-traversal-02). The draft remains preliminary: although it defines related extension frames and identifies capabilities such as STUN and `signaling` as requirements for NAT traversal, it does not fully specify how those capabilities integrate with QUIC. Building on this work, DQuic implements a complete NAT traversal workflow, introduces the `ep-&EP` pair model, and integrates STUN, `signaling`, and Relay into the QUIC protocol framework.

In this model, an endpoint `ep` in a private network pairs with at least one public endpoint `EP`, which acts as `ep`'s public delegate. The two communicating endpoints first establish a connection using previously obtained Endpoint Addresses, then exchange additional candidate addresses and attempt to establish a directly reachable path.

> [!NOTE]
> **Endpoint Address**
>
> An Endpoint Address describes how an endpoint is currently reachable. A directly reachable endpoint uses one transport address—an IP address and port. For an endpoint in a private network, the Endpoint Address combines the public delegate's public transport address with the endpoint's publicly mapped transport address. DDns uses Endpoint Address Records (E records) to associate a stable name with one or more current Endpoint Addresses. See the [DDns Protocol Documentation](https://docs.dhttp.net/en/docs/protocol/ddns) and the [open-source DDns implementation](https://github.com/genmeta/ddns).

A validated direct path joins the existing connection. If no direct path can be established, the connection can continue over a path through the public delegate; the application does not need to establish a new session.

For details of the NAT traversal design and protocol extensions, see the [DQuic Protocol Documentation](https://docs.dhttp.net/en/docs/protocol/dquic).

## Multipath Transport

An endpoint may be connected through Wi-Fi, cellular, and Ethernet simultaneously and may have multiple IPv4 and IPv6 addresses. Two endpoints can therefore form multiple candidate paths.

Standard QUIC completes its handshake over a single initial path. DQuic can attempt multiple paths in parallel for the same connection and complete the handshake over an available path, improving the likelihood of successful connection establishment and NAT traversal. After the handshake, other validated paths can join the connection; as the network changes, communication can continue over paths that remain valid.

As IPv6 adoption grows, DQuic can use a direct IPv6 path when both endpoints can communicate over IPv6 and network policy permits it, avoiding NAT traversal on that path. If IPv6 is unavailable, DQuic can try other paths or fall back to a path through a public delegate.

For details of multipath handshake, path validation, and scheduling, see the [DQuic Protocol Documentation](https://docs.dhttp.net/en/docs/protocol/dquic).

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

Discussion and contributions that improve DQuic are welcome. Use [GitHub Issues](https://github.com/genmeta/dquic/issues) to share ideas, suggest improvements, or report problems. If you have implemented an improvement, pull requests are welcome. Before contributing code, read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report security issues by following the process in [SECURITY.md](SECURITY.md).
