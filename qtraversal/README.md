# qtraversal

## STUN server example

Build the standalone node with `cargo build --release -p qtraversal --example stun_server`.
It serves two UDP ports, supports public address mappings and changed-source
responses, and enables dquic forwarding with `--relay`. See
[deployment instructions](examples/stun-server/README.md) for the three-node
configuration and systemd files.

## Architecture

`qtraversal` owns connection-scoped NAT hole punching for QUIC. `qprotocol::Dock`
registers sockets, their direct QUIC addresses and receive tasks. `AddressBook`
owns the local endpoint directory, NAT records and ordered address subscriptions.
The network owner registers extra socket aliases with `QuicProtocol` before
explicitly publishing endpoints through `AddressBook`. It withdraws addresses
through `AddressBook::remove_bound(bound)` before removing the socket from Dock;
Dock revokes every QUIC endpoint for that binding with `unregister(bound)`.
The network owner runs STUN mapping discovery and NAT classification independently.

`ArcPuncher` keeps connection-specific address advertisements and punch
transactions, the active and passive NAT strategy matrix, port predictor and
probe scheduler. Temporary probe sockets own their Dock/QUIC registrations and
never enter AddressBook. Dropping their owner releases the registrations.

## AddressBook integration

`ArcPuncher::observe_endpoints` consumes the receiver from
`AddressBook::subscribe_punch(scopes)`. It processes queued replay before returning,
then consumes `Added`, `Removed` and `BoundRemoved` in order. Each `Added` carries
a concrete NAT type for advertisement. AddressBook withholds external endpoints
until classification is known, then emits `Added`. Classification changes refresh
existing external endpoints through `Added`; there is no separate NAT event.

- Each binding can have multiple endpoints; removing one leaves its siblings intact.
- Internal and loopback Direct endpoints advertise immediate reachability using
  `FullCone` in the wire frame. This does not change the binding's stored NAT result.
- External Direct endpoints wait for a NAT result before advertising.
- NAT changes withdraw and re-advertise affected external endpoints, cancelling
  transactions using the old sequence numbers. They do not retire existing paths.
- Endpoint withdrawal invokes the removal callback even if NAT discovery had not
  yet allowed an advertisement. Binding withdrawal also reports its actual Direct
  address. Path retirement callbacks should be idempotent.
- Advertisements use grouping value zero. Puncher construction takes only the
  reliable frame sender and packet encoder.

Punch addresses keep the actual bound address used to find the socket in Dock.
Temporary probes use the local bound address with a new port.
The STUN module fixes the name to `nat.genmeta.net`. `StunProtocol::global()`
starts one background task to warm `StunProtocol::stun_servers()`. The global
Dock uses this STUN instance. The function-local static
cache shares one system DNS lookup on port 20002 across the process, including
empty results and errors, without retries or periodic refresh. All Punchers wait
for that same result and select a server matching the temporary socket's family.
Cancelling a waiter does not cancel or restart DNS.
`EphemeralSocket::bind(bound)` binds that target address and registers it with the
global Dock and QUIC protocol. It does not reconstruct or resolve a BindUri.
Address frames carry the endpoint's advertised address.

The method returns a `JoinHandle<()>`. Resolving the supplied close future or
dropping the AddressBook ends observation and drops the receiver. This does not
remove ordinary shared sockets. The connection lifecycle remains responsible for
aborting punch transactions and releasing retained temporary sockets.

## Connection integration

The caller provides a reliable frame sender and a `ProbeEncoder` constructed from
its shared `qtransport::DataSpace` and peer CID. `qtraversal` owns probe assembly
and protection, reusing `qtransport::packet::assemble`.

Direct `PUNCH_HELLO` and `PUNCH_DONE` probes are sent on UDP sockets without a
Path. `qconnection::MaturePhase` now creates and retains a Puncher for both roles,
and authenticated 1-RTT reception dispatches all five punch/address frame types to
it while preserving the received UDP link. Reception currently obtains or creates
a path before packet authentication; deferring passive-path admission remains
connection integration work. After handshake confirmation, both connection
lifecycles start AddressBook observation: clients observe all scopes and servers
use their listening scopes. Observation stops before connection cleanup and also
when the lifecycle coroutine is dropped. Address withdrawal updates only Puncher;
the removal callback does not retire paths. Path validation and Puncher shutdown
remain separate connection integration work.
