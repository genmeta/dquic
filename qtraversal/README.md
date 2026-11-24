# qtraversal

## STUN server example

Build the standalone node with `cargo build --release -p qtraversal --example stun_server`.
It serves two UDP ports, supports public address mappings and changed-source
responses, and enables dquic forwarding with `--relay`. See
[deployment instructions](examples/stun-server/README.md) for the three-node
configuration and systemd files.

## Docker network unit tests

Run `bash qtraversal/tools/run.sh` from the workspace root. The ignored tests in
`punch::puncher::network_tests` drive two Punchers with a mock reliable broker and
real UDP/STUN traffic through isolated NATs. They cover RestrictedPort/Symmetric
in both active/passive roles, simultaneous active arbitration, retained probe
sockets and direct UDP round trips. Examples are independent of this harness.
See [the test guide](tools/README.md) for cases, topology and logs.

## Architecture

`qtraversal` owns connection-scoped NAT hole punching for QUIC. Applications
configure remote STUN nodes with `Dock::bootstrap(nodes)` and interface selection
with `with_socket_factory`, then create permanent sockets through `Dock::socket`.
Dock owns reception, publishes local endpoints, discovers Direct/Mediate mappings,
and publishes measured Link/NAT candidates through `ArcAddrBook`. Reception exit
cancels discovery before withdrawing endpoints, candidates and protocol routes.
The close callback runs after cleanup for permanent sockets only.

`ArcPuncher` keeps connection-specific address advertisements and punch
transactions, the active and passive NAT strategy matrix, port predictor and
probe scheduler. Temporary probe sockets own their Dock/QUIC registrations and
never enter ArcAddrBook. Dropping their owner asynchronously releases the registrations and socket without a close callback.

## ArcAddrBook integration

`ArcAddrBook::attach(sender)` replays all explicit candidates and then sends
ordered `Candidate::New { link, nat }` / `Invalid { link }` changes on the same
channel. `ArcPuncher::observe_candidates(receiver, scopes, closed)` consumes the
queued replay before returning and filters the outer address by the connection's
scopes. Endpoint publication and candidate observation are independent.

- Dock registers discovered candidates once their NAT type is known.
  Internal and loopback self Links are registered as FullCone when created.
- One Link identifies one actual socket → outer mapping. Direct and Mediate
  aliases of the same mapping do not create duplicate advertisements.
- NAT refresh withdraws and re-advertises that exact Link, cancelling transactions
  and completed history using its old sequence number. Another socket with the
  same outer address remains intact. Existing paths are not retired.
- `del_endpoint_addr` changes publication only. `del_candidate` withdraws the
  corresponding advertisement; `del_sock_addr` withdraws all of a socket's Links.
- Observed candidates use grouping value zero. Puncher construction takes only
  the reliable frame sender and packet encoder.

Punch addresses retain their Link: `link.src` finds the actual socket in Dock,
while `link.dst` is advertised in ADD_ADDRESS. Temporary probes use the actual
bound IP with a new port and never register candidates in ArcAddrBook.
Remote nodes come from the application's earlier `Dock::bootstrap(nodes)` call.
`StunProtocol::stun_servers(&self)` returns that node snapshot without DNS or I/O.
Punchers select a node matching the temporary socket's address family.
Both dynamic and predicted sockets use `Dock::global().ephemeral_socket(bound)`
with port zero, so the OS allocates each local port and the factory selects the
interface. Temporary sockets do not start Dock's automatic discovery, publish
candidates, or invoke `on_socket_closed`. The caller retains the owner of a winning
probe socket for the connection lifetime.
Address frames carry the Link's outer address.

The method returns a `JoinHandle<()>`. Resolving the supplied close future or
dropping the ArcAddrBook ends observation and drops the receiver. This does not
remove ordinary shared sockets. The connection lifecycle remains responsible for
aborting punch transactions and releasing retained temporary sockets.

## Connection integration

The caller provides a reliable frame sender and a `PunchPacketEncoder`.
`qtransport::punch::ProbeEncoder` implements this interface using the connection's
shared packet spaces and peer CID. Packet assembly and protection live in
`qtransport`; `qtraversal` manages traversal without depending on it.

Direct `PUNCH_HELLO` and `PUNCH_DONE` probes are sent on UDP sockets without a
Path. `qconnection::MaturePhase` now creates and retains a Puncher for both roles,
and authenticated 1-RTT reception dispatches all five punch/address frame types to
it while preserving the received UDP link. Reception currently obtains or creates
a path before packet authentication; deferring passive-path admission remains
connection integration work. After handshake confirmation, both connection
lifecycles start ArcAddrBook observation: clients observe all scopes and servers
use their listening scopes. The close future retains Paths until observation has finished applying the
current event. Candidate withdrawal updates Puncher and does not retire paths;
connection cleanup aborts transactions and releases retained temporary sockets.
