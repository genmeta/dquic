# qtraversal

`qtraversal` owns connection-scoped NAT hole punching for QUIC. `qprotocol::Dock`
registers sockets and manages their receive tasks. `AddressBook` owns the local
endpoint directory, NAT records and ordered address subscriptions. The network
owner registers socket aliases with `QuicProtocol` before publishing endpoints,
and runs STUN mapping discovery and NAT classification independently.

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
- Advertisements use grouping value zero. The existing Puncher constructor still
  receives the STUN servers used by temporary-socket mapping probes.

Punch addresses keep the actual bound address used to find the socket in Dock.
Temporary probes use the local bound address with a new port.
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
Path. The remaining qconnection integration must authenticate received probes,
admit and validate passive paths, dispatch punch frames, and own Puncher shutdown.
The crate is a workspace member; this address adapter does not yet enable punching
inside `QuicEndpoint` connections.
