use std::{fmt, ops};

use crate::param::ParameterId;

/// Roles in the QUIC protocol, including client and server.
///
/// The least significant bit (0x01) of the [`StreamId`](crate::sid) identifies the initiator role of the stream.
/// Client-initiated streams have even-numbered stream IDs (with the bit set to 0),
/// and server-initiated streams have odd-numbered stream IDs (with the bit set to 1).
/// See [section-2.1-3](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1-3)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html).
///
/// # Note
///
/// As a protocol capable of multiplexing streams, QUIC is different from traditional
/// HTTP protocols for clients and servers.
/// In the QUIC protocol, it is not only the client that can actively open a new stream;
/// the server can also actively open a new stream to push some data to the client.
/// In fact, in a new stream, the server can initiate an HTTP3 request to the client,
/// and the client, upon receiving the request, responds back to the server.
/// In this case, the client surprisingly plays the role of the traditional "server",
/// which is quite fascinating.
///
/// # Example
///
/// ```
/// use qbase::role::Role;
///
/// let local = Role::Client;
/// let peer = !local;
/// let is_client = matches!(local, Role::Client); // true
/// let is_server = matches!(peer, Role::Server); // true
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Role {
    /// The initiator of a connection
    Client = 0,
    /// The acceptor of a connection
    Server = 1,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match *self {
            Self::Client => "client",
            Self::Server => "server",
        })
    }
}

impl ops::Not for Role {
    type Output = Self;
    fn not(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

pub trait IntoRole {
    /// Convert the type into a [`Role`].
    fn into_role() -> Role;
}

pub trait RequiredParameters {
    fn required_parameters() -> impl IntoIterator<Item = ParameterId>;
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Client;

impl From<Client> for Role {
    fn from(_: Client) -> Self {
        Role::Client
    }
}

impl IntoRole for Client {
    fn into_role() -> Role {
        Role::Client
    }
}

impl RequiredParameters for Client {
    fn required_parameters() -> impl IntoIterator<Item = ParameterId> {
        [ParameterId::InitialSourceConnectionId].into_iter()
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Server;

impl From<Server> for Role {
    fn from(_: Server) -> Self {
        Role::Server
    }
}

impl IntoRole for Server {
    fn into_role() -> Role {
        Role::Server
    }
}

impl RequiredParameters for Server {
    fn required_parameters() -> impl IntoIterator<Item = ParameterId> {
        [ParameterId::InitialSourceConnectionId, ParameterId::OriginalDestinationConnectionId].into_iter()
    }
}
