mod connection_id;
pub use connection_id::*;

mod local_cid;
pub use local_cid::*;

mod remote_cid;
pub use remote_cid::*;

/// When issuing a CID to the peer, be careful not to duplicate
/// other local connection IDs, as this will cause routing conflicts.
pub trait GenUniqueCid {
    /// Generate a unique connection ID.
    #[must_use]
    fn gen_unique_cid(&self) -> ConnectionId;
}

pub trait RetireCid {
    /// Retire a connection ID.
    fn retire_cid(&self, cid: ConnectionId);
}

/// Connection ID registry.
///
/// - `local` represents the management of connection IDs issued by me to peer,
/// - `remote` represents the reception of connection IDs issued by peer,
///   which will be used by the path.
#[derive(Debug, Clone)]
pub struct Registry<LOCAL, REMOTE> {
    pub local: LOCAL,
    pub remote: REMOTE,
}

impl<LOCAL, REMOTE> Registry<LOCAL, REMOTE> {
    /// Create a new connection ID registry.
    pub fn new(local: LOCAL, remote: REMOTE) -> Self {
        Self { local, remote }
    }
}
