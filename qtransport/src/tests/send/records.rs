pub use qrecovery::journal::*;

use crate::keys::PacketError;

impl From<RecordError> for PacketError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::Blocked => Self::Blocked(std::task::Poll::Pending),
            RecordError::Connection(error) => Self::Connection(error),
        }
    }
}
