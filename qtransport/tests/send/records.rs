pub use qrecovery::journal::*;

use super::write::PacketError;

impl From<RecordError> for PacketError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::Blocked => Self::Blocked(std::task::Poll::Pending),
            RecordError::Connection(error) => Self::Connection(error),
        }
    }
}

pub fn reserve(
    keys: &qtransport::keys::OneRttKeys,
    journal: &ArcSentJournal,
    records: &mut Vec<qtransport::GuaranteedFrame>,
) -> Result<
    (
        (u64, qbase::packet::PacketNumber),
        qtransport::keys::OneRttSealingKey,
    ),
    PacketError,
> {
    let mut record_error = None;
    keys.reserve(|generation| {
        journal.record_pending(generation, records).map_err(|error| {
            record_error = Some(error);
            // Return the journal error without counting an AEAD use.
            qtransport::keys::PacketError::Layout
        })
    })
    .map_err(|error| match record_error {
        Some(error) => error.into(),
        None => error.into(),
    })
}
