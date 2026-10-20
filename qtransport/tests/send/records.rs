use qbase::{
    error::Error,
    packet::{PacketNumber, Type, assemble::Metadata, r#type::short::OneRtt},
};
pub use qrecovery::journal::*;

use super::write::PacketError;

pub fn record_pending(
    journal: &ArcSentJournal,
    generation: impl Into<Option<u64>>,
    records: &mut Vec<qtransport::GuaranteedFrame>,
) -> Result<(u64, PacketNumber), Error> {
    let number = journal.next_pn()?;
    journal.on_sealed(
        number.0,
        generation.into(),
        0,
        Metadata::new(Type::Short(OneRtt(0.into()))),
        records.drain(..),
    );
    Ok(number)
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
    keys.reserve(|generation| record_pending(journal, generation, records).map_err(Into::into))
        .map_err(Into::into)
}
