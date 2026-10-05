//! ACK handling for established connections.
use std::sync::Arc;

use qbase::{
    Epoch,
    frame::AckFrame,
    param::ParameterId,
    varint::{VARINT_MAX, VarInt},
};

use crate::{
    ArcParameters, Error,
    path::Path,
    space::{DataSpace, Recover},
};

/// Data ACK pipe target. Capture the original components when wiring reception.
/// Lock the receiving path CC before the journal, so ACK observes committed sends.
/// Report the highest acknowledged generation to the receive task's ready OneRttKeys.
pub fn acknowledge(
    data: &DataSpace,
    parameters: &ArcParameters,
    ack: &AckFrame,
    received_on: &Arc<Path>,
    on_ack: impl Fn(u64),
) -> Result<(), Error> {
    let acknowledged = {
        let mut congestion = received_on.cc.lock();
        let exponent: u64 = parameters.remote(ParameterId::AckDelayExponent);
        let delay = ack
            .delay()
            .checked_shl(exponent as u32)
            .unwrap_or(VARINT_MAX)
            .min(VARINT_MAX);
        let acknowledged = data.on_acked(ack)?;
        let ack = AckFrame::new(
            VarInt::from_u64(ack.largest()).unwrap(),
            VarInt::from_u64(delay).unwrap(),
            VarInt::from_u64(ack.first_range()).unwrap(),
            ack.ranges().clone(),
            ack.ecn(),
        );
        congestion.on_ack_rcvd(Epoch::Data, &ack, tokio::time::Instant::now());
        acknowledged
    };
    if let Some(generation) = acknowledged {
        on_ack(generation);
    }
    received_on.send_waker.wake_all();
    Ok(())
}
