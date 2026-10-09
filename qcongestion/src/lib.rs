use qbase::{Epoch, frame::AckFrame};
use qevent::quic::recovery::PacketLostTrigger;
use thiserror::Error;
use tokio::time::{Duration, Instant};

mod algorithm;
pub use algorithm::Algorithm;
mod congestion;
pub use congestion::{ArcCC, CongestionController};
mod pacing;
mod packets;
mod rtt;
mod status;
pub use status::{HandshakeStatus, PathStatus};

/// default datagram size in bytes.
pub const MSS: usize = 1200;

#[derive(Debug, Clone, Copy, Error)]
#[error("Too many PTOs: {0}")]
pub struct TooManyPtos(u32);

/// The [`Transport`] trait defines the interface for congestion control algorithms.
pub trait Transport {
    /// Performs a periodic tick to drive the congestion control algorithm.
    fn do_tick(&self) -> Result<(), TooManyPtos>;

    /// Returns how many bytes can be sent at the moment.
    /// Returns zero when the congestion controller is not ready.
    fn send_quota(&self) -> usize;

    /// Gets the retransmission and expiration time for the given epoch.
    fn retransmit_and_expire_time(&self, epoch: Epoch) -> (Duration, Duration);

    /// Records the sending of a packet, which may affect congestion control state.
    /// # Parameters
    /// - `pn`: The packet number of the sent packet.
    /// - `is_ack_eliciting`: A boolean indicating whether the packet is ack-eliciting.
    /// - `sent_bytes`: The number of bytes sent in this packet.
    /// - `in_flight`: A boolean indicating whether the packet is considered in-flight.
    /// - `ack`: An optional `u64` representing the largest acknowledged packet number if an AckFrame was included.
    fn on_pkt_sent(
        &self,
        epoch: Epoch,
        pn: u64,
        is_ack_eliciting: bool,
        sent_bytes: usize,
        in_flight: bool,
        ack: Option<u64>,
    );

    /// Records the receipt of a packet, which may influence future packet transmissions.
    /// # Parameters
    /// - `pn`: The packet number of the received packet.
    /// - `is_ack_elicition`: A boolean indicating whether the received packet is ack-eliciting.
    fn on_pkt_rcvd(&self, space: Epoch, pn: u64, is_ack_elicition: bool);

    /// Checks if an AckFrame should be sent in the next packet for the given epoch.
    /// # Returns
    /// An [`Option`] containing the largest packet ID and the time it was received if an AckFrame is needed.
    fn need_ack(&self, space: Epoch) -> Option<(u64, Instant)>;

    /// Checks if an ack-eliciting packet should be sent for the given epoch.
    fn need_send_ack_eliciting(&self, space: Epoch) -> usize;

    /// Updates the congestion control state upon receiving an AckFrame.
    fn on_ack_rcvd(&self, space: Epoch, ack_frame: &AckFrame);

    /// Retrieves the current path's PTO duration.
    /// # Returns
    /// The current PTO duration for the given epoch.
    fn get_pto(&self, epoch: Epoch) -> Duration;

    /// Discards the congestion control state for the specified epoch.
    fn discard_epoch(&self, epoch: Epoch);

    /// Releases the anti-amplification limit for this path.
    fn grant_anti_amplification(&self);
}

/// The [`Resend`] trait defines the interface for retransmitting lost packets.
pub trait Resend: Send + Sync {
    /// Indicates that a packet with the specified packet number may have been lost.
    /// # Parameters
    /// - `pn`: The packet number of the potentially lost packet.
    fn resend(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>);
}
