use qbase::{Epoch, frame::AckFrame};
use tokio::time::Instant;

use crate::packets::SentPacket;

// pub(crate) mod bbr;
pub(crate) mod new_reno;

/// The [`Algorithm`] enum represents different congestion control algorithms that can be used.
pub enum Algorithm {
    Bbr,
    NewReno,
}

pub trait Control: Send {
    fn on_packet_sent_cc(&mut self, packet: &SentPacket);

    fn on_packet_acked(&mut self, acked_packet: &SentPacket);

    fn on_packets_lost(
        &mut self,
        lost_packets: &mut dyn Iterator<Item = &SentPacket>,
        persistent_lost: bool,
    );

    fn process_ecn(&mut self, ack: &AckFrame, sent_time: &Instant, epoch: Epoch);

    fn congestion_window(&self) -> usize;

    fn bytes_in_flight(&self) -> usize;

    fn pacing_rate(&self) -> Option<usize>;

    fn remove_from_bytes_in_flight(&mut self, packets: &mut dyn Iterator<Item = &SentPacket>);
}
