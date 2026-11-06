//! Datagram write windows and once-per-datagram budget settlement.
use std::io::Cursor;

use qbase::{
    Epoch,
    packet::assemble::{Constraints as PacketLimits, Metadata},
};
use qcongestion::{ArcCC, Transport as _};

/// Balances reserved once for a burst.
#[derive(Clone, Default)]
pub struct Constraints {
    pub send_quota: usize,
    pub credit: usize,
    pub probe_quota: [usize; 3],
    /// Datagram envelope bytes, charged once when a datagram is assembled.
    pub overhead: usize,
}

impl Constraints {
    pub(super) fn windows(&self, length: usize) -> [Option<(usize, Self)>; 2] {
        let credit = self.credit.saturating_sub(self.overhead);
        let send_quota = self.send_quota.saturating_sub(self.overhead);
        let probe_quota = self
            .probe_quota
            .map(|quota| quota.saturating_sub(self.overhead));
        let quota = if send_quota > 0 {
            send_quota
        } else {
            probe_quota.into_iter().max().unwrap_or(0)
        };
        let control_len = length.min(credit).min(1200);
        let length = control_len.min(if quota == 0 { 1200 } else { quota });
        let control = Self {
            send_quota: 0,
            ..self.clone()
        };
        [
            (length > 0).then(|| (length, self.clone())),
            (control_len > length).then_some((control_len, control)),
        ]
    }

    pub(super) fn packet(
        &self,
        epoch: Epoch,
        cc: &ArcCC,
        bytes: &Cursor<&mut [u8]>,
    ) -> PacketLimits {
        let send_quota = self
            .send_quota
            .min(cc.send_quota())
            .saturating_sub(self.overhead);
        let probe_quota = self.probe_quota[epoch].saturating_sub(self.overhead);
        let max_size = if epoch == Epoch::Initial
            && (bytes.get_ref().len() < 1200 || send_quota.max(probe_quota) < 1200)
        {
            0
        } else {
            bytes
                .get_ref()
                .len()
                .saturating_sub(bytes.position() as usize)
        };
        PacketLimits {
            send_quota,
            probe_quota,
            credit: self.credit.saturating_sub(self.overhead),
            max_size,
            ..Default::default()
        }
    }

    pub(super) fn on_assembled(&mut self, size: usize, packets: &[Metadata]) {
        self.credit -= size + self.overhead;
        let in_flight: usize = packets
            .iter()
            .filter(|meta| meta.in_flight)
            .map(|meta| meta.pktlen)
            .sum();
        if in_flight > 0 {
            self.send_quota = self.send_quota.saturating_sub(in_flight + self.overhead);
        }
        for meta in packets {
            self.probe_quota[meta.epoch()] = 0;
        }
    }
}
