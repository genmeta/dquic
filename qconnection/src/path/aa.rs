use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use qbase::net::tx::{ArcSendWaker, Signals};

pub const DEFAULT_ANTI_FACTOR: usize = 3;
/// Therefore, after receiving packets from an address that is not yet validated,
/// an endpoint MUST limit the amount of data it sends to the unvalidated address
/// to N(three) times the amount of data received from that address.
#[derive(Debug)]
pub struct AntiAmplifier<const N: usize = DEFAULT_ANTI_FACTOR> {
    // Each time data is received, credit is increased;
    // each time data is sent, credit is consumed.
    credit: AtomicUsize,
    // If the credit is exhausted, it needs to wait until
    // new data is received before it can continue to send.
    tx_waker: ArcSendWaker,
    state: AtomicU8,
}

impl<const N: usize> AntiAmplifier<N> {
    const NORMAL: u8 = 0;
    const GRANTED: u8 = 1;
    const ABORTED: u8 = 2;

    pub fn new(tx_waker: ArcSendWaker) -> Self {
        Self {
            credit: AtomicUsize::new(0),
            tx_waker,
            state: AtomicU8::new(0),
        }
    }

    /// Store N * amount of credit
    #[allow(deprecated)] // `try_update` is not available on the crate's MSRV.
    pub fn on_rcvd(&self, amount: usize) {
        if self.state.load(Ordering::Acquire) != Self::NORMAL {
            return;
        }
        _ = self
            .credit
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |credit| {
                Some(credit.saturating_add(amount.saturating_mul(N)))
            });
        self.tx_waker.wake_by(Signals::CREDIT);
    }

    /// This function must only be called by one at a time, and the amount of data sent
    /// must be feed back to the anti-amplifier before poll_apply can be called again.
    pub fn balance(&self) -> Result<Option<usize>, Signals> {
        match self.state.load(Ordering::Acquire) {
            Self::GRANTED => Ok(Some(usize::MAX)),
            Self::ABORTED => Ok(None),
            Self::NORMAL => {
                let credit = self.credit.load(Ordering::Acquire);
                if credit == 0 {
                    // 再次检查，以防grant、abort在self.waker赋值前被调用，导致任务死掉
                    let state = self.state.load(Ordering::Acquire);
                    if state == Self::NORMAL {
                        Err(Signals::CREDIT)
                    } else {
                        self.tx_waker.wake_by(Signals::CREDIT);
                        if state == Self::GRANTED {
                            Ok(Some(usize::MAX))
                        } else {
                            Ok(None)
                        }
                    }
                } else {
                    Ok(Some(credit))
                }
            }
            _ => unreachable!(),
        }
    }

    #[allow(deprecated)] // `try_update` is not available on the crate's MSRV.
    pub fn on_sent(&self, amount: usize) {
        if self.state.load(Ordering::Acquire) == Self::NORMAL {
            _ = self
                .credit
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |credit| {
                    Some(credit.saturating_sub(amount))
                });
        }
    }

    pub fn grant(&self) {
        if self
            .state
            .compare_exchange(
                Self::NORMAL,
                Self::GRANTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.tx_waker.wake_by(Signals::CREDIT);
        }
    }

    pub fn abort(&self) {
        if self
            .state
            .compare_exchange(
                Self::NORMAL,
                Self::ABORTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.tx_waker.wake_by(Signals::CREDIT);
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use qbase::packet::{Packet, PacketReader};

    use super::*;

    #[test]
    fn udp_bytes_after_initial_length_count_toward_amplification_credit() {
        const INITIAL_PACKET_SIZE: usize = 290;
        const DATAGRAM_SIZE: usize = 1200;

        // The two-byte Length field is 272 (0x110 with the 01 varint prefix).
        // With the 18-byte long header, only the first 290 bytes belong to the
        // Initial packet. The remaining UDP payload is deliberately outside it.
        let mut datagram = BytesMut::from(
            &[
                0xc0, // Initial, packet number length 1
                0x00, 0x00, 0x00, 0x01, // QUIC v1
                8,    // DCID length
                0, 1, 2, 3, 4, 5, 6, 7, // DCID
                0, // SCID length
                0, // token length
                0x41, 0x10, // Length = 272
            ][..],
        );
        datagram.resize(INITIAL_PACKET_SIZE, 0);
        datagram.resize(DATAGRAM_SIZE, 0);

        let (Packet::Data(initial), datagram_size) = PacketReader::new(datagram, 8)
            .next()
            .expect("datagram contains an Initial packet")
            .expect("Initial packet is parseable")
        else {
            panic!("expected an Initial packet");
        };

        assert_eq!(initial.bytes.len(), INITIAL_PACKET_SIZE);
        assert_eq!(datagram_size, DATAGRAM_SIZE);

        let anti_amplifier = AntiAmplifier::<3>::new(ArcSendWaker::new());
        anti_amplifier.on_rcvd(datagram_size);

        assert_eq!(anti_amplifier.balance(), Ok(Some(DATAGRAM_SIZE * 3)));
        assert_ne!(
            anti_amplifier.balance(),
            Ok(Some(INITIAL_PACKET_SIZE * 3)),
            "credit must not be derived from the Initial packet Length field"
        );
    }

    #[test]
    fn test_deposit_and_poll_apply() {
        let waker = ArcSendWaker::new();
        let anti_amplifier = AntiAmplifier::<3>::new(waker);
        // Initially, no credit
        assert_eq!(anti_amplifier.balance(), Err(Signals::CREDIT));

        // Deposit 1 unit of data, should add 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        // Apply for 2 units of data, should return 2 units
        assert_eq!(anti_amplifier.balance(), Ok(Some(3)));
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        anti_amplifier.on_sent(3);

        // No credit left, should return Pending
        assert_eq!(anti_amplifier.balance(), Err(Signals::CREDIT));
    }

    #[test]
    fn test_multiple_deposits() {
        let waker = ArcSendWaker::new();
        let anti_amplifier = AntiAmplifier::<3>::new(waker);

        // Deposit 1 unit of data, should add 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        // Deposit another 1 unit of data, should add another 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 6);

        // Apply for 5 units of data, should return 5 units
        assert_eq!(anti_amplifier.balance(), Ok(Some(6)));
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 6);

        // Post sent 5 units, should reduce credit by 5
        anti_amplifier.on_sent(5);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 1);
    }

    #[test]
    fn sent_amount_larger_than_credit_does_not_underflow() {
        let anti_amplifier = AntiAmplifier::<3>::new(ArcSendWaker::new());
        anti_amplifier.on_rcvd(1);

        anti_amplifier.on_sent(4);

        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 0);
        assert_eq!(anti_amplifier.balance(), Err(Signals::CREDIT));
    }

    #[test]
    fn received_credit_saturates_instead_of_wrapping() {
        let anti_amplifier = AntiAmplifier::<3>::new(ArcSendWaker::new());

        anti_amplifier.on_rcvd(usize::MAX);

        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), usize::MAX);
    }
}
