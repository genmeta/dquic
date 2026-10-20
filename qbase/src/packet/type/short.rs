use bytes::BufMut;
use derive_more::Deref;

use crate::packet::SpinBit;

const SHORT_HEADER_BIT: u8 = 0x00;

/// The type of the 1-Rtt packet.
/// For simplicity, the spin bit is also one part of the 1-Rtt packet type.
#[derive(Debug, Clone, Copy, Deref, PartialEq, Eq)]
pub struct OneRtt(#[deref] pub SpinBit);

impl From<u8> for OneRtt {
    fn from(value: u8) -> Self {
        OneRtt(SpinBit::from(value))
    }
}

impl From<OneRtt> for u8 {
    fn from(one_rtt: OneRtt) -> Self {
        SHORT_HEADER_BIT | super::FIXED_BIT | one_rtt.0.value()
    }
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly to write the short packet type.
pub trait WriteShortType: BufMut {
    /// Write the short packet type to the buffer.
    fn put_short_type(&mut self, ty: &OneRtt);
}

impl<B: BufMut> WriteShortType for B {
    fn put_short_type(&mut self, ty: &OneRtt) {
        self.put_u8((*ty).into());
    }
}
