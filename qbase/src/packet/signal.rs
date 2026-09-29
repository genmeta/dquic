/// The spin bit in 1-RTT packets
const SPIN_BIT: u8 = 0x20;
/// The key phase bit in 1-RTT packets
const KEY_PHASE_BIT: u8 = 0x04;

/// The toggle type, which can be used to represent the spin bit and key phase bit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Toggle<const B: u8> {
    /// Represents the bit is 0
    #[default]
    Zero,
    /// Represents the bit is 1
    One,
}

/// The spin bit in the 1-RTT packet.
pub type SpinBit = Toggle<SPIN_BIT>;

/// The key phase bit in the 1-RTT packet.
pub type KeyPhaseBit = Toggle<KEY_PHASE_BIT>;

impl<const B: u8> Toggle<B> {
    /// Toggle the bit, from 0 to 1, or from 1 to 0.
    pub fn toggle(&mut self) {
        *self = match self {
            Toggle::Zero => Toggle::One,
            Toggle::One => Toggle::Zero,
        }
    }

    /// Get the value of the bit.
    pub fn value(&self) -> u8 {
        match self {
            Toggle::Zero => 0,
            Toggle::One => B,
        }
    }

    /// Imply the bit to the byte.
    pub fn imply(&self, byte: &mut u8) {
        match self {
            Toggle::Zero => *byte &= !B,
            Toggle::One => *byte |= B,
        }
    }
}

impl<const B: u8> std::ops::Not for Toggle<B> {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Toggle::Zero => Toggle::One,
            Toggle::One => Toggle::Zero,
        }
    }
}

impl<const B: u8> From<u8> for Toggle<B> {
    fn from(value: u8) -> Self {
        if value & B == 0 {
            Toggle::Zero
        } else {
            Toggle::One
        }
    }
}

impl<const B: u8> From<Toggle<B>> for u8 {
    fn from(value: Toggle<B>) -> Self {
        value.value()
    }
}

impl<const B: u8> From<bool> for Toggle<B> {
    fn from(value: bool) -> Self {
        if value { Toggle::One } else { Toggle::Zero }
    }
}

impl<const B: u8> From<Toggle<B>> for bool {
    fn from(value: Toggle<B>) -> Self {
        match value {
            Toggle::Zero => false,
            Toggle::One => true,
        }
    }
}
