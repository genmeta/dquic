#[path = "type/long.rs"]
mod long;
#[path = "type/short.rs"]
mod short;

use qbase::packet::{KeyPhaseBit, error::Error, r#type::*};

#[test]
fn test_long_clear_bits() {
    let specific_bits = SpecificBits::<0x0C>::from(0x0C);
    assert_eq!(
        specific_bits.pn_len(),
        Err(Error::InvalidReservedBits(0x0C, 0x0C))
    );
    let specific_bits = SpecificBits::<0x0C>::from(0x04);
    assert_eq!(
        specific_bits.pn_len(),
        Err(Error::InvalidReservedBits(0x04, 0x0C))
    );
    let specific_bits = SpecificBits::<0x0C>::from(0x08);
    assert_eq!(
        specific_bits.pn_len(),
        Err(Error::InvalidReservedBits(0x08, 0x0C))
    );

    let specific_bits = LongSpecificBits::with_pn_len(4);
    assert_eq!(specific_bits.pn_len().unwrap(), 4);
    let specific_bits = LongSpecificBits::with_pn_len(3);
    assert_eq!(specific_bits.pn_len().unwrap(), 3);
    let specific_bits = LongSpecificBits::with_pn_len(2);
    assert_eq!(specific_bits.pn_len().unwrap(), 2);
    let specific_bits = LongSpecificBits::with_pn_len(1);
    assert_eq!(specific_bits.pn_len().unwrap(), 1);
}

#[test]
fn test_short_specific_bits() {
    let specific_bits = SpecificBits::<0x18>::from(0x18);
    assert_eq!(
        specific_bits.pn_len(),
        Err(Error::InvalidReservedBits(0x18, 0x18))
    );
    let specific_bits = SpecificBits::<0x18>::from(0x11);
    assert_eq!(
        specific_bits.pn_len(),
        Err(Error::InvalidReservedBits(0x10, 0x18))
    );
    let specific_bits = SpecificBits::<0x18>::from(0x0A);
    assert_eq!(
        specific_bits.pn_len(),
        Err(Error::InvalidReservedBits(0x08, 0x18))
    );

    let specific_bits = ShortSpecificBits::with_pn_len(4);
    assert_eq!(specific_bits.pn_len().unwrap(), 4);
    let specific_bits = ShortSpecificBits::with_pn_len(3);
    assert_eq!(specific_bits.pn_len().unwrap(), 3);
    let specific_bits = ShortSpecificBits::with_pn_len(2);
    assert_eq!(specific_bits.pn_len().unwrap(), 2);
    let specific_bits = ShortSpecificBits::with_pn_len(1);
    assert_eq!(specific_bits.pn_len().unwrap(), 1);
}

#[test]
fn test_set_key_phase_bit() {
    let mut specific_bits = ShortSpecificBits::with_pn_len(4);
    assert_eq!(*specific_bits, 0x03);
    specific_bits.set_key_phase(KeyPhaseBit::One);
    assert_eq!(*specific_bits, 0x07);
    assert_eq!(specific_bits.key_phase(), KeyPhaseBit::One);
    specific_bits.set_key_phase(KeyPhaseBit::Zero);
    assert_eq!(*specific_bits, 0x03);
    assert_eq!(specific_bits.key_phase(), KeyPhaseBit::Zero);
}
