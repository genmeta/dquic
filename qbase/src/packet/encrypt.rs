use std::ops::Deref;

use rustls::quic::{HeaderProtectionKey, PacketKey};

use super::{KeyPhaseBit, LongSpecificBits, ShortSpecificBits};

/// Encrypt the packet body, applicable to both long and short packets.
///
/// It relies on the packet encryption key of the corresponding level and the packet
/// number to encrypt the packet body.
/// The packet body refers to the packet data located after the packet number,
/// specifically including the intergrity checksum codes at the end, which usually consist of
/// 16 bytes depending on the encryption algorithm.
///
/// # Note
///
/// Before encrypting the packet body, the entire packet content must be fully and
/// correctly populated, including the packet header and body, especially the last
/// few bits of the first byte.
pub fn encrypt_packet(key: &dyn PacketKey, pn: u64, pkt_buf: &mut [u8], body_offset: usize) {
    let (aad, body_tag) = pkt_buf.split_at_mut(body_offset);
    let (body, tag_buf) = body_tag.split_at_mut(body_tag.len() - key.tag_len());
    let tag = key.encrypt_in_place(pn, aad, body).unwrap();
    tag_buf.copy_from_slice(tag.as_ref());
}

/// Add header protection, applicable to both long and short packets.
/// Mainly protects the Reserved Bits and Packet Number Length in the packet header,
/// as well as the Packet Number.
///
/// Use the header protection key of the corresponding level to protect the header.
/// For long headers, the last 4 bits of the first byte are protected;
/// and for short headers, the last 5 bits of the first byte are protected.
///
/// This function uses the first bit of the first byte of the packet to determine
/// whether it is a long packet or a short packet, and then performs the corresponding
/// header protection.
///
/// ## Note
///
/// Before encrypting the packet body, the entire packet content must be fully and
/// correctly filled, including the packet header and body, especially the last
/// few bits of the first byte, and the packet body encryption must be completed.
pub fn protect_header(
    key: &dyn HeaderProtectionKey,
    pkt_buf: &mut [u8],
    payload_offset: usize,
    pn_len: usize,
) {
    let (predata, payload) = pkt_buf.split_at_mut(payload_offset);
    let first_byte = &mut predata[0];

    let (max_pn_buf, sample) = payload.split_at_mut(4);
    let sample_len = key.sample_len();
    key.encrypt_in_place(&sample[..sample_len], first_byte, &mut max_pn_buf[..pn_len])
        .unwrap();
}

/// Encode the last 4 specific bits of the first byte of the long packet, i.e.,
/// two reserved bits of 0 and two bits of packet number encoding length.
pub fn encode_long_first_byte(first_byte: &mut u8, pn_len: usize) {
    let specific_bits = LongSpecificBits::with_pn_len(pn_len);
    *first_byte |= specific_bits.deref();
}

/// Encode the last 5 specific bits of the first byte of the short packet, i.e.,
/// two reserverd bits of 0, one bit of key phase, and two bits of packet number encoding length.
pub fn encode_short_first_byte(first_byte: &mut u8, pn_len: usize, key_phase: KeyPhaseBit) {
    let mut specific_bits = ShortSpecificBits::with_pn_len(pn_len);
    specific_bits.set_key_phase(key_phase);
    *first_byte |= specific_bits.deref();
}
