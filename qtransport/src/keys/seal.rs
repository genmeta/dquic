//! Encrypt the body before applying header protection.
use super::PacketError;

/// Encrypt in place and fill the authentication tag reserved at the buffer's end.
pub fn body(key: &qtls::PacketKey, pn: u64, buffer: &mut [u8], body_offset: usize) -> Result<(), PacketError> {
    let tag_offset = buffer.len().checked_sub(key.tag_len()).ok_or(PacketError::Layout)?;
    if body_offset == 0 || body_offset > tag_offset {
        return Err(PacketError::Layout);
    }
    let (header, body_tag) = buffer.split_at_mut(body_offset);
    let (body, tag) = body_tag.split_at_mut(tag_offset - body_offset);
    key.seal(pn, header, body, tag)?;
    Ok(())
}

/// Protect the first byte and PN, sampling ciphertext at pn_offset + 4.
pub fn header(key: &qtls::HeaderProtectionKey, buffer: &mut [u8], pn_offset: usize, pn_len: usize) -> Result<(), PacketError> {
    let sample_start = pn_offset.checked_add(4).ok_or(PacketError::Layout)?;
    let sample_end = sample_start.checked_add(key.sample_len()).ok_or(PacketError::Layout)?;
    if pn_offset == 0 || !(1..=4).contains(&pn_len) || sample_end > buffer.len() {
        return Err(PacketError::Layout);
    }
    let (header, sample) = buffer.split_at_mut(sample_start);
    let (prefix, pn_bytes) = header.split_at_mut(pn_offset);
    key.protect(&sample[..key.sample_len()], &mut prefix[0], &mut pn_bytes[..pn_len])?;
    Ok(())
}
