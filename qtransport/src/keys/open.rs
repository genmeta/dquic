//! Remove header protection before decoding PN, then authenticate the body.
use qbase::packet::{PacketNumber, number::take_pn_len};

use super::PacketError;

/// Remove header protection in place and return the truncated packet number.
/// Reserved bits and Key Phase are not authenticated at this stage.
pub fn header(key: &qtls::HeaderProtectionKey, buffer: &mut [u8], pn_offset: usize) -> Result<PacketNumber, PacketError> {
    let sample_start = pn_offset.checked_add(4).ok_or(PacketError::Layout)?;
    let sample_end = sample_start.checked_add(key.sample_len()).ok_or(PacketError::Layout)?;
    if pn_offset == 0 || sample_end > buffer.len() {
        return Err(PacketError::Layout);
    }
    let (header, sample) = buffer.split_at_mut(sample_start);
    let (prefix, pn_bytes) = header.split_at_mut(pn_offset);
    key.unprotect(&sample[..key.sample_len()], &mut prefix[0], pn_bytes)?;
    let pn_len = (buffer[0] & 3) + 1;
    take_pn_len(pn_len)(&buffer[pn_offset..]).map(|(_, pn)| pn).map_err(|_| PacketError::Layout)
}

/// Decrypt ciphertext and tag in place, using the preceding header as AAD.
/// On authentication failure the buffer may have been modified by the backend.
pub fn body(key: &qtls::PacketKey, pn: u64, buffer: &mut [u8], body_offset: usize) -> Result<usize, PacketError> {
    if body_offset == 0 || body_offset > buffer.len() || buffer.len() - body_offset < key.tag_len() {
        return Err(PacketError::Layout);
    }
    let (header, body) = buffer.split_at_mut(body_offset);
    key.open(pn, header, body).map(|plain| plain.len()).map_err(|_| PacketError::AuthenticationFailed)
}
