use qbase::ArcReceiving;

/// Packet engines produce these facts; growing is their only consumer.
/// `true` reports success; `false` ends the corresponding wait after an abnormal stop.
/// The actual connection error is submitted separately through the close signal.
#[derive(Clone, Default)]
pub struct HandshakeSignals {
    pub rcvd_and_decrypted_hs_packet: ArcReceiving<bool>,
    pub rcvd_and_decrypted_1rtt_packet: ArcReceiving<bool>,
    pub rcvd_handshake_done_frame: ArcReceiving<bool>,
    pub sent_handshake_packet: ArcReceiving<bool>,
}
