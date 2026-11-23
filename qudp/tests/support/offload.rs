use std::{
    io::{self, IoSlice},
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
};

use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};

pub fn send_segmented(peer: &UdpSocket, destination: SocketAddr, payload: &[u8], segment_size: u16) -> io::Result<()> {
    let address = SockaddrStorage::from(destination);
    let buffers = [IoSlice::new(payload)];
    let controls = [ControlMessage::UdpGsoSegments(&segment_size)];
    let sent = sendmsg(peer.as_raw_fd(), &buffers, &controls, MsgFlags::empty(), Some(&address))?;
    assert_eq!(sent, payload.len());
    Ok(())
}
