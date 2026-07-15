use std::{
    io::{self, IoSlice},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsFd, AsRawFd},
};

use nix::{
    cmsg_space,
    sys::socket::{
        ControlMessageOwned, SockaddrLike, SockaddrStorage,
        sockopt::{self},
    },
};
use qbase::net::route::Line;
use socket2::Socket;

use crate::{BoundDevice, Io, UdpSocket};

const OPTION_ON: bool = true;

impl Io for UdpSocket {
    fn config(socket: &Socket, addr: SocketAddr) -> io::Result<()> {
        let io = socket.as_fd();
        nix::sys::socket::setsockopt(&io, sockopt::RcvBuf, &(2 * 1024 * 1024))?;
        match addr {
            SocketAddr::V4(_) => {
                #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
                {
                    nix::sys::socket::setsockopt(&io, sockopt::IpDontFrag, &OPTION_ON)?;
                    nix::sys::socket::setsockopt(&io, sockopt::Ipv4RecvDstAddr, &OPTION_ON)?;
                }
                #[cfg(any(
                    target_os = "android",
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "netbsd"
                ))]
                nix::sys::socket::setsockopt(&io, sockopt::Ipv4Ttl, &(Line::DEFAULT_TTL as i32))?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv4PacketInfo, &OPTION_ON)?;
            }
            SocketAddr::V6(_) => {
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6V6Only, &OPTION_ON)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6RecvPacketInfo, &OPTION_ON)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6DontFrag, &OPTION_ON)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6Ttl, &(Line::DEFAULT_TTL as i32))?;
            }
        }

        socket.bind(&addr.into())
    }

    fn bind_device_to_socket(
        socket: &socket2::SockRef<'_>,
        addr: SocketAddr,
        device: &BoundDevice,
    ) -> io::Result<()> {
        let _ = addr;
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            if let Err(error) = socket.bind_device(Some(device.name().as_bytes())) {
                tracing::debug!(
                    target: "qudp",
                    interface = device.name(),
                    ifindex = device.index().get(),
                    %error,
                    "failed to apply socket-level device binding; sendmsg packet info will constrain egress interface"
                );
            }
            return Ok(());
        }

        #[cfg(target_os = "fuchsia")]
        {
            return socket.bind_device(Some(device.name().as_bytes()));
        }

        #[cfg(any(
            target_os = "ios",
            target_os = "visionos",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos",
        ))]
        {
            return match addr {
                SocketAddr::V4(..) => socket.bind_device_by_index_v4(Some(device.index())),
                SocketAddr::V6(..) => socket.bind_device_by_index_v6(Some(device.index())),
            };
        }

        #[allow(unreachable_code)]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "binding UDP socket to interface {} is unsupported on this platform",
                device.name()
            ),
        ))
    }

    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    fn sendmsg(&self, buffers: &[IoSlice<'_>], line: &Line) -> io::Result<usize> {
        use nix::{
            errno::Errno,
            sys::socket::{MsgFlags, MultiHeaders, SockaddrIn, SockaddrIn6, sendmmsg},
        };

        use super::BATCH_SIZE;
        let slices: Vec<_> = buffers
            .iter()
            .take(BATCH_SIZE)
            .map(std::slice::from_ref)
            .collect();

        let batch_size = slices.len();
        if batch_size == 0 {
            return Ok(0);
        }
        let mut cmsgs = Vec::new();
        #[cfg(feature = "gso")]
        let has_gso = true;
        #[cfg(not(feature = "gso"))]
        let has_gso = false;
        #[cfg(feature = "gso")]
        cmsgs.push(nix::sys::socket::ControlMessage::UdpGsoSegments(
            &line.seg_size,
        ));

        #[cfg(any(target_os = "android", target_os = "linux"))]
        #[derive(Clone, Copy)]
        enum PacketInfoKind {
            V4,
            V6,
        }
        #[cfg(any(target_os = "android", target_os = "linux"))]
        let mut packet_info_kind = None;
        #[cfg(any(target_os = "android", target_os = "linux"))]
        let v4_pktinfo;
        #[cfg(any(target_os = "android", target_os = "linux"))]
        let v6_pktinfo;

        #[cfg(any(target_os = "android", target_os = "linux"))]
        if let Some(device) = self.bound_device.as_ref() {
            let src = if line.src.ip().is_unspecified() {
                self.io.local_addr()?
            } else {
                line.src
            };
            match src.ip() {
                IpAddr::V4(src) => {
                    v4_pktinfo = libc::in_pktinfo {
                        ipi_ifindex: device.index().get() as _,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(src.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    cmsgs.push(nix::sys::socket::ControlMessage::Ipv4PacketInfo(
                        &v4_pktinfo,
                    ));
                    packet_info_kind = Some(PacketInfoKind::V4);
                }
                IpAddr::V6(src) => {
                    v6_pktinfo = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: src.octets(),
                        },
                        ipi6_ifindex: device.index().get() as _,
                    };
                    cmsgs.push(nix::sys::socket::ControlMessage::Ipv6PacketInfo(
                        &v6_pktinfo,
                    ));
                    packet_info_kind = Some(PacketInfoKind::V6);
                }
            }
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        let space = match (has_gso, packet_info_kind) {
            (false, None) => None,
            (true, None) => Some(cmsg_space!(libc::c_int)),
            (false, Some(PacketInfoKind::V4)) => Some(cmsg_space!(libc::in_pktinfo)),
            (false, Some(PacketInfoKind::V6)) => Some(cmsg_space!(libc::in6_pktinfo)),
            (true, Some(PacketInfoKind::V4)) => Some(cmsg_space!(libc::c_int, libc::in_pktinfo)),
            (true, Some(PacketInfoKind::V6)) => Some(cmsg_space!(libc::c_int, libc::in6_pktinfo)),
        };
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        let space = has_gso.then_some(cmsg_space!(libc::c_int));

        macro_rules! send_batch {
            ($ty:ty, $addr:expr) => {{
                let sock_addr = <$ty>::from($addr);
                let addrs = vec![Some(sock_addr); BATCH_SIZE];
                let mut data = MultiHeaders::<$ty>::preallocate(BATCH_SIZE, space);
                match sendmmsg(
                    self.io.as_raw_fd(),
                    &mut data,
                    &slices,
                    &addrs,
                    &cmsgs,
                    MsgFlags::empty(),
                ) {
                    Ok(ret) => Ok(ret.count()),
                    Err(e @ (Errno::EINTR | Errno::EAGAIN | Errno::ENOBUFS)) => {
                        Err(io::Error::new(io::ErrorKind::WouldBlock, e))
                    }
                    Err(e) => Err(e.into()),
                }
            }};
        }

        match line.dst {
            SocketAddr::V4(v4) => send_batch!(SockaddrIn, v4),
            SocketAddr::V6(v6) => send_batch!(SockaddrIn6, v6),
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "tvos"
    ))]
    fn sendmsg(&self, slices: &[IoSlice<'_>], send_line: &Line) -> io::Result<usize> {
        use nix::{
            errno::Errno,
            sys::socket::{MsgFlags, SockaddrIn, SockaddrIn6, sendmsg},
        };
        let mut sent_packet = 0;
        for slice in slices.iter() {
            macro_rules! send_batch {
                ($ty:ty, $addr:expr) => {{
                    let sock_addr = <$ty>::from($addr);
                    match sendmsg(
                        self.io.as_raw_fd(),
                        &[*slice],
                        &[],
                        MsgFlags::empty(),
                        Some(&sock_addr),
                    ) {
                        Ok(_send_bytes) => sent_packet += 1,
                        Err(_) if sent_packet > 0 => return Ok(sent_packet),
                        Err(Errno::EINTR) => continue,
                        Err(e @ (Errno::EAGAIN | Errno::ENOBUFS)) => {
                            return Err(io::Error::new(io::ErrorKind::WouldBlock, e));
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                }};
            }

            match send_line.dst {
                SocketAddr::V4(v4) => send_batch!(SockaddrIn, v4),
                SocketAddr::V6(v6) => send_batch!(SockaddrIn6, v6),
            }
        }
        Ok(sent_packet)
    }

    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_lines: &mut [Line],
    ) -> io::Result<usize> {
        use nix::sys::socket::{MsgFlags, recvmmsg};

        use super::BATCH_SIZE;
        let mut msgs: Vec<_> = bufs
            .iter_mut()
            .map(|buf| [std::io::IoSliceMut::new(&mut buf[..])])
            .collect();

        let cmsg_buffer = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
        let mut data = nix::sys::socket::MultiHeaders::<SockaddrStorage>::preallocate(
            BATCH_SIZE,
            Some(cmsg_buffer),
        );

        let res = match recvmmsg(
            self.io.as_raw_fd(),
            &mut data,
            &mut msgs,
            MsgFlags::MSG_DONTWAIT,
            None,
        ) {
            Ok(results) => results.collect::<Vec<_>>(),
            Err(e) => {
                if matches!(e, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, e));
                }
                return Err(e.into());
            }
        };

        let local_port = self.local_addr()?.port();
        let mut count = 0;

        for recv_msg in res {
            let src_addr = recv_msg.address.unwrap().to_socketaddr();
            let link = qbase::net::route::Link::new(src_addr, recv_lines[count].dst);
            let mut recv_line = Line {
                link,
                ttl: 0,
                ecn: None,
                seg_size: recv_msg.bytes as u16,
            };
            for cmsg in recv_msg.cmsgs().unwrap() {
                parse_cmsg(cmsg, &mut recv_line);
            }
            recv_line.dst.set_port(local_port);
            recv_lines[count] = recv_line;
            count += 1;
        }

        Ok(count)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "tvos"
    ))]
    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_lines: &mut [Line],
    ) -> io::Result<usize> {
        use nix::sys::socket::{MsgFlags, recvmsg};
        let mut cmsg_space = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
        let result = recvmsg::<SockaddrStorage>(
            self.io.as_raw_fd(),
            bufs,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        );

        match result {
            Ok(recv_msg) => {
                if let Ok(cmsgs) = recv_msg.cmsgs() {
                    for cmsg in cmsgs {
                        parse_cmsg(cmsg, &mut recv_lines[0]);
                    }
                }
                recv_lines[0].dst.set_port(self.local_addr()?.port());
                recv_lines[0].src = recv_msg.address.unwrap().to_socketaddr();
                recv_lines[0].seg_size = recv_msg.bytes as u16;
                Ok(1)
            }
            Err(e) => {
                if matches!(e, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) {
                    // actually, it's not an error, just a signal to retry
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, e));
                }
                Err(e.into())
            }
        }
    }

    fn set_ttl(&self, ttl: i32) -> io::Result<()> {
        use std::sync::atomic::Ordering::{Acquire, SeqCst};

        if ttl == self.ttl.load(Acquire) {
            return Ok(());
        }
        let local = self.local_addr()?;
        let io = self.io.as_raw_fd();
        let ret = match local.ip() {
            IpAddr::V4(_) => unsafe {
                libc::setsockopt(
                    io,
                    libc::IPPROTO_IP,
                    libc::IP_TTL,
                    &ttl as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&ttl) as libc::socklen_t,
                )
            },
            IpAddr::V6(_) => unsafe {
                libc::setsockopt(
                    io,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_UNICAST_HOPS,
                    &ttl as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&ttl) as libc::socklen_t,
                )
            },
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        self.ttl.store(ttl, SeqCst);
        Ok(())
    }
}

fn parse_cmsg(cmsg: ControlMessageOwned, line: &mut Line) {
    match cmsg {
        ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
            let ip = IpAddr::V4(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()));
            line.link.dst.set_ip(ip);
        }
        ControlMessageOwned::Ipv6PacketInfo(pktinfo6) => {
            let ip = IpAddr::V6(Ipv6Addr::from(pktinfo6.ipi6_addr.s6_addr));
            line.link.dst.set_ip(ip);
            if let SocketAddr::V6(dst) = &mut line.link.dst
                && dst.ip().is_unicast_link_local()
            {
                dst.set_scope_id(pktinfo6.ipi6_ifindex);
            }
        }
        _ => {}
    }
}

trait ToSocketAddr {
    fn to_socketaddr(&self) -> SocketAddr;
}

impl ToSocketAddr for SockaddrStorage {
    fn to_socketaddr(&self) -> SocketAddr {
        match self.family() {
            Some(nix::sys::socket::AddressFamily::Inet) => {
                let sockaddr_in = self.as_sockaddr_in().unwrap();
                let v4_addr = SocketAddrV4::new(sockaddr_in.ip(), sockaddr_in.port());
                SocketAddr::V4(v4_addr)
            }
            Some(nix::sys::socket::AddressFamily::Inet6) => {
                let sockaddr_in6 = self.as_sockaddr_in6().unwrap();
                let v6_addr = SocketAddrV6::new(
                    sockaddr_in6.ip(),
                    sockaddr_in6.port(),
                    sockaddr_in6.flowinfo(),
                    sockaddr_in6.scope_id(),
                );
                SocketAddr::V6(v6_addr)
            }
            _ => panic!("Unsupported address family"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_link_local_packet_info_preserves_the_interface_scope() {
        let mut line = Line::default();
        let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let packet_info = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: address.octets(),
            },
            ipi6_ifindex: 7,
        };

        parse_cmsg(ControlMessageOwned::Ipv6PacketInfo(packet_info), &mut line);

        let SocketAddr::V6(destination) = line.link.dst else {
            panic!("IPv6 packet info must produce an IPv6 destination");
        };
        assert_eq!(*destination.ip(), address);
        assert_eq!(destination.scope_id(), 7);
    }
}
