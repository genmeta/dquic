#[cfg(any(target_os = "macos", target_os = "ios", target_os = "watchos", target_os = "tvos"))]
#[path = "nix/darwin.rs"]
mod darwin;

#[cfg(any(target_os = "android", target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
#[path = "nix/unix.rs"]
mod unix;

use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd},
};

use ::nix::sys::socket::{AddressFamily, ControlMessageOwned, SockaddrLike, SockaddrStorage, sockopt};
use qbase::net::route::Line;
use socket2::Socket;

use crate::{Io, UdpSocket};

const OPTION_ON: bool = true;

#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
enum PacketInfo {
    V4(libc::in_pktinfo),
    V6(libc::in6_pktinfo),
}

#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
impl PacketInfo {
    fn new(src: IpAddr, ifindex: u32) -> Option<Self> {
        if src.is_unspecified() && ifindex == 0 {
            return None;
        }
        Some(match src {
            IpAddr::V4(src) => Self::V4(libc::in_pktinfo {
                ipi_ifindex: ifindex as _,
                ipi_spec_dst: libc::in_addr { s_addr: u32::from_ne_bytes(src.octets()) },
                ipi_addr: libc::in_addr { s_addr: 0 },
            }),
            IpAddr::V6(src) => {
                Self::V6(libc::in6_pktinfo { ipi6_addr: libc::in6_addr { s6_addr: src.octets() }, ipi6_ifindex: ifindex as _ })
            }
        })
    }
}

impl Io for UdpSocket {
    fn setsockopt(socket: &Socket, addr: SocketAddr) -> io::Result<()> {
        let io = socket.as_fd();
        ::nix::sys::socket::setsockopt(&io, sockopt::RcvBuf, &(2 * 1024 * 1024))?;
        #[cfg(all(feature = "udp_offload_opt", any(target_os = "android", target_os = "linux")))]
        ::nix::sys::socket::setsockopt(&io, sockopt::UdpGroSegment, &OPTION_ON)?;
        match addr {
            SocketAddr::V4(_) => {
                #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
                {
                    ::nix::sys::socket::setsockopt(&io, sockopt::IpDontFrag, &OPTION_ON)?;
                    ::nix::sys::socket::setsockopt(&io, sockopt::Ipv4RecvDstAddr, &OPTION_ON)?;
                }
                #[cfg(any(target_os = "android", target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
                ::nix::sys::socket::setsockopt(&io, sockopt::Ipv4Ttl, &(Line::DEFAULT_TTL as i32))?;
                ::nix::sys::socket::setsockopt(&io, sockopt::Ipv4PacketInfo, &OPTION_ON)?;
            }
            SocketAddr::V6(_) => {
                ::nix::sys::socket::setsockopt(&io, sockopt::Ipv6V6Only, &OPTION_ON)?;
                ::nix::sys::socket::setsockopt(&io, sockopt::Ipv6RecvPacketInfo, &OPTION_ON)?;
                ::nix::sys::socket::setsockopt(&io, sockopt::Ipv6DontFrag, &OPTION_ON)?;
                ::nix::sys::socket::setsockopt(&io, sockopt::Ipv6Ttl, &(Line::DEFAULT_TTL as i32))?;
            }
        }

        Ok(())
    }

    fn sendmsg(&self, bufs: &[IoSlice<'_>], line: &Line) -> io::Result<usize> {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "watchos", target_os = "tvos"))]
        {
            darwin::sendmsg(self, bufs, line)
        }
        #[cfg(any(target_os = "android", target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
        {
            unix::sendmsg(self, bufs, line)
        }
    }

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], lines: &mut [Line]) -> io::Result<usize> {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "watchos", target_os = "tvos"))]
        {
            darwin::recvmsg(self, bufs, lines)
        }
        #[cfg(any(target_os = "android", target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
        {
            unix::recvmsg(self, bufs, lines)
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

pub(crate) fn parse_cmsg(cmsg: ControlMessageOwned, line: &mut Line) {
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
                #[cfg(target_os = "android")]
                let scope_id = pktinfo6.ipi6_ifindex as u32;
                #[cfg(not(target_os = "android"))]
                let scope_id = pktinfo6.ipi6_ifindex;
                dst.set_scope_id(scope_id);
            }
        }
        _ => {}
    }
}

trait ExtractSocketAddr {
    fn inner(&self) -> SocketAddr;
}

impl ExtractSocketAddr for SockaddrStorage {
    fn inner(&self) -> SocketAddr {
        match self.family() {
            Some(AddressFamily::Inet) => SocketAddr::from(*self.as_sockaddr_in().unwrap()),
            Some(AddressFamily::Inet6) => SocketAddr::from(*self.as_sockaddr_in6().unwrap()),
            _ => panic!("Unsupported address family"),
        }
    }
}
