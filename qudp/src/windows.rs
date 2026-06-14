use std::{
    ffi::c_int,
    io, mem,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::windows::io::AsRawSocket,
    ptr,
};

use libc::c_uchar;
use qbase::net::route::{Line, Link};
use socket2::Socket;
use windows_sys::Win32::Networking::WinSock::{self, SOCKET};

use crate::{BoundDevice, Io, UdpSocket};

const CMSG_LEN: usize = 128;
#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<WinSock::CMSGHDR>
pub(crate) struct Aligned<T>(pub(crate) T);

impl Io for UdpSocket {
    fn config(socket: &Socket, addr: SocketAddr) -> std::io::Result<()> {
        const OPTION_ON: c_int = 1;
        let io = socket.as_raw_socket().try_into().unwrap();

        setsockopt(io, WinSock::SOL_SOCKET, WinSock::SO_RCVBUF, 2 * 1024 * 1024);
        match addr {
            SocketAddr::V4(_) => {
                setsockopt(io, WinSock::IPPROTO_IP, WinSock::IP_RECVTOS, OPTION_ON);
                setsockopt(io, WinSock::IPPROTO_IP, WinSock::IP_PKTINFO, OPTION_ON);
                setsockopt(io, WinSock::IPPROTO_IP, WinSock::IP_RECVTTL, OPTION_ON);
                setsockopt(io, WinSock::IPPROTO_IP, WinSock::IP_RECVDSTADDR, OPTION_ON);
                setsockopt(
                    io,
                    WinSock::IPPROTO_IP,
                    WinSock::IP_TTL,
                    Line::DEFAULT_TTL as c_int,
                );
            }
            SocketAddr::V6(_) => {
                setsockopt(io, WinSock::IPPROTO_IPV6, WinSock::IPV6_V6ONLY, OPTION_ON);
                setsockopt(io, WinSock::IPPROTO_IPV6, WinSock::IPV6_HOPLIMIT, OPTION_ON);
                setsockopt(
                    io,
                    WinSock::IPPROTO_IPV6,
                    WinSock::IPV6_RECVTCLASS,
                    OPTION_ON,
                );
                setsockopt(io, WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO, OPTION_ON);
            }
        }
        if let Err(e) = socket.bind(&addr.into()) {
            tracing::error!(target: "qudp", "Failed to bind socket: {}", e);
            return Err(io::Error::new(io::ErrorKind::AddrInUse, e));
        }
        Ok(())
    }

    fn bind_device_to_socket(
        _socket: &socket2::SockRef<'_>,
        _addr: SocketAddr,
        _device: &BoundDevice,
    ) -> io::Result<()> {
        Ok(())
    }

    fn sendmsg(&self, bufs: &[std::io::IoSlice<'_>], line: &Line) -> std::io::Result<usize> {
        let dst = socket2::SockAddr::from(line.dst);
        let mut count = 0;

        for buf in bufs {
            let mut ctrl_buf = Aligned([0; CMSG_LEN]);
            let mut data = WinSock::WSABUF {
                buf: buf.as_ptr() as *mut _,
                len: buf.len() as _,
            };

            let ctrl = WinSock::WSABUF {
                buf: ctrl_buf.0.as_mut_ptr(),
                len: ctrl_buf.0.len() as _,
            };

            let mut wsa_msg = WinSock::WSAMSG {
                name: dst.as_ptr() as *mut _,
                namelen: dst.len(),
                lpBuffers: &mut data,
                Control: ctrl,
                dwBufferCount: 1,
                dwFlags: 0,
            };

            let mut cmsg = unsafe { first_cmsg(&mut wsa_msg).as_mut() };
            let mut cmsg_len = 0;
            if !line.src.ip().is_unspecified() || self.bound_device.is_some() {
                let src = if line.src.ip().is_unspecified() {
                    self.io.local_addr()?
                } else {
                    line.src
                };
                let src = socket2::SockAddr::from(src);
                let ifindex = self
                    .bound_device
                    .as_ref()
                    .map_or(0, |device| device.index().get());
                match src.family() {
                    WinSock::AF_INET => {
                        let src_ip =
                            unsafe { ptr::read(src.as_ptr() as *const WinSock::SOCKADDR_IN) };
                        let pktinfo = WinSock::IN_PKTINFO {
                            ipi_addr: src_ip.sin_addr,
                            ipi_ifindex: ifindex,
                        };

                        cmsg = append_cmsg(
                            &wsa_msg,
                            cmsg,
                            WinSock::IPPROTO_IP,
                            WinSock::IP_PKTINFO,
                            pktinfo,
                            &mut cmsg_len,
                        );
                    }
                    WinSock::AF_INET6 => {
                        let src_ip =
                            unsafe { ptr::read(src.as_ptr() as *const WinSock::SOCKADDR_IN6) };
                        let scope_id = unsafe { src_ip.Anonymous.sin6_scope_id };
                        let pktinfo = WinSock::IN6_PKTINFO {
                            ipi6_addr: src_ip.sin6_addr,
                            ipi6_ifindex: if self.bound_device.is_some() {
                                ifindex
                            } else {
                                scope_id
                            },
                        };

                        cmsg = append_cmsg(
                            &wsa_msg,
                            cmsg,
                            WinSock::IPPROTO_IPV6,
                            WinSock::IPV6_PKTINFO,
                            pktinfo,
                            &mut cmsg_len,
                        );
                    }
                    _ => {
                        return Err(io::Error::from(io::ErrorKind::InvalidInput));
                    }
                }
            }

            if let Some(ecn) = line.ecn {
                let is_ipv4 = line.dst.is_ipv4()
                    || matches!(line.dst.ip(), IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some());
                if is_ipv4 {
                    _ = append_cmsg(
                        &wsa_msg,
                        cmsg,
                        WinSock::IPPROTO_IP,
                        WinSock::IP_ECN,
                        ecn,
                        &mut cmsg_len,
                    );
                } else {
                    _ = append_cmsg(
                        &wsa_msg,
                        cmsg,
                        WinSock::IPPROTO_IPV6,
                        WinSock::IPV6_TCLASS,
                        ecn,
                        &mut cmsg_len,
                    );
                }
            }

            wsa_msg.Control.len = cmsg_len as _;
            if cmsg_len == 0 {
                wsa_msg.Control = WinSock::WSABUF {
                    buf: ptr::null_mut(),
                    len: 0,
                };
            }

            let mut len = 0;
            let ret = unsafe {
                WinSock::WSASendMsg(
                    self.io.as_raw_socket() as usize,
                    &wsa_msg,
                    0,
                    &mut len,
                    ptr::null_mut(),
                    None,
                )
            };

            if ret != 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::WouldBlock {
                    return Err(e);
                }
            }
            count += 1;
        }
        Ok(count as usize)
    }

    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        lines: &mut [Line],
    ) -> std::io::Result<usize> {
        let wsa_recvmsg_ptr = wsarecvmsg_ptr().expect("valid function pointer for WSARecvMsg");

        let mut ctrl_buf = Aligned([0; CMSG_LEN]);
        let mut source: WinSock::SOCKADDR_INET = unsafe { mem::zeroed() };

        let ctrl = WinSock::WSABUF {
            buf: ctrl_buf.0.as_mut_ptr(),
            len: ctrl_buf.0.len() as _,
        };

        let mut wsa_msg = WinSock::WSAMSG {
            name: &mut source as *mut _ as *mut _,
            namelen: mem::size_of_val(&source) as _,
            lpBuffers: &mut WinSock::WSABUF {
                buf: bufs[0].as_mut_ptr(),
                len: bufs[0].len() as _,
            },
            Control: ctrl,
            dwBufferCount: 1,
            dwFlags: 0,
        };

        let mut len = 0;
        unsafe {
            let rc = (wsa_recvmsg_ptr)(
                self.io.as_raw_socket() as usize,
                &mut wsa_msg,
                &mut len,
                ptr::null_mut(),
                None,
            );
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        let addr = unsafe {
            let (_, addr) = socket2::SockAddr::try_init(|addr_storage, len| {
                *len = mem::size_of_val(&source) as _;
                ptr::copy_nonoverlapping(&source, addr_storage as _, 1);
                Ok(())
            })?;
            addr.as_socket()
        };

        let mut ecn_bits = 0;
        let mut dst_ip = None;
        let mut cmsg: Option<&mut WinSock::CMSGHDR> = unsafe { first_cmsg(&mut wsa_msg).as_mut() };
        while let Some(cur_cmsg) = cmsg {
            // [header (len)][data][padding(len + sizeof(data))] -> [header][data][padding]
            match (cur_cmsg.cmsg_level, cur_cmsg.cmsg_type) {
                (WinSock::IPPROTO_IP, WinSock::IP_PKTINFO) => {
                    let pktinfo = cmsg_decode::<WinSock::IN_PKTINFO>(cur_cmsg);
                    let ip4 = Ipv4Addr::from(u32::from_be(unsafe { pktinfo.ipi_addr.S_un.S_addr }));
                    dst_ip = Some(ip4.into());
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO) => {
                    let pktinfo = cmsg_decode::<WinSock::IN6_PKTINFO>(cur_cmsg);
                    // Addr is stored in big endian format
                    dst_ip = Some(IpAddr::from(unsafe { pktinfo.ipi6_addr.u.Byte }));
                }
                (WinSock::IPPROTO_IP, WinSock::IP_ECN) => {
                    ecn_bits = cmsg_decode::<c_int>(cur_cmsg);
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN) => {
                    ecn_bits = cmsg_decode::<c_int>(cur_cmsg);
                }
                _ => {}
            }
            cmsg = unsafe { next_cmsg(&wsa_msg, cur_cmsg).as_mut() };
        }
        let dst = if let Some(ip) = dst_ip {
            crate::SocketAddr::new(ip, self.local_addr()?.port())
        } else {
            self.local_addr()?
        };
        lines[0] = Line {
            link: Link::new(addr.unwrap(), dst),
            ttl: Line::DEFAULT_TTL,
            ecn: Some(ecn_bits as u8),
            seg_size: len as u16,
        };
        Ok(1)
    }

    fn set_ttl(&self, ttl: i32) -> io::Result<()> {
        use std::sync::atomic::Ordering::{Acquire, SeqCst};

        if ttl == self.ttl.load(Acquire) {
            return Ok(());
        }

        let local = self.local_addr()?;
        let socket = self.io.as_raw_socket() as usize;

        match local.ip() {
            IpAddr::V4(_) => setsockopt(socket, WinSock::IPPROTO_IP, WinSock::IP_TTL, ttl),
            IpAddr::V6(_) => setsockopt(
                socket,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_UNICAST_HOPS,
                ttl,
            ),
        };
        self.ttl.store(ttl, SeqCst);
        Ok(())
    }
}

fn append_cmsg<'a, V: Copy>(
    msg: &'a WinSock::WSAMSG,
    mut cmsg: Option<&'a mut WinSock::CMSGHDR>,
    level: libc::c_int,
    ty: libc::c_int,
    data: V,
    cmsg_len: &mut usize,
) -> Option<&'a mut WinSock::CMSGHDR> {
    let space = cmsg_space(mem::size_of_val(&data));
    let next = cmsg.take().expect("no available cmsghdr");
    next.cmsg_level = level as _;
    next.cmsg_type = ty as _;
    next.cmsg_len = cmsg_data_len(mem::size_of_val(&data)) as _;
    unsafe {
        ptr::write(cmsg_data(next) as *const V as *mut V, data);
    }
    *cmsg_len += space;
    unsafe { next_cmsg(msg, next).as_mut() }
}

fn cmsg_decode<T: Copy>(cmsg: &mut WinSock::CMSGHDR) -> T {
    unsafe { ptr::read(cmsg_data(cmsg) as *const T) }
}

const fn cmsghdr_align(length: usize) -> usize {
    (length + mem::align_of::<WinSock::CMSGHDR>() - 1) & !(mem::align_of::<WinSock::CMSGHDR>() - 1)
}

fn cmsgdata_align(length: usize) -> usize {
    (length + mem::align_of::<usize>() - 1) & !(mem::align_of::<usize>() - 1)
}

fn cmsg_data_len(len: usize) -> usize {
    mem::size_of::<WinSock::CMSGHDR>() + len
}

fn cmsg_space(len: usize) -> usize {
    let total = mem::size_of::<WinSock::CMSGHDR>() + len;
    let align = mem::align_of::<WinSock::CMSGHDR>();
    (total + align - 1) & !(align - 1)
}

unsafe fn first_cmsg(msg: &mut WinSock::WSAMSG) -> *mut WinSock::CMSGHDR {
    if msg.Control.len as usize >= mem::size_of::<WinSock::CMSGHDR>() {
        msg.Control.buf as *mut WinSock::CMSGHDR
    } else {
        ptr::null_mut::<WinSock::CMSGHDR>()
    }
}

fn next_cmsg(msg: &WinSock::WSAMSG, cmsg: &WinSock::CMSGHDR) -> *mut WinSock::CMSGHDR {
    let next = (cmsg as *const _ as usize + cmsghdr_align(cmsg.cmsg_len)) as *mut WinSock::CMSGHDR;
    let max = msg.Control.buf as usize + msg.Control.len as usize;
    if unsafe { next.offset(1) } as usize > max {
        ptr::null_mut()
    } else {
        next
    }
}

fn cmsg_data(cmsg: &mut WinSock::CMSGHDR) -> *mut libc::c_uchar {
    (cmsg as *const _ as usize + cmsgdata_align(mem::size_of::<WinSock::CMSGHDR>())) as *mut c_uchar
}

fn setsockopt(io: SOCKET, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
    unsafe {
        WinSock::setsockopt(
            io,
            level,
            name,
            &value as *const _ as _,
            mem::size_of_val(&value) as _,
        )
    };
}

fn wsarecvmsg_ptr() -> &'static WinSock::LPFN_WSARECVMSG {
    static WSARECVMSG_PTR: std::sync::OnceLock<WinSock::LPFN_WSARECVMSG> =
        std::sync::OnceLock::new();
    WSARECVMSG_PTR.get_or_init(|| {
        let s = unsafe { WinSock::socket(WinSock::AF_INET as _, WinSock::SOCK_DGRAM as _, 0) };
        if s == WinSock::INVALID_SOCKET {
            tracing::warn!(
                target: "qudp",
                "Failed to create socket for WSARecvMsg function pointer: {}",
                io::Error::last_os_error()
            );
            return None;
        }
        // Detect if OS expose WSARecvMsg API based on
        // https://github.com/Azure/mio-uds-windows/blob/a3c97df82018086add96d8821edb4aa85ec1b42b/src/stdnet/ext.rs#L601
        let guid = WinSock::WSAID_WSARECVMSG;
        let mut wsa_recvmsg_ptr = None;
        let mut len = 0;

        // Safety: Option handles the NULL pointer with a None value
        let ret = unsafe {
            WinSock::WSAIoctl(
                s as _,
                WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
                &guid as *const _ as *const _,
                mem::size_of_val(&guid) as u32,
                &mut wsa_recvmsg_ptr as *mut _ as *mut _,
                mem::size_of_val(&wsa_recvmsg_ptr) as u32,
                &mut len,
                ptr::null_mut(),
                None,
            )
        };

        if ret == -1 {
            tracing::warn!(
                target: "qudp",
                "Failed to get WSARecvMsg function pointer: {}",
                io::Error::last_os_error()
            );
        } else if len as usize != mem::size_of::<WinSock::LPFN_WSARECVMSG>() {
            tracing::warn!(
                target: "qudp",
                "WSARecvMsg function pointer size mismatch: expected {}, got {}",
                mem::size_of::<WinSock::LPFN_WSARECVMSG>(),
                len
            );
            wsa_recvmsg_ptr = None;
        }

        unsafe {
            WinSock::closesocket(s);
        }

        wsa_recvmsg_ptr
    })
}
