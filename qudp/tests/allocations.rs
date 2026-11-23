#![cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]

mod common;

#[cfg(all(feature = "udp_offload_opt", any(target_os = "linux", target_os = "android")))]
#[path = "support/offload.rs"]
mod offload;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::IoSliceMut;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::{self, IoSlice},
    time::Duration,
};

use qbase::net::route::{Line, Link};
use qudp::{Io, UdpSocket};

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn record_allocation() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value + 1));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[tokio::test(flavor = "current_thread")]
async fn sending_packet_info_batches_does_not_allocate() -> io::Result<()> {
    for ifindex in [0, common::loopback_ifindex()] {
        for (bind, peer_bind) in
            [("127.0.0.1:0", "127.0.0.1:0"), ("[::1]:0", "[::1]:0"), ("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")]
        {
            let socket = UdpSocket::bind(bind.parse().unwrap(), ifindex)?;
            let peer = std::net::UdpSocket::bind(peer_bind)?;
            peer.set_read_timeout(Some(Duration::from_secs(1)))?;
            let line = Line::new(Link::new(socket.local_addr()?, peer.local_addr()?), 64, None, 4);
            let buffers = [IoSlice::new(b"live"); 8];
            for width in [1, 8] {
                ALLOCATIONS.set(Some(0));
                let sent = socket.sendmsg(&buffers[..width], &line);
                let allocations = ALLOCATIONS.take().unwrap();
                assert_eq!(sent?, width);
                assert_eq!(allocations, 0, "bind={bind}, ifindex={ifindex}, width={width}");
                for _ in 0..width {
                    let mut bytes = [0; 16];
                    let (len, source) = peer.recv_from(&mut bytes)?;
                    assert_eq!(&bytes[..len], b"live");
                    assert_eq!(source.ip(), peer.local_addr()?.ip());
                    assert_eq!(source.port(), socket.local_addr()?.port());
                }
            }
        }
    }
    Ok(())
}

#[cfg(all(feature = "udp_offload_opt", any(target_os = "linux", target_os = "android")))]
#[tokio::test(flavor = "current_thread")]
async fn gso_batches_split_payloads_without_allocating() -> io::Result<()> {
    for ifindex in [0, common::loopback_ifindex()] {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let socket = UdpSocket::bind(bind.parse().unwrap(), ifindex)?;
            let peer = std::net::UdpSocket::bind(bind)?;
            peer.set_read_timeout(Some(Duration::from_secs(1)))?;
            let line = Line::new(Link::new(socket.local_addr()?, peer.local_addr()?), 64, None, 5);
            let buffers = [IoSlice::new(b"firstother"), IoSlice::new(b"thirdfinal")];

            ALLOCATIONS.set(Some(0));
            let sent = socket.sendmsg(&buffers, &line);
            let allocations = ALLOCATIONS.take().unwrap();
            assert_eq!(sent?, 2);
            assert_eq!(allocations, 0);
            for expected in [b"first", b"other", b"third", b"final"] {
                let mut bytes = [0; 16];
                let (len, source) = peer.recv_from(&mut bytes)?;
                assert_eq!(&bytes[..len], expected);
                assert_eq!(source, socket.local_addr()?);
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn receiving_packet_info_batches_does_not_allocate() -> io::Result<()> {
    for ifindex in [0, common::loopback_ifindex()] {
        for (bind, peer_bind) in
            [("127.0.0.1:0", "127.0.0.1:0"), ("[::1]:0", "[::1]:0"), ("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")]
        {
            let socket = UdpSocket::bind(bind.parse().unwrap(), ifindex)?;
            let peers = [std::net::UdpSocket::bind(peer_bind)?, std::net::UdpSocket::bind(peer_bind)?];
            let destination = std::net::SocketAddr::new(peers[0].local_addr()?.ip(), socket.local_addr()?.port());
            let mut packets = [[0; 16]; 8];
            let mut buffers = packets.each_mut().map(|packet| IoSliceMut::new(packet));
            let mut lines = [Line::default(); 8];
            for width in [1, 8] {
                for index in 0..width {
                    peers[index % 2].send_to(&[index as u8], destination)?;
                }
                ALLOCATIONS.set(Some(0));
                let received = socket.recvmsg(&mut buffers[..width], &mut lines[..width]);
                let allocations = ALLOCATIONS.take().unwrap();
                assert_eq!(received?, width);
                assert_eq!(allocations, 0, "bind={bind}, ifindex={ifindex}, width={width}");
                for index in 0..width {
                    assert_eq!(&buffers[index][..lines[index].seg_size as usize], &[index as u8]);
                    assert_eq!(lines[index].src, peers[index % 2].local_addr()?);
                    assert_eq!(lines[index].dst, destination);
                }

                ALLOCATIONS.set(Some(0));
                let empty = socket.recvmsg(&mut buffers, &mut lines);
                let allocations = ALLOCATIONS.take().unwrap();
                assert_eq!(empty.unwrap_err().kind(), io::ErrorKind::WouldBlock);
                assert_eq!(allocations, 0);
            }
        }
    }
    Ok(())
}

#[cfg(all(feature = "udp_offload_opt", any(target_os = "linux", target_os = "android")))]
#[tokio::test(flavor = "current_thread")]
async fn receiving_gro_batches_does_not_allocate() -> io::Result<()> {
    for ifindex in [0, common::loopback_ifindex()] {
        for (bind, peer_bind) in
            [("127.0.0.1:0", "127.0.0.1:0"), ("[::1]:0", "[::1]:0"), ("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")]
        {
            let socket = UdpSocket::bind(bind.parse().unwrap(), ifindex)?;
            let peers = [std::net::UdpSocket::bind(peer_bind)?, std::net::UdpSocket::bind(peer_bind)?];
            let destination = std::net::SocketAddr::new(peers[0].local_addr()?.ip(), socket.local_addr()?.port());
            for width in [1, 8] {
                for index in 0..width {
                    offload::send_segmented(&peers[index % 2], destination, &[index as u8; 13], 5)?;
                }
                let mut packets = [[0; 64]; 8];
                let mut buffers = packets.each_mut().map(|packet| IoSliceMut::new(packet));
                let mut lines = [Line::default(); 8];
                ALLOCATIONS.set(Some(0));
                let received = socket.recvmsg(&mut buffers[..width], &mut lines[..width]);
                let allocations = ALLOCATIONS.take().unwrap();
                assert_eq!(received?, width);
                assert_eq!(allocations, 0, "bind={bind}, ifindex={ifindex}, width={width}");
                for index in 0..width {
                    assert_eq!(&buffers[index][..], &[index as u8; 13]);
                    assert_eq!(lines[index].seg_size, 5);
                    assert_eq!(lines[index].src, peers[index % 2].local_addr()?);
                    assert_eq!(lines[index].dst, destination);
                }
                ALLOCATIONS.set(Some(0));
                let empty = socket.recvmsg(&mut buffers, &mut lines);
                let allocations = ALLOCATIONS.take().unwrap();
                assert_eq!(empty.unwrap_err().kind(), io::ErrorKind::WouldBlock);
                assert_eq!(allocations, 0);
            }
        }
    }
    Ok(())
}
