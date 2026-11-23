use std::{net::IpAddr, sync::OnceLock};

pub fn loopback_ifindex() -> u32 {
    static INDEX: OnceLock<u32> = OnceLock::new();
    *INDEX.get_or_init(|| interface_index(std::net::Ipv4Addr::LOCALHOST.into()))
}

pub fn interface_index(ip: IpAddr) -> u32 {
    netdev::get_interfaces()
        .into_iter()
        .find(|interface| {
            interface.ipv4.iter().any(|addr| IpAddr::V4(addr.addr()) == ip)
                || interface.ipv6.iter().any(|addr| IpAddr::V6(addr.addr()) == ip)
        })
        .map(|interface| interface.index)
        .filter(|index| *index != 0)
        .expect("local interface with a non-zero index")
}
