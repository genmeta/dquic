use std::{net::IpAddr, num::NonZeroU32, sync::OnceLock};

pub fn loopback_ifindex() -> NonZeroU32 {
    static INDEX: OnceLock<NonZeroU32> = OnceLock::new();
    *INDEX.get_or_init(|| interface_index(std::net::Ipv4Addr::LOCALHOST.into()))
}

pub fn interface_index(ip: IpAddr) -> NonZeroU32 {
    netdev::get_interfaces()
        .into_iter()
        .find(|interface| {
            interface.ipv4.iter().any(|addr| IpAddr::V4(addr.addr()) == ip)
                || interface.ipv6.iter().any(|addr| IpAddr::V6(addr.addr()) == ip)
        })
        .and_then(|interface| NonZeroU32::new(interface.index))
        .expect("local interface with a non-zero index")
}
