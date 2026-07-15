use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use qbase::net::Family;
use thiserror::Error;

use super::Way;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSide {
    Local,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidWay {
    #[error("local and remote addresses use different IP families")]
    AddressFamilyMismatch,
    #[error("bind URI family does not match the concrete local address")]
    BindFamilyMismatch,
    #[error("loopback and non-loopback addresses cannot form one path")]
    LoopbackScopeMismatch,
    #[error("{side:?} concrete address is unspecified")]
    Unspecified { side: EndpointSide },
    #[error("{side:?} concrete endpoint uses port zero")]
    ZeroPort { side: EndpointSide },
    #[error("{side:?} concrete address is multicast")]
    Multicast { side: EndpointSide },
    #[error("{side:?} concrete address is broadcast")]
    Broadcast { side: EndpointSide },
    #[error("local and remote concrete endpoints are identical")]
    IdenticalEndpoints,
    #[error("link-local peer is missing a compatible interface scope")]
    LinkLocalScopeMismatch,
    #[error("bind URI cannot currently resolve to an interface")]
    BindUnavailable,
    #[error("concrete local address {local} does not match bind address {bound}")]
    BindAddressMismatch {
        bound: SocketAddr,
        local: SocketAddr,
    },
}

fn validate_endpoint(side: EndpointSide, addr: SocketAddr) -> Result<(), InvalidWay> {
    if addr.ip().is_unspecified() {
        return Err(InvalidWay::Unspecified { side });
    }
    if addr.port() == 0 {
        return Err(InvalidWay::ZeroPort { side });
    }
    if addr.ip().is_multicast() {
        return Err(InvalidWay::Multicast { side });
    }
    if matches!(addr.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::BROADCAST) {
        return Err(InvalidWay::Broadcast { side });
    }
    Ok(())
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    }
}

pub fn validate_way((bind, _pathway, link): &Way) -> Result<(), InvalidWay> {
    let local = link.src;
    let remote = link.dst;

    if local.is_ipv4() != remote.is_ipv4() {
        return Err(InvalidWay::AddressFamilyMismatch);
    }
    let link_family = if local.is_ipv4() {
        Family::V4
    } else {
        Family::V6
    };
    if bind.family() != link_family {
        return Err(InvalidWay::BindFamilyMismatch);
    }
    validate_endpoint(EndpointSide::Local, local)?;
    validate_endpoint(EndpointSide::Remote, remote)?;
    if local == remote {
        return Err(InvalidWay::IdenticalEndpoints);
    }
    if local.ip().is_loopback() != remote.ip().is_loopback() {
        return Err(InvalidWay::LoopbackScopeMismatch);
    }

    let binding = bind
        .resolve_binding()
        .map_err(|_| InvalidWay::BindUnavailable)?;
    let bound = binding.addr;
    if !bound.ip().is_unspecified() && bound.ip() != local.ip() {
        return Err(InvalidWay::BindAddressMismatch { bound, local });
    }

    if is_link_local(remote.ip()) {
        match binding.device {
            Some(device) => {
                if let SocketAddr::V6(remote) = remote
                    && remote.scope_id() != 0
                    && remote.scope_id() != device.index
                {
                    return Err(InvalidWay::LinkLocalScopeMismatch);
                }
            }
            None => {
                if !is_link_local(local.ip()) {
                    return Err(InvalidWay::LinkLocalScopeMismatch);
                }
                if let (SocketAddr::V6(local), SocketAddr::V6(remote)) = (local, remote) {
                    let local_scope = local.scope_id();
                    let remote_scope = remote.scope_id();
                    if (local_scope == 0 && remote_scope == 0)
                        || (local_scope != 0 && remote_scope != 0 && local_scope != remote_scope)
                    {
                        return Err(InvalidWay::LinkLocalScopeMismatch);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use qbase::net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
    };

    use super::*;
    use crate::component::route::Way;

    fn way(bind: &str, local: &str, remote: &str) -> Way {
        let local: SocketAddr = local.parse().unwrap();
        let remote: SocketAddr = remote.parse().unwrap();
        (
            bind.parse().unwrap(),
            Pathway::new(EndpointAddr::direct(local), EndpointAddr::direct(remote)),
            Link::new(local, remote),
        )
    }

    #[test]
    fn accepts_safe_unicast_combinations() {
        for candidate in [
            way(
                "inet://127.0.0.1:50000",
                "127.0.0.1:50000",
                "127.0.0.1:4433",
            ),
            way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "203.0.113.10:4433",
            ),
            way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "192.168.1.10:4433",
            ),
            way(
                "inet://[2001:db8::1]:50000",
                "[2001:db8::1]:50000",
                "[2001:db8::2]:4433",
            ),
        ] {
            assert_eq!(validate_way(&candidate), Ok(()), "{candidate:?}");
        }
    }

    #[test]
    fn rejects_loopback_scope_mismatch_in_both_directions() {
        for candidate in [
            way(
                "inet://127.0.0.1:50000",
                "127.0.0.1:50000",
                "203.0.113.10:4433",
            ),
            way(
                "inet://203.0.113.10:50000",
                "203.0.113.10:50000",
                "127.0.0.1:4433",
            ),
        ] {
            assert_eq!(
                validate_way(&candidate),
                Err(InvalidWay::LoopbackScopeMismatch)
            );
        }
    }

    #[test]
    fn rejects_non_path_endpoints() {
        assert!(matches!(
            validate_way(&way(
                "inet://0.0.0.0:50000",
                "0.0.0.0:50000",
                "203.0.113.10:4433"
            )),
            Err(InvalidWay::Unspecified {
                side: EndpointSide::Local
            })
        ));
        assert!(matches!(
            validate_way(&way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "224.0.0.1:4433"
            )),
            Err(InvalidWay::Multicast {
                side: EndpointSide::Remote
            })
        ));
        assert!(matches!(
            validate_way(&way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "255.255.255.255:4433"
            )),
            Err(InvalidWay::Broadcast {
                side: EndpointSide::Remote
            })
        ));
        assert!(matches!(
            validate_way(&way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "203.0.113.10:0"
            )),
            Err(InvalidWay::ZeroPort {
                side: EndpointSide::Remote
            })
        ));
    }

    #[test]
    fn rejects_family_identity_bind_and_link_local_scope_mismatches() {
        assert_eq!(
            validate_way(&way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "[2001:db8::2]:4433"
            )),
            Err(InvalidWay::AddressFamilyMismatch)
        );
        assert_eq!(
            validate_way(&way(
                "inet://192.168.1.10:4433",
                "192.168.1.10:4433",
                "192.168.1.10:4433"
            )),
            Err(InvalidWay::IdenticalEndpoints)
        );
        assert!(matches!(
            validate_way(&way(
                "inet://192.168.1.11:50000",
                "192.168.1.10:50000",
                "203.0.113.10:4433"
            )),
            Err(InvalidWay::BindAddressMismatch { .. })
        ));
        assert_eq!(
            validate_way(&way(
                "inet://[2001:db8::1]:50000",
                "[2001:db8::1]:50000",
                "[fe80::2]:4433"
            )),
            Err(InvalidWay::LinkLocalScopeMismatch)
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn iface_bind_rejects_an_address_not_owned_by_that_device() {
        let candidate = way(
            "iface://v4.lo:50000",
            "203.0.113.10:50000",
            "198.51.100.10:4433",
        );
        assert!(matches!(
            validate_way(&candidate),
            Err(InvalidWay::BindAddressMismatch { .. })
        ));
    }
}
