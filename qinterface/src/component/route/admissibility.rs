use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use qbase::net::{Family, addr::EndpointAddr};
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
    #[error("{side:?} direct endpoint does not match the concrete path address")]
    DirectEndpointMismatch { side: EndpointSide },
    #[error("link-local peer is missing a compatible interface scope")]
    LinkLocalScopeMismatch,
    #[error("concrete local address {local} does not match bind address {bound}")]
    BindAddressMismatch {
        bound: SocketAddr,
        local: SocketAddr,
    },
}

fn is_unspecified(ip: IpAddr) -> bool {
    ip.is_unspecified()
        || matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some_and(|ip| ip.is_unspecified()))
}

fn validate_endpoint(side: EndpointSide, addr: SocketAddr) -> Result<(), InvalidWay> {
    let mapped_ipv4 = match addr.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped(),
        IpAddr::V4(..) => None,
    };
    if is_unspecified(addr.ip()) {
        return Err(InvalidWay::Unspecified { side });
    }
    if addr.port() == 0 {
        return Err(InvalidWay::ZeroPort { side });
    }
    if addr.ip().is_multicast() || mapped_ipv4.is_some_and(|ip| ip.is_multicast()) {
        return Err(InvalidWay::Multicast { side });
    }
    if matches!(addr.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::BROADCAST)
        || mapped_ipv4 == Some(Ipv4Addr::BROADCAST)
    {
        return Err(InvalidWay::Broadcast { side });
    }
    Ok(())
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_link_local())
        }
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

#[derive(Clone, Copy)]
enum Evidence {
    OutboundCandidate,
    Received,
}

pub fn validate_outbound_candidate(way: &Way) -> Result<(), InvalidWay> {
    validate(way, Evidence::OutboundCandidate)
}

pub fn validate_received_way(way: &Way) -> Result<(), InvalidWay> {
    validate(way, Evidence::Received)
}

fn validate((bind, pathway, link): &Way, evidence: Evidence) -> Result<(), InvalidWay> {
    let local = link.src;
    let remote = link.dst;
    let local_is_unspecified = is_unspecified(local.ip());

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

    validate_endpoint(EndpointSide::Remote, remote)?;
    if !matches!(evidence, Evidence::OutboundCandidate) || !local_is_unspecified {
        validate_endpoint(EndpointSide::Local, local)?;
    } else if local.port() == 0 {
        return Err(InvalidWay::ZeroPort {
            side: EndpointSide::Local,
        });
    }

    if let Some(bound) = bind.as_inet_bind_uri()
        && !bound.ip().is_unspecified()
        && !local_is_unspecified
        && (bound.ip() != local.ip() || (bound.port() != 0 && bound.port() != local.port()))
    {
        return Err(InvalidWay::BindAddressMismatch { bound, local });
    }

    if matches!(pathway.local(), EndpointAddr::Direct { addr } if !local_is_unspecified && addr != local)
    {
        return Err(InvalidWay::DirectEndpointMismatch {
            side: EndpointSide::Local,
        });
    }
    if matches!(pathway.remote(), EndpointAddr::Direct { addr } if addr != remote) {
        return Err(InvalidWay::DirectEndpointMismatch {
            side: EndpointSide::Remote,
        });
    }

    if !local_is_unspecified {
        if local == remote {
            return Err(InvalidWay::IdenticalEndpoints);
        }
        if is_loopback(local.ip()) != is_loopback(remote.ip()) {
            return Err(InvalidWay::LoopbackScopeMismatch);
        }
    }

    if let (EndpointAddr::Direct { addr: local }, EndpointAddr::Direct { addr: remote }) =
        (pathway.local(), pathway.remote())
    {
        let local_is_unspecified = is_unspecified(local.ip());
        if local.is_ipv4() != remote.is_ipv4() {
            return Err(InvalidWay::AddressFamilyMismatch);
        }
        validate_endpoint(EndpointSide::Remote, remote)?;
        if !local_is_unspecified {
            validate_endpoint(EndpointSide::Local, local)?;
            if local == remote {
                return Err(InvalidWay::IdenticalEndpoints);
            }
            if is_loopback(local.ip()) != is_loopback(remote.ip()) {
                return Err(InvalidWay::LoopbackScopeMismatch);
            }
        }
    }

    if is_link_local(remote.ip()) {
        if !local_is_unspecified && !is_link_local(local.ip()) {
            return Err(InvalidWay::LinkLocalScopeMismatch);
        }
        if let SocketAddr::V6(remote) = remote {
            if remote.scope_id() == 0 {
                return Err(InvalidWay::LinkLocalScopeMismatch);
            }
            if let SocketAddr::V6(local) = local
                && !local_is_unspecified
                && (local.scope_id() == 0 || local.scope_id() != remote.scope_id())
            {
                return Err(InvalidWay::LinkLocalScopeMismatch);
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
            assert_eq!(
                validate_outbound_candidate(&candidate),
                Ok(()),
                "{candidate:?}"
            );
            assert_eq!(validate_received_way(&candidate), Ok(()), "{candidate:?}");
        }
    }

    #[test]
    fn outbound_wildcard_local_is_preserved() {
        let candidate = way("inet://0.0.0.0:50000", "0.0.0.0:50000", "203.0.113.10:4433");

        assert_eq!(validate_outbound_candidate(&candidate), Ok(()));
        assert_eq!(candidate.2.src, "0.0.0.0:50000".parse().unwrap());
    }

    #[test]
    fn received_wildcard_local_is_rejected() {
        let received = way("inet://0.0.0.0:50000", "0.0.0.0:50000", "203.0.113.10:4433");

        assert_eq!(
            validate_received_way(&received),
            Err(InvalidWay::Unspecified {
                side: EndpointSide::Local,
            })
        );
    }

    #[test]
    fn outbound_wildcard_link_accepts_concrete_direct_intent() {
        let mut candidate = way("inet://0.0.0.0:50000", "0.0.0.0:50000", "203.0.113.10:4433");
        candidate.1 = Pathway::new(
            EndpointAddr::direct("192.0.2.10:50000".parse().unwrap()),
            candidate.1.remote(),
        );

        assert_eq!(validate_outbound_candidate(&candidate), Ok(()));
        assert_eq!(
            validate_received_way(&candidate),
            Err(InvalidWay::Unspecified {
                side: EndpointSide::Local,
            })
        );
    }

    #[test]
    fn neither_context_accepts_a_wildcard_remote() {
        let candidate = way("inet://0.0.0.0:50000", "0.0.0.0:50000", "0.0.0.0:4433");

        for result in [
            validate_outbound_candidate(&candidate),
            validate_received_way(&candidate),
        ] {
            assert_eq!(
                result,
                Err(InvalidWay::Unspecified {
                    side: EndpointSide::Remote,
                })
            );
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
            way(
                "inet://[::ffff:127.0.0.1]:50000",
                "[::ffff:127.0.0.1]:50000",
                "[::ffff:203.0.113.10]:4433",
            ),
        ] {
            for result in [
                validate_outbound_candidate(&candidate),
                validate_received_way(&candidate),
            ] {
                assert_eq!(result, Err(InvalidWay::LoopbackScopeMismatch));
            }
        }
    }

    #[test]
    fn rejects_non_path_endpoints() {
        assert!(matches!(
            validate_received_way(&way(
                "inet://0.0.0.0:50000",
                "0.0.0.0:50000",
                "203.0.113.10:4433"
            )),
            Err(InvalidWay::Unspecified {
                side: EndpointSide::Local
            })
        ));
        assert!(matches!(
            validate_received_way(&way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "224.0.0.1:4433"
            )),
            Err(InvalidWay::Multicast {
                side: EndpointSide::Remote
            })
        ));
        assert!(matches!(
            validate_received_way(&way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "255.255.255.255:4433"
            )),
            Err(InvalidWay::Broadcast {
                side: EndpointSide::Remote
            })
        ));
        assert!(matches!(
            validate_received_way(&way(
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
            validate_received_way(&way(
                "inet://192.168.1.10:50000",
                "192.168.1.10:50000",
                "[2001:db8::2]:4433"
            )),
            Err(InvalidWay::AddressFamilyMismatch)
        );
        assert_eq!(
            validate_received_way(&way(
                "inet://192.168.1.10:4433",
                "192.168.1.10:4433",
                "192.168.1.10:4433"
            )),
            Err(InvalidWay::IdenticalEndpoints)
        );
        assert!(matches!(
            validate_received_way(&way(
                "inet://192.168.1.11:50000",
                "192.168.1.10:50000",
                "203.0.113.10:4433"
            )),
            Err(InvalidWay::BindAddressMismatch { .. })
        ));
        assert_eq!(
            validate_received_way(&way(
                "inet://[2001:db8::1]:50000",
                "[2001:db8::1]:50000",
                "[fe80::2]:4433"
            )),
            Err(InvalidWay::LinkLocalScopeMismatch)
        );
        assert_eq!(
            validate_received_way(&way(
                "inet://[::]:50000",
                "[fe80::1%3]:50000",
                "[fe80::2]:4433"
            )),
            Err(InvalidWay::LinkLocalScopeMismatch)
        );
    }

    #[test]
    fn rejects_direct_endpoint_and_link_mismatches() {
        let mut candidate = way(
            "inet://127.0.0.1:50000",
            "127.0.0.1:50000",
            "127.0.0.1:4433",
        );
        candidate.1 = Pathway::new(
            EndpointAddr::direct("127.0.0.1:50001".parse().unwrap()),
            candidate.1.remote(),
        );
        for result in [
            validate_outbound_candidate(&candidate),
            validate_received_way(&candidate),
        ] {
            assert_eq!(
                result,
                Err(InvalidWay::DirectEndpointMismatch {
                    side: EndpointSide::Local
                })
            );
        }
    }

    #[test]
    fn iface_bind_validation_does_not_resolve_the_device() {
        let candidate = way(
            "iface://v4.nonexistent:50000",
            "203.0.113.10:50000",
            "198.51.100.10:4433",
        );

        assert_eq!(validate_outbound_candidate(&candidate), Ok(()));
        assert_eq!(validate_received_way(&candidate), Ok(()));
    }

    #[test]
    fn outbound_direct_intent_must_match_the_physical_family() {
        let mut candidate = way("inet://0.0.0.0:50000", "0.0.0.0:50000", "203.0.113.10:4433");
        candidate.1 = Pathway::new(
            EndpointAddr::direct("[2001:db8::1]:50000".parse().unwrap()),
            candidate.1.remote(),
        );

        assert_eq!(
            validate_outbound_candidate(&candidate),
            Err(InvalidWay::AddressFamilyMismatch)
        );
    }

    #[test]
    fn concrete_inet_bind_port_must_match_the_link() {
        let candidate = way(
            "inet://192.0.2.10:50001",
            "192.0.2.10:50000",
            "203.0.113.10:4433",
        );

        for result in [
            validate_outbound_candidate(&candidate),
            validate_received_way(&candidate),
        ] {
            assert!(matches!(
                result,
                Err(InvalidWay::BindAddressMismatch { .. })
            ));
        }
    }

    #[test]
    fn received_ipv6_link_local_scopes_must_both_be_concrete() {
        let candidate = way("inet://[::]:50000", "[fe80::1]:50000", "[fe80::2%3]:4433");

        assert_eq!(
            validate_received_way(&candidate),
            Err(InvalidWay::LinkLocalScopeMismatch)
        );
    }
}
