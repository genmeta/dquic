use std::{
    fmt::Display,
    io,
    net::{Ipv6Addr, SocketAddr},
};

use dns_lookup::{AddrFamily, AddrInfoHints, SockType, getaddrinfo};
use futures::{FutureExt, StreamExt, future, stream};

use super::{EndpointAddr, Family, Resolve, ResolveFuture, Source};

/// Default resolver backed by the system `getaddrinfo` implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Display for SystemResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Source::System, f)
    }
}

impl Resolve for SystemResolver {
    fn lookup<'l>(&'l self, hostname: &'l str, servname: &'l str, family: Option<Family>) -> ResolveFuture<'l> {
        let host = hostname
            .rsplit_once(':')
            .filter(|(host, suffix)| !host.contains(':') && !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
            .map_or(hostname, |(host, _)| host)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host == "dhttp.net" || host.ends_with(".dhttp.net") {
            return future::ready(Err(io::Error::new(io::ErrorKind::NotFound, "DHTTP names require a DHTTP resolver"))).boxed();
        }
        let hostname = hostname.to_owned();
        let servname = servname.to_owned();
        async move {
            let addrs = tokio::task::spawn_blocking(move || lookup_socket_addrs(&hostname, &servname, family))
                .await
                .map_err(io::Error::other)??;
            let source = Source::System;
            Ok(stream::iter(addrs.into_iter().map(move |addr| {
                let ep = EndpointAddr::direct(addr);
                (source.clone(), ep)
            }))
            .boxed())
        }
        .boxed()
    }
}

fn lookup_socket_addrs(hostname: &str, servname: &str, family: Option<Family>) -> io::Result<Vec<SocketAddr>> {
    let (hostname, port) = split_name_port(hostname);
    let servname = port.unwrap_or(servname);
    let servname = if servname.is_empty() { "443" } else { servname };
    let hints = AddrInfoHints {
        address: match family {
            None => 0,
            Some(Family::V4) => AddrFamily::Inet.into(),
            Some(Family::V6) => AddrFamily::Inet6.into(),
        },
        socktype: SockType::Stream.into(),
        ..AddrInfoHints::default()
    };
    getaddrinfo(Some(hostname), Some(servname), Some(hints))?.map(|info| info.map(|info| info.sockaddr)).collect()
}

/// Split an optional numeric port from a hostname or bracketed IPv6 address.
/// Bare IPv6 addresses have no port; unrecognized suffixes remain part of the host.
pub fn split_name_port(hostname: &str) -> (&str, Option<&str>) {
    if let Some(bracketed) = hostname.strip_prefix('[')
        && let Some((host, suffix)) = bracketed.split_once(']')
    {
        if suffix.is_empty() {
            return (host, None);
        }
        if let Some(port) = suffix.strip_prefix(':')
            && port.parse::<u16>().is_ok()
        {
            return (host, Some(port));
        }
    }

    if hostname.parse::<Ipv6Addr>().is_ok() {
        return (hostname, None);
    }

    if let Some((host, port)) = hostname.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
        && port.parse::<u16>().is_ok()
    {
        return (host, Some(port));
    }

    (hostname, None)
}
