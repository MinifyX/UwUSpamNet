//! Values as they are stored and listed: IPs, networks, domains.

use std::net::{IpAddr, Ipv6Addr};

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn mask6(ip: Ipv6Addr, prefix: u32) -> Ipv6Addr {
    let bits = u128::from(ip);
    Ipv6Addr::from(bits & (u128::MAX << (128 - prefix)))
}

/// The registration network of a client address: IPv4 /24, IPv6 /48.
pub fn registration_network(ip: IpAddr) -> String {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => format!("{}/48", mask6(v6, 48)),
    }
}

/// A reported sending IP as it is stored: IPv4 as the address, IPv6 as its /64 network
/// (`2001:db8:1:2::/64`). Non-public addresses (loopback, private, link-local, multicast,
/// unspecified) give `None` and are dropped. A trailing `/64` on IPv6 input is accepted.
pub fn reported_ip(text: &str) -> Option<String> {
    let text = text.trim();
    let text = text.strip_suffix("/64").unwrap_or(text);
    let ip = canonical(text.parse::<IpAddr>().ok()?);
    match ip {
        IpAddr::V4(v4) => {
            let bad = v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.octets()[0] == 0;
            (!bad).then(|| v4.to_string())
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            let bad = v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80;
            (!bad).then(|| format!("{}/64", mask6(v6, 64)))
        }
    }
}

/// An IPv4 or IPv6 network in CIDR notation, for allowlist entries.
pub fn parse_cidr(text: &str) -> Option<(IpAddr, u32)> {
    let (addr, prefix) = text.split_once('/')?;
    let ip = canonical(addr.parse().ok()?);
    let prefix: u32 = prefix.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((ip, prefix))
}

/// Whether a stored `ip` value lies inside a CIDR network. For an IPv6 /64 value, its network
/// address is checked.
pub fn cidr_contains((net, prefix): (IpAddr, u32), value: &str) -> bool {
    let value = value.strip_suffix("/64").unwrap_or(value);
    let Ok(ip) = value.parse::<IpAddr>() else {
        return false;
    };
    match (net, canonical(ip)) {
        (IpAddr::V4(n), IpAddr::V4(v)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(n) & mask == u32::from(v) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(v)) => prefix == 0 || mask6(n, prefix) == mask6(v, prefix),
        _ => false,
    }
}

/// A domain as it is stored: lowercase ASCII (IDNs as A-labels), no trailing dot, at least two
/// labels, each 1–63 of `a-z 0-9 -` and not starting or ending with `-`, at most 253 characters,
/// and a top-level label that is not all digits.
pub fn domain(text: &str) -> Option<String> {
    let d = text.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let ok = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    let tld_digits = labels.last()?.bytes().all(|b| b.is_ascii_digit());
    (ok && !tld_digits).then_some(d)
}
