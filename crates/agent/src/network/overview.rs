use crate::domain::AddressScope;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maps addresses into Task 5's approved four-value wire contract.
///
/// `Private` includes ordinary private-use ranges plus non-public unicast host ranges that are
/// useful on local interfaces (shared/NAT, benchmarking, and local translation space). Values
/// that the contract cannot describe truthfully, including unspecified, documentation,
/// multicast, reserved, mapped, discard-only, and ambiguous transition addresses, are omitted.
/// `Global` is returned only by an explicit globally-routable unicast predicate; it is never the
/// fallback for an unrecognized address.
pub(crate) fn classify_address_scope(ip: IpAddr) -> Option<AddressScope> {
    match ip {
        IpAddr::V4(ip) => classify_ipv4(ip),
        IpAddr::V6(ip) => classify_ipv6(ip),
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> Option<AddressScope> {
    if ip.is_loopback() {
        Some(AddressScope::Loopback)
    } else if ip.is_link_local() {
        Some(AddressScope::LinkLocal)
    } else if is_non_public_ipv4_host(ip) {
        Some(AddressScope::Private)
    } else if is_globally_routable_ipv4(ip) {
        Some(AddressScope::Global)
    } else {
        None
    }
}

fn classify_ipv6(ip: Ipv6Addr) -> Option<AddressScope> {
    if ip.is_loopback() {
        Some(AddressScope::Loopback)
    } else if ip.is_unicast_link_local() {
        Some(AddressScope::LinkLocal)
    } else if is_non_public_ipv6_host(ip) {
        Some(AddressScope::Private)
    } else if is_globally_routable_ipv6(ip) {
        Some(AddressScope::Global)
    } else {
        None
    }
}

fn is_non_public_ipv4_host(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ipv4_in_prefix(ip, Ipv4Addr::new(100, 64, 0, 0), 10)
        || ipv4_in_prefix(ip, Ipv4Addr::new(198, 18, 0, 0), 15)
}

fn is_globally_routable_ipv4(ip: Ipv4Addr) -> bool {
    if matches!(ip.octets(), [192, 0, 0, 9 | 10]) {
        return true;
    }

    matches!(ip.octets()[0], 1..=223)
        && !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ipv4_in_prefix(ip, Ipv4Addr::new(100, 64, 0, 0), 10)
        && !ipv4_in_prefix(ip, Ipv4Addr::new(192, 0, 0, 0), 24)
        && !ipv4_in_prefix(ip, Ipv4Addr::new(192, 0, 2, 0), 24)
        && !ipv4_in_prefix(ip, Ipv4Addr::new(192, 88, 99, 0), 24)
        && !ipv4_in_prefix(ip, Ipv4Addr::new(198, 18, 0, 0), 15)
        && !ipv4_in_prefix(ip, Ipv4Addr::new(198, 51, 100, 0), 24)
        && !ipv4_in_prefix(ip, Ipv4Addr::new(203, 0, 113, 0), 24)
}

fn is_non_public_ipv6_host(ip: Ipv6Addr) -> bool {
    ip.is_unique_local()
        || ipv6_in_prefix(ip, "64:ff9b:1::".parse().expect("fixed IPv6 prefix"), 48)
        || ipv6_in_prefix(ip, "2001:2::".parse().expect("fixed IPv6 prefix"), 48)
}

/// Positive allocation policy for ordinary IPv6 global unicast addresses.
///
/// This is the complete set of `ALLOCATED` RIR ranges from IANA's "IPv6 Global Unicast
/// Address Space" registry, last updated 2025-10-10. The partially allocated `2001::/23`
/// and the special-purpose `2002::/16` entry are intentionally handled by the explicit
/// special-purpose rules below instead of treating their whole allocation as globally
/// routable. Unlisted portions of `2000::/3` remain reserved by IANA and are not inferred to
/// be global merely from their address format.
const IANA_ALLOCATED_IPV6_GLOBAL_UNICAST: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2001, 0x0200, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0400, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0600, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0800, 0, 0, 0, 0, 0, 0), 22),
    (Ipv6Addr::new(0x2001, 0x0c00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0e00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x1200, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x1400, 0, 0, 0, 0, 0, 0), 22),
    (Ipv6Addr::new(0x2001, 0x1800, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x1a00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x1c00, 0, 0, 0, 0, 0, 0), 22),
    (Ipv6Addr::new(0x2001, 0x2000, 0, 0, 0, 0, 0, 0), 19),
    (Ipv6Addr::new(0x2001, 0x4000, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4200, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4400, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4600, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4800, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4a00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4c00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x5000, 0, 0, 0, 0, 0, 0), 20),
    (Ipv6Addr::new(0x2001, 0x8000, 0, 0, 0, 0, 0, 0), 19),
    (Ipv6Addr::new(0x2001, 0xa000, 0, 0, 0, 0, 0, 0), 20),
    (Ipv6Addr::new(0x2001, 0xb000, 0, 0, 0, 0, 0, 0), 20),
    (Ipv6Addr::new(0x2003, 0, 0, 0, 0, 0, 0, 0), 18),
    (Ipv6Addr::new(0x2400, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2410, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2610, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2620, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2630, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2800, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2a00, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2a10, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2c00, 0, 0, 0, 0, 0, 0, 0), 12),
];

fn is_globally_routable_ipv6(ip: Ipv6Addr) -> bool {
    if ipv6_in_prefix(ip, "64:ff9b::".parse().expect("fixed IPv6 prefix"), 96)
        || matches!(
            ip,
            address if address == "2001:1::1".parse::<Ipv6Addr>().expect("fixed IPv6 address")
                || address == "2001:1::2".parse::<Ipv6Addr>().expect("fixed IPv6 address")
                || address == "2001:1::3".parse::<Ipv6Addr>().expect("fixed IPv6 address")
        )
        || ipv6_in_prefix(ip, "2001:3::".parse().expect("fixed IPv6 prefix"), 32)
        || ipv6_in_prefix(ip, "2001:4:112::".parse().expect("fixed IPv6 prefix"), 48)
        || ipv6_in_prefix(ip, "2001:20::".parse().expect("fixed IPv6 prefix"), 28)
        || ipv6_in_prefix(ip, "2001:30::".parse().expect("fixed IPv6 prefix"), 28)
        || ipv6_in_prefix(ip, "2620:4f:8000::".parse().expect("fixed IPv6 prefix"), 48)
    {
        return true;
    }

    !ipv6_in_prefix(ip, "2001:db8::".parse().expect("fixed IPv6 prefix"), 32)
        && IANA_ALLOCATED_IPV6_GLOBAL_UNICAST
            .iter()
            .any(|(network, prefix)| ipv6_in_prefix(ip, *network, *prefix))
}

fn ipv4_in_prefix(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(network) & mask
}

fn ipv6_in_prefix(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
    u128::from(ip) & mask == u128::from(network) & mask
}
