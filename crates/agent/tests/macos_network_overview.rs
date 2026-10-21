use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr, Ifv6Addr, Interface};
use network_path_agent::{
    domain::{AddressScope, InterfaceKind, MihomoRuntime},
    platform::macos::network::build_overview,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HARDWARE_PORTS: &str = r#"
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 00:11:22:33:44:55

Hardware Port: Thunderbolt Ethernet
Device: en5
Ethernet Address: 66:77:88:99:aa:bb

Hardware Port: USB Ethernet
Device: en9
Ethernet Address: cc:dd:ee:ff:00:11
"#;

fn runtime() -> MihomoRuntime {
    MihomoRuntime {
        available: true,
        mode: Some("rule".into()),
        tun_enabled: Some(true),
        controller: Some("auto_unix".into()),
    }
}

fn interface(name: &str, ip: &str, oper_status: IfOperStatus) -> Interface {
    let addr = match ip.parse::<IpAddr>().unwrap() {
        IpAddr::V4(ip) => IfAddr::V4(Ifv4Addr {
            ip,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            prefixlen: 24,
            broadcast: None,
        }),
        IpAddr::V6(ip) => IfAddr::V6(Ifv6Addr {
            ip,
            netmask: "ffff:ffff:ffff:ffff::".parse::<Ipv6Addr>().unwrap(),
            prefixlen: 64,
            broadcast: None,
        }),
    };
    Interface {
        name: name.into(),
        addr,
        index: Some(1),
        oper_status,
        is_p2p: name.starts_with("utun"),
    }
}

fn up(name: &str, ip: &str) -> Interface {
    interface(name, ip, IfOperStatus::Up)
}

fn fixture_interfaces() -> Vec<Interface> {
    vec![
        up("utun5", "198.18.0.1"),
        up("lo0", "::1"),
        up("en5", "10.20.30.40"),
        up("en0", "fe80::1"),
        up("en0", "192.168.1.20"),
        up("en0", "2001:4860:4860::8888"),
        up("lo0", "127.0.0.1"),
    ]
}

fn interface_named<'a>(
    overview: &'a network_path_agent::domain::LocalNetworkOverview,
    name: &str,
) -> &'a network_path_agent::domain::NetworkInterfaceInfo {
    overview
        .interfaces
        .iter()
        .find(|interface| interface.name == name)
        .unwrap_or_else(|| panic!("missing interface {name}"))
}

fn observed_scope(
    overview: &network_path_agent::domain::LocalNetworkOverview,
    address: &str,
) -> Option<AddressScope> {
    let address = address.parse::<IpAddr>().unwrap();
    overview
        .interfaces
        .iter()
        .flat_map(|interface| &interface.addresses)
        .find(|candidate| candidate.ip == address)
        .map(|candidate| candidate.scope)
}

fn scope_for(address: &str) -> Option<AddressScope> {
    let overview = build_overview(vec![up("fixture0", address)], "", "", runtime());
    let scope = observed_scope(&overview, address);
    if scope.is_none() {
        assert!(
            overview.interfaces.is_empty(),
            "omitted address {address} left an empty interface"
        );
    }
    scope
}

fn assert_default_consistency(
    overview: &network_path_agent::domain::LocalNetworkOverview,
    expected: Option<&str>,
) {
    assert_eq!(overview.default_interface.as_deref(), expected);
    let marked = overview
        .interfaces
        .iter()
        .filter(|interface| interface.is_default)
        .collect::<Vec<_>>();
    match expected {
        Some(name) => {
            assert_eq!(
                marked.len(),
                1,
                "{name} must have exactly one default entry"
            );
            assert_eq!(marked[0].name, name);
        }
        None => assert!(marked.is_empty()),
    }
}

fn label_from_hardware_fixture(
    interface_name: &str,
    hardware_ports: &str,
) -> (String, InterfaceKind) {
    let overview = build_overview(
        vec![up(interface_name, "8.8.8.8")],
        "",
        hardware_ports,
        runtime(),
    );
    let interface = interface_named(&overview, interface_name);
    (interface.display_name.clone(), interface.kind)
}

#[test]
fn labels_wifi_ethernet_tun_and_loopback_interfaces() {
    let overview = build_overview(
        fixture_interfaces(),
        "  route to: default\n  interface: en0  \n",
        HARDWARE_PORTS,
        runtime(),
    );

    assert_eq!(overview.default_interface.as_deref(), Some("en0"));
    assert_eq!(interface_named(&overview, "en0").display_name, "Wi-Fi");
    assert_eq!(interface_named(&overview, "en0").kind, InterfaceKind::Wifi);
    assert_eq!(
        interface_named(&overview, "en5").display_name,
        "Thunderbolt Ethernet"
    );
    assert_eq!(
        interface_named(&overview, "en5").kind,
        InterfaceKind::Ethernet
    );
    assert_eq!(interface_named(&overview, "utun5").display_name, "TUN");
    assert_eq!(interface_named(&overview, "utun5").kind, InterfaceKind::Tun);
    assert_eq!(interface_named(&overview, "lo0").display_name, "Loopback");
    assert_eq!(
        interface_named(&overview, "lo0").kind,
        InterfaceKind::Loopback
    );
}

#[test]
fn parses_real_hardware_port_labels_and_ignores_incomplete_blocks() {
    let cases = [
        (
            "AirPort",
            "en0",
            "Hardware Port: AirPort\nDevice: en0\n",
            "AirPort",
            InterfaceKind::Wifi,
        ),
        (
            "Wi-Fi",
            "en0",
            "Hardware Port: Wi-Fi\nDevice: en0\n",
            "Wi-Fi",
            InterfaceKind::Wifi,
        ),
        (
            "Ethernet Adapter",
            "en4",
            "Hardware Port: Ethernet Adapter (en4)\nDevice: en4\n",
            "Ethernet Adapter (en4)",
            InterfaceKind::Ethernet,
        ),
        (
            "Thunderbolt Ethernet",
            "en5",
            "Hardware Port: Thunderbolt Ethernet\nDevice: en5\n",
            "Thunderbolt Ethernet",
            InterfaceKind::Ethernet,
        ),
        (
            "Thunderbolt Bridge",
            "bridge0",
            "Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n",
            "Thunderbolt Bridge",
            InterfaceKind::Other,
        ),
        (
            "missing Hardware Port",
            "en0",
            "Device: en0\n",
            "en0",
            InterfaceKind::Other,
        ),
        (
            "missing Device",
            "en0",
            "Hardware Port: Wi-Fi\n",
            "en0",
            InterfaceKind::Other,
        ),
        (
            "malformed Device",
            "en0",
            "Hardware Port: Wi-Fi\nDevice: en0 injected\n",
            "en0",
            InterfaceKind::Other,
        ),
        (
            "stale block separated by blank line",
            "en0",
            "Hardware Port: AirPort\n\nDevice: en0\n",
            "en0",
            InterfaceKind::Other,
        ),
        (
            "valid block after malformed empty port",
            "en0",
            "Hardware Port:\nHardware Port: Wi-Fi\nDevice: en0\n",
            "Wi-Fi",
            InterfaceKind::Wifi,
        ),
    ];

    for (name, interface_name, fixture, display_name, kind) in cases {
        assert_eq!(
            label_from_hardware_fixture(interface_name, fixture),
            (display_name.into(), kind),
            "{name}"
        );
    }
}

#[test]
fn repeated_hardware_blocks_are_accepted_only_when_they_agree() {
    let repeated_same = "Hardware Port: Wi-Fi\nDevice: en0\n\
                         \nHardware Port: Wi-Fi\nDevice: en0\n";
    let repeated_conflict = "Hardware Port: Wi-Fi\nDevice: en0\n\
                             \nHardware Port: Ethernet\nDevice: en0\n";

    assert_eq!(
        label_from_hardware_fixture("en0", repeated_same),
        ("Wi-Fi".into(), InterfaceKind::Wifi)
    );
    assert_eq!(
        label_from_hardware_fixture("en0", repeated_conflict),
        ("en0".into(), InterfaceKind::Other)
    );
}

#[test]
fn vlan_trailer_terminates_hardware_port_parsing() {
    let fixture = "VLAN Configurations\n===================\n\
                   Hardware Port: Ethernet\nDevice: en0\n";

    assert_eq!(
        label_from_hardware_fixture("en0", fixture),
        ("en0".into(), InterfaceKind::Other)
    );
}

#[test]
fn classifies_ipv4_and_ipv6_address_scopes() {
    let interfaces = [
        ("lo0", "127.9.8.7", AddressScope::Loopback),
        ("lo0", "::1", AddressScope::Loopback),
        ("en0", "169.254.9.8", AddressScope::LinkLocal),
        ("en0", "fe80::abcd", AddressScope::LinkLocal),
        ("en0", "10.1.2.3", AddressScope::Private),
        ("en0", "172.31.2.3", AddressScope::Private),
        ("en0", "192.168.2.3", AddressScope::Private),
        ("utun5", "fc00::1234", AddressScope::Private),
        ("utun5", "fd12:3456::1", AddressScope::Private),
        ("en0", "8.8.8.8", AddressScope::Global),
        ("en0", "2001:4860:4860::8888", AddressScope::Global),
    ];
    let overview = build_overview(
        interfaces
            .iter()
            .map(|(name, ip, _)| up(name, ip))
            .collect(),
        "interface: en0\n",
        HARDWARE_PORTS,
        runtime(),
    );

    for (_, address, expected) in interfaces {
        assert_eq!(
            observed_scope(&overview, address),
            Some(expected),
            "{address}"
        );
    }
}

#[test]
fn classifies_or_omits_ipv4_special_use_boundaries_without_calling_them_global() {
    let cases = [
        ("0.0.0.0", None),
        ("0.255.255.255", None),
        ("1.0.0.0", Some(AddressScope::Global)),
        ("9.255.255.255", Some(AddressScope::Global)),
        ("10.0.0.0", Some(AddressScope::Private)),
        ("10.255.255.255", Some(AddressScope::Private)),
        ("11.0.0.0", Some(AddressScope::Global)),
        ("100.63.255.255", Some(AddressScope::Global)),
        ("100.64.0.0", Some(AddressScope::Private)),
        ("100.127.255.255", Some(AddressScope::Private)),
        ("100.128.0.0", Some(AddressScope::Global)),
        ("126.255.255.255", Some(AddressScope::Global)),
        ("127.0.0.0", Some(AddressScope::Loopback)),
        ("127.255.255.255", Some(AddressScope::Loopback)),
        ("128.0.0.0", Some(AddressScope::Global)),
        ("169.253.255.255", Some(AddressScope::Global)),
        ("169.254.0.0", Some(AddressScope::LinkLocal)),
        ("169.254.255.255", Some(AddressScope::LinkLocal)),
        ("169.255.0.0", Some(AddressScope::Global)),
        ("172.15.255.255", Some(AddressScope::Global)),
        ("172.16.0.0", Some(AddressScope::Private)),
        ("172.31.255.255", Some(AddressScope::Private)),
        ("172.32.0.0", Some(AddressScope::Global)),
        ("192.0.0.0", None),
        ("192.0.0.8", None),
        ("192.0.0.9", Some(AddressScope::Global)),
        ("192.0.0.10", Some(AddressScope::Global)),
        ("192.0.0.11", None),
        ("192.0.0.170", None),
        ("192.0.0.255", None),
        ("192.0.1.0", Some(AddressScope::Global)),
        ("192.0.2.1", None),
        ("192.88.99.1", None),
        ("192.167.255.255", Some(AddressScope::Global)),
        ("192.168.0.0", Some(AddressScope::Private)),
        ("192.168.255.255", Some(AddressScope::Private)),
        ("192.169.0.0", Some(AddressScope::Global)),
        ("198.17.255.255", Some(AddressScope::Global)),
        ("198.18.0.0", Some(AddressScope::Private)),
        ("198.19.255.255", Some(AddressScope::Private)),
        ("198.20.0.0", Some(AddressScope::Global)),
        ("198.51.100.1", None),
        ("203.0.113.1", None),
        ("223.255.255.255", Some(AddressScope::Global)),
        ("224.0.0.0", None),
        ("239.255.255.255", None),
        ("240.0.0.0", None),
        ("255.255.255.254", None),
        ("255.255.255.255", None),
    ];

    for (address, expected) in cases {
        assert_eq!(scope_for(address), expected, "{address}");
    }
}

#[test]
fn classifies_or_omits_ipv6_special_use_boundaries_without_calling_them_global() {
    let cases = [
        ("::", None),
        ("::1", Some(AddressScope::Loopback)),
        ("::ffff:8.8.8.8", None),
        ("::ffff:192.168.1.1", None),
        ("64:ff9b::1", Some(AddressScope::Global)),
        ("64:ff9b:1::1", Some(AddressScope::Private)),
        ("100::1", None),
        ("100:0:0:1::1", None),
        ("2001::1", None),
        ("2001:1::1", Some(AddressScope::Global)),
        ("2001:2::1", Some(AddressScope::Private)),
        ("2001:3::1", Some(AddressScope::Global)),
        ("2001:20::1", Some(AddressScope::Global)),
        ("2001:db8::1", None),
        ("2002::1", None),
        ("2001:4860:4860::8888", Some(AddressScope::Global)),
        ("2620:4f:8000::1", Some(AddressScope::Global)),
        ("2606:4700:4700::1111", Some(AddressScope::Global)),
        ("3fff::1", None),
        ("5f00::1", None),
        ("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", None),
        ("fc00::", Some(AddressScope::Private)),
        (
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Private),
        ),
        ("fe00::", None),
        ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", None),
        ("fe80::", Some(AddressScope::LinkLocal)),
        (
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::LinkLocal),
        ),
        ("fec0::", None),
        ("ff00::", None),
        ("ff02::1", None),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", None),
    ];

    for (address, expected) in cases {
        assert_eq!(scope_for(address), expected, "{address}");
    }
}

#[test]
fn recognizes_only_iana_allocated_ipv6_global_unicast_boundaries() {
    let cases = [
        (
            "before allocated global-unicast space",
            "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        (
            "partially allocated IANA block remainder",
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        (
            "2001:200::/23 lower",
            "2001:200::",
            Some(AddressScope::Global),
        ),
        (
            "2001:200::/23 upper",
            "2001:3ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:400::/23 lower",
            "2001:400::",
            Some(AddressScope::Global),
        ),
        (
            "2001:400::/23 upper",
            "2001:5ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:600::/23 lower",
            "2001:600::",
            Some(AddressScope::Global),
        ),
        (
            "2001:600::/23 upper",
            "2001:7ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:800::/22 lower",
            "2001:800::",
            Some(AddressScope::Global),
        ),
        (
            "2001:800::/22 upper",
            "2001:bff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:c00::/23 lower",
            "2001:c00::",
            Some(AddressScope::Global),
        ),
        (
            "2001:c00::/23 upper",
            "2001:dff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:e00::/23 lower",
            "2001:e00::",
            Some(AddressScope::Global),
        ),
        (
            "2001:e00::/23 upper",
            "2001:fff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("first 2001 allocation gap lower", "2001:1000::", None),
        (
            "first 2001 allocation gap upper",
            "2001:11ff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        (
            "2001:1200::/23 lower",
            "2001:1200::",
            Some(AddressScope::Global),
        ),
        (
            "2001:1200::/23 upper",
            "2001:13ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:1400::/22 lower",
            "2001:1400::",
            Some(AddressScope::Global),
        ),
        (
            "2001:1400::/22 upper",
            "2001:17ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:1800::/23 lower",
            "2001:1800::",
            Some(AddressScope::Global),
        ),
        (
            "2001:1800::/23 upper",
            "2001:19ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:1a00::/23 lower",
            "2001:1a00::",
            Some(AddressScope::Global),
        ),
        (
            "2001:1a00::/23 upper",
            "2001:1bff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:1c00::/22 lower",
            "2001:1c00::",
            Some(AddressScope::Global),
        ),
        (
            "2001:1c00::/22 upper",
            "2001:1fff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:2000::/19 lower",
            "2001:2000::",
            Some(AddressScope::Global),
        ),
        (
            "2001:2000::/19 upper",
            "2001:3fff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:4000::/23 lower",
            "2001:4000::",
            Some(AddressScope::Global),
        ),
        (
            "2001:4000::/23 upper",
            "2001:41ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:4200::/23 lower",
            "2001:4200::",
            Some(AddressScope::Global),
        ),
        (
            "2001:4200::/23 upper",
            "2001:43ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:4400::/23 lower",
            "2001:4400::",
            Some(AddressScope::Global),
        ),
        (
            "2001:4400::/23 upper",
            "2001:45ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:4600::/23 lower",
            "2001:4600::",
            Some(AddressScope::Global),
        ),
        (
            "2001:4600::/23 upper",
            "2001:47ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:4800::/23 lower",
            "2001:4800::",
            Some(AddressScope::Global),
        ),
        (
            "2001:4800::/23 upper",
            "2001:49ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:4a00::/23 lower",
            "2001:4a00::",
            Some(AddressScope::Global),
        ),
        (
            "2001:4a00::/23 upper",
            "2001:4bff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:4c00::/23 lower",
            "2001:4c00::",
            Some(AddressScope::Global),
        ),
        (
            "2001:4c00::/23 upper",
            "2001:4dff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("second 2001 allocation gap lower", "2001:4e00::", None),
        (
            "second 2001 allocation gap upper",
            "2001:4fff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        (
            "2001:5000::/20 lower",
            "2001:5000::",
            Some(AddressScope::Global),
        ),
        (
            "2001:5000::/20 upper",
            "2001:5fff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("third 2001 allocation gap lower", "2001:6000::", None),
        (
            "third 2001 allocation gap upper",
            "2001:7fff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        (
            "2001:8000::/19 lower",
            "2001:8000::",
            Some(AddressScope::Global),
        ),
        (
            "2001:8000::/19 upper",
            "2001:9fff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:a000::/20 lower",
            "2001:a000::",
            Some(AddressScope::Global),
        ),
        (
            "2001:a000::/20 upper",
            "2001:afff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        (
            "2001:b000::/20 lower",
            "2001:b000::",
            Some(AddressScope::Global),
        ),
        (
            "2001:b000::/20 upper",
            "2001:bfff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("final 2001 allocation gap lower", "2001:c000::", None),
        (
            "final 2001 allocation gap upper",
            "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("6to4 lower", "2002::", None),
        (
            "6to4 upper",
            "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("2003::/18 lower", "2003::", Some(AddressScope::Global)),
        (
            "2003::/18 upper",
            "2003:3fff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("after 2003::/18", "2003:4000::", None),
        (
            "before APNIC /12 allocations",
            "23ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("2400::/12 lower", "2400::", Some(AddressScope::Global)),
        (
            "2400::/12 upper",
            "240f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("2410::/12 lower", "2410::", Some(AddressScope::Global)),
        (
            "2410::/12 upper",
            "241f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("after APNIC /12 allocations", "2420::", None),
        ("2600::/12 lower", "2600::", Some(AddressScope::Global)),
        (
            "2600::/12 upper",
            "260f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("2610::/23 lower", "2610::", Some(AddressScope::Global)),
        (
            "2610::/23 upper",
            "2610:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("after 2610::/23", "2610:200::", None),
        ("2620::/23 lower", "2620::", Some(AddressScope::Global)),
        (
            "2620::/23 upper",
            "2620:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("after 2620::/23", "2620:200::", None),
        ("2630::/12 lower", "2630::", Some(AddressScope::Global)),
        (
            "2630::/12 upper",
            "263f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("after ARIN allocations", "2640::", None),
        ("2800::/12 lower", "2800::", Some(AddressScope::Global)),
        (
            "2800::/12 upper",
            "280f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("after LACNIC allocation", "2810::", None),
        ("2a00::/12 lower", "2a00::", Some(AddressScope::Global)),
        (
            "2a00::/12 upper",
            "2a0f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("2a10::/12 lower", "2a10::", Some(AddressScope::Global)),
        (
            "2a10::/12 upper",
            "2a1f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("after RIPE NCC allocations", "2a20::", None),
        ("2c00::/12 lower", "2c00::", Some(AddressScope::Global)),
        (
            "2c00::/12 upper",
            "2c0f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(AddressScope::Global),
        ),
        ("after AFRINIC allocation", "2c10::", None),
        ("2d00::/8 lower reserved", "2d00::", None),
        (
            "2d00::/8 upper reserved",
            "2dff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("2e00::/7 lower reserved", "2e00::", None),
        ("2e00::/7 includes 2f00", "2f00::", None),
        (
            "2e00::/7 upper reserved",
            "2fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3000::/5 lower reserved", "3000::", None),
        (
            "3000::/5 upper reserved",
            "37ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3800::/6 lower reserved", "3800::", None),
        (
            "3800::/6 upper reserved",
            "3bff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3c00::/7 lower reserved", "3c00::", None),
        (
            "3c00::/7 upper reserved",
            "3dff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3e00::/8 lower reserved", "3e00::", None),
        (
            "3e00::/8 upper reserved",
            "3eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3f00::/9 lower reserved", "3f00::", None),
        (
            "3f00::/9 upper reserved",
            "3f7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3f80::/10 lower reserved", "3f80::", None),
        (
            "3f80::/10 upper reserved",
            "3fbf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3fc0::/11 lower reserved", "3fc0::", None),
        (
            "3fc0::/11 upper reserved",
            "3fdf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3fe0::/12 lower reserved", "3fe0::", None),
        (
            "3fe0::/12 upper reserved",
            "3fef:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3ff0::/13 lower reserved", "3ff0::", None),
        (
            "3ff0::/13 upper reserved",
            "3ff7:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3ff8::/14 lower reserved", "3ff8::", None),
        (
            "3ff8::/14 upper reserved",
            "3ffb:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3ffc::/15 lower reserved", "3ffc::", None),
        (
            "3ffc::/15 upper reserved",
            "3ffd:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("retired 3ffe::/16 lower", "3ffe::", None),
        (
            "retired 3ffe::/16 upper",
            "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("3fff documentation lower", "3fff::", None),
        (
            "3fff documentation upper",
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
        ),
        ("after 3fff documentation", "3fff:1000::", None),
        ("after assignable global-unicast space", "4000::", None),
        (
            "representative 2001 allocation",
            "2001:4860:4860::8888",
            Some(AddressScope::Global),
        ),
        (
            "representative 2400 allocation",
            "2404:6800:4001::200e",
            Some(AddressScope::Global),
        ),
        (
            "representative 2600 allocation",
            "2606:4700:4700::1111",
            Some(AddressScope::Global),
        ),
        (
            "representative 2800 allocation",
            "2800:3f0:4001::",
            Some(AddressScope::Global),
        ),
        (
            "representative 2a00 allocation",
            "2a00:1450:4001::200e",
            Some(AddressScope::Global),
        ),
        (
            "representative 2c00 allocation",
            "2c0f:f248::1",
            Some(AddressScope::Global),
        ),
    ];

    for (name, address, expected) in cases {
        assert_eq!(scope_for(address), expected, "{name}: {address}");
    }
}

#[test]
fn benchmark_tun_address_is_private_not_global() {
    let overview = build_overview(fixture_interfaces(), "", HARDWARE_PORTS, runtime());

    assert_eq!(
        observed_scope(&overview, "198.18.0.1"),
        Some(AddressScope::Private)
    );
}

#[test]
fn omits_down_interfaces_and_hardware_ports_without_addresses() {
    let overview = build_overview(
        vec![
            up("en0", "192.168.1.20"),
            interface("en5", "10.20.30.40", IfOperStatus::Down),
            interface("en6", "10.20.30.41", IfOperStatus::Unknown),
        ],
        "interface: en0\n",
        HARDWARE_PORTS,
        runtime(),
    );

    assert_eq!(
        overview
            .interfaces
            .iter()
            .map(|interface| interface.name.as_str())
            .collect::<Vec<_>>(),
        vec!["en0"]
    );
    assert!(
        overview
            .interfaces
            .iter()
            .all(|interface| !interface.addresses.is_empty())
    );
}

#[test]
fn deduplicates_and_sorts_interfaces_and_addresses_deterministically() {
    let overview = build_overview(
        vec![
            up("utun5", "fd00::2"),
            up("en0", "2001:4860::2"),
            up("en5", "10.0.0.2"),
            up("en0", "192.168.1.20"),
            up("en0", "192.168.1.3"),
            up("en0", "192.168.1.20"),
            up("lo0", "127.0.0.1"),
            up("en5", "10.0.0.2"),
        ],
        "interface: en5\n",
        HARDWARE_PORTS,
        runtime(),
    );

    assert_eq!(
        overview
            .interfaces
            .iter()
            .map(|interface| interface.name.as_str())
            .collect::<Vec<_>>(),
        vec!["en0", "en5", "lo0", "utun5"]
    );
    assert_eq!(
        interface_named(&overview, "en0")
            .addresses
            .iter()
            .map(|address| address.ip.to_string())
            .collect::<Vec<_>>(),
        vec!["192.168.1.3", "192.168.1.20", "2001:4860::2"]
    );
    assert_eq!(interface_named(&overview, "en5").addresses.len(), 1);
}

#[test]
fn selects_exactly_one_default_interface_from_repeated_candidates() {
    let overview = build_overview(
        fixture_interfaces(),
        "interface: en5\n  interface:   en5  \n",
        HARDWARE_PORTS,
        runtime(),
    );

    assert_default_consistency(&overview, Some("en5"));
}

#[test]
fn clears_default_route_candidates_not_present_in_retained_interfaces() {
    let cases = [
        (
            "down candidate",
            vec![
                interface("en0", "192.168.1.20", IfOperStatus::Down),
                up("en5", "10.0.0.2"),
            ],
            "interface: en0\n",
            None,
        ),
        (
            "candidate emptied by special-use omission",
            vec![up("en0", "0.0.0.0"), up("en5", "10.0.0.2")],
            "interface: en0\n",
            None,
        ),
        (
            "absent candidate",
            vec![up("en5", "10.0.0.2")],
            "interface: en0\n",
            None,
        ),
        (
            "retained candidate",
            vec![up("en5", "10.0.0.2")],
            "interface: en5\n",
            Some("en5"),
        ),
    ];

    for (name, interfaces, route_output, expected) in cases {
        let overview = build_overview(interfaces, route_output, HARDWARE_PORTS, runtime());
        assert_default_consistency(&overview, expected);
        if expected.is_none() {
            assert!(
                overview
                    .interfaces
                    .iter()
                    .all(|interface| !interface.is_default),
                "{name}"
            );
        }
    }
}

#[test]
fn conflicting_or_malformed_default_route_output_does_not_guess() {
    for output in [
        "interface: en0\ninterface: en5\n",
        "interface:\n",
        "interface: en0 injected\n",
        "gateway: 192.168.1.1\n",
        "not route output",
    ] {
        let overview = build_overview(fixture_interfaces(), output, HARDWARE_PORTS, runtime());

        assert_eq!(overview.default_interface, None, "{output:?}");
        assert!(
            overview
                .interfaces
                .iter()
                .all(|interface| !interface.is_default),
            "{output:?}"
        );
    }
}

#[test]
fn serializes_the_complete_exact_network_overview_contract() {
    let overview = build_overview(
        fixture_interfaces(),
        "interface: en0\n",
        HARDWARE_PORTS,
        runtime(),
    );
    let json = serde_json::to_value(overview).unwrap();

    assert_eq!(
        json,
        serde_json::json!({
            "interfaces": [
                {
                    "name": "en0",
                    "display_name": "Wi-Fi",
                    "kind": "wifi",
                    "is_default": true,
                    "addresses": [
                        { "ip": "192.168.1.20", "scope": "private" },
                        { "ip": "2001:4860:4860::8888", "scope": "global" },
                        { "ip": "fe80::1", "scope": "link_local" }
                    ]
                },
                {
                    "name": "en5",
                    "display_name": "Thunderbolt Ethernet",
                    "kind": "ethernet",
                    "is_default": false,
                    "addresses": [
                        { "ip": "10.20.30.40", "scope": "private" }
                    ]
                },
                {
                    "name": "lo0",
                    "display_name": "Loopback",
                    "kind": "loopback",
                    "is_default": false,
                    "addresses": [
                        { "ip": "127.0.0.1", "scope": "loopback" },
                        { "ip": "::1", "scope": "loopback" }
                    ]
                },
                {
                    "name": "utun5",
                    "display_name": "TUN",
                    "kind": "tun",
                    "is_default": false,
                    "addresses": [
                        { "ip": "198.18.0.1", "scope": "private" }
                    ]
                }
            ],
            "default_interface": "en0",
            "mihomo": {
                "available": true,
                "mode": "rule",
                "tun_enabled": true,
                "controller": "auto_unix"
            }
        })
    );
}
