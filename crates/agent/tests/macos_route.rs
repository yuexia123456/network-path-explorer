use network_path_agent::platform::macos::route::parse_route_get;
use std::net::IpAddr;

#[test]
fn extracts_gateway_and_interface() {
    let output =
        "route to: 93.184.216.34\ndestination: default\ngateway: 192.168.1.1\ninterface: en0\n";
    let route = parse_route_get(output, "93.184.216.34".parse().unwrap()).unwrap();
    assert_eq!(route.interface, "en0");
    assert_eq!(route.gateway.unwrap().to_string(), "192.168.1.1");
}

#[test]
fn parses_route_output_edge_cases() {
    let ipv4: IpAddr = "93.184.216.34".parse().unwrap();
    let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
    let cases = [
        (
            "leading whitespace",
            "  gateway: 192.168.1.1\n  interface: en0\n",
            ipv4,
            Some("192.168.1.1"),
            "en0",
        ),
        ("missing gateway", "interface: lo0\n", ipv4, None, "lo0"),
        (
            "scoped ipv6 gateway",
            "gateway: fe80::1%en0\ninterface: en0\n",
            ipv6,
            Some("fe80::1"),
            "en0",
        ),
    ];

    for (name, output, destination, gateway, interface) in cases {
        let route =
            parse_route_get(output, destination).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(route.destination, destination, "{name}");
        assert_eq!(
            route.gateway.map(|gateway| gateway.to_string()),
            gateway.map(str::to_owned),
            "{name}"
        );
        assert_eq!(route.interface, interface, "{name}");
    }

    assert!(parse_route_get("gateway: 192.168.1.1\ninterface: \n", ipv4).is_err());
    assert!(parse_route_get("gateway: 192.168.1.1\n", ipv4).is_err());
    let malformed_gateway = parse_route_get("gateway: not-an-ip\ninterface: en0\n", ipv4).unwrap();
    assert_eq!(malformed_gateway.interface, "en0");
    assert_eq!(malformed_gateway.gateway, None);
}
