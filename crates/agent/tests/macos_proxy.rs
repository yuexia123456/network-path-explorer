use network_path_agent::domain::{EvidenceLevel, ProxyKind};
use network_path_agent::platform::macos::proxy::{decide_proxy, parse_scutil_proxy};
use url::Url;

const FIXTURE: &str = r#"<dictionary> {
  ExceptionsList : <array> {
    0 : 127.0.0.1
    1 : *.local
    2 : <local>
  }
  HTTPEnable : 1
  HTTPPort : 2023
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 2023
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 0
}"#;

#[test]
fn selects_https_proxy_for_public_url() {
    let settings = parse_scutil_proxy(FIXTURE).unwrap();
    let decision = decide_proxy(&Url::parse("https://example.com").unwrap(), &settings);
    assert_eq!(decision.kind, ProxyKind::Https);
    assert_eq!(decision.host.as_deref(), Some("127.0.0.1"));
    assert_eq!(decision.port, Some(2023));
}

#[test]
fn bypasses_dot_local_hostnames() {
    let settings = parse_scutil_proxy(FIXTURE).unwrap();
    let decision = decide_proxy(&Url::parse("https://printer.local").unwrap(), &settings);
    assert_eq!(decision.kind, ProxyKind::Direct);
    assert_eq!(
        decision.bypass_reason.as_deref(),
        Some("匹配系统代理绕过规则 *.local")
    );
}

#[test]
fn rejects_enabled_proxy_without_a_port() {
    let malformed = r#"<dictionary> {
  HTTPEnable : 1
  HTTPProxy : 127.0.0.1
}"#;

    assert!(parse_scutil_proxy(malformed).is_err());
}

#[test]
fn selects_direct_when_http_proxy_is_disabled() {
    let disabled = r#"<dictionary> {
  HTTPEnable : 0
  HTTPProxy : 127.0.0.1
  HTTPPort : 2023
}"#;

    let settings = parse_scutil_proxy(disabled).unwrap();
    let decision = decide_proxy(&Url::parse("http://example.com").unwrap(), &settings);

    assert_eq!(decision.kind, ProxyKind::Direct);
    assert_eq!(
        decision.evidence.summary,
        "系统代理配置为这个网址选择了直连"
    );
}

#[test]
fn reports_unknown_when_proxy_auto_configuration_is_enabled() {
    let auto_config = r#"<dictionary> {
  HTTPSEnable : 1
  HTTPSPort : 2023
  HTTPSProxy : 127.0.0.1
  ProxyAutoConfigEnable : 1
}"#;

    let settings = parse_scutil_proxy(auto_config).unwrap();
    let decision = decide_proxy(&Url::parse("https://example.com").unwrap(), &settings);

    assert_eq!(decision.kind, ProxyKind::Unknown);
    assert_eq!(decision.evidence.level, EvidenceLevel::Unknown);
}

#[test]
fn reports_unknown_when_proxy_auto_discovery_is_enabled() {
    let auto_discovery = r#"<dictionary> {
  HTTPSEnable : 1
  HTTPSPort : 2023
  HTTPSProxy : 127.0.0.1
  ProxyAutoDiscoveryEnable : 1
}"#;

    let settings = parse_scutil_proxy(auto_discovery).unwrap();
    let decision = decide_proxy(&Url::parse("https://example.com").unwrap(), &settings);

    assert_eq!(decision.kind, ProxyKind::Unknown);
    assert_eq!(decision.evidence.level, EvidenceLevel::Unknown);
}

#[test]
fn bypasses_simple_hostname_when_system_excludes_simple_hostnames() {
    let simple_hostname_excluded = r#"<dictionary> {
  ExcludeSimpleHostnames : 1
  HTTPSEnable : 1
  HTTPSPort : 2023
  HTTPSProxy : 127.0.0.1
}"#;

    let settings = parse_scutil_proxy(simple_hostname_excluded).unwrap();
    let decision = decide_proxy(&Url::parse("https://printer").unwrap(), &settings);

    assert_eq!(decision.kind, ProxyKind::Direct);
    assert_eq!(
        decision.bypass_reason.as_deref(),
        Some("匹配系统代理绕过规则 ExcludeSimpleHostnames")
    );
}

#[test]
fn bypasses_hostname_for_mixed_case_wildcard_suffix() {
    let mixed_case_wildcard = r#"<dictionary> {
  ExceptionsList : <array> {
    0 : *.LOCAL
  }
  HTTPSEnable : 1
  HTTPSPort : 2023
  HTTPSProxy : 127.0.0.1
}"#;

    let settings = parse_scutil_proxy(mixed_case_wildcard).unwrap();
    let decision = decide_proxy(&Url::parse("https://printer.local").unwrap(), &settings);

    assert_eq!(decision.kind, ProxyKind::Direct);
    assert_eq!(
        decision.bypass_reason.as_deref(),
        Some("匹配系统代理绕过规则 *.LOCAL")
    );
}

#[test]
fn bypasses_matching_ipv4_and_ipv6_cidr_exceptions_for_ip_literals() {
    let cidr_exceptions = r#"<dictionary> {
  ExceptionsList : <array> {
    0 : 192.168.0.0/16
    1 : fd12:3456::/32
  }
  HTTPSEnable : 1
  HTTPSPort : 2023
  HTTPSProxy : 127.0.0.1
}"#;
    let settings = parse_scutil_proxy(cidr_exceptions).unwrap();

    for (url, exception) in [
        ("https://192.168.42.7", "192.168.0.0/16"),
        ("https://[fd12:3456:789a::7]", "fd12:3456::/32"),
    ] {
        let decision = decide_proxy(&Url::parse(url).unwrap(), &settings);
        let expected_reason = format!("匹配系统代理绕过规则 {exception}");
        assert_eq!(decision.kind, ProxyKind::Direct, "{url}");
        assert_eq!(
            decision.bypass_reason.as_deref(),
            Some(expected_reason.as_str()),
            "{url}"
        );
    }
}

#[test]
fn malformed_or_nonmatching_cidr_exceptions_do_not_bypass_the_proxy() {
    let cidr_exceptions = r#"<dictionary> {
  ExceptionsList : <array> {
    0 : 192.168.0.0/33
    1 : 192.168.0.0/-1
    2 : fd12:3456::/129
    3 : fd12:3456::/not-a-prefix
    4 : 10.0.0.0/8
    5 : fe00::/8
  }
  HTTPSEnable : 1
  HTTPSPort : 2023
  HTTPSProxy : 127.0.0.1
}"#;
    let settings = parse_scutil_proxy(cidr_exceptions).unwrap();

    for url in ["https://192.168.42.7", "https://[fd12:3456::7]"] {
        assert_eq!(
            decide_proxy(&Url::parse(url).unwrap(), &settings).kind,
            ProxyKind::Https,
            "{url}"
        );
    }
}

#[test]
fn exact_private_ip_exception_is_honored() {
    let exact_exception = r#"<dictionary> {
  ExceptionsList : <array> {
    0 : 192.168.42.7
  }
  HTTPSEnable : 1
  HTTPSPort : 2023
  HTTPSProxy : 127.0.0.1
}"#;
    let settings = parse_scutil_proxy(exact_exception).unwrap();

    let decision = decide_proxy(&Url::parse("https://192.168.42.7").unwrap(), &settings);

    assert_eq!(decision.kind, ProxyKind::Direct);
}
