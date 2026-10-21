use network_path_agent::{conclusion::build_conclusion, domain::*};

fn system_proxy(kind: ProxyKind, host: Option<&str>, port: Option<u16>) -> ProxyDecision {
    ProxyDecision {
        kind,
        host: host.map(str::to_owned),
        port,
        bypass_reason: None,
        evidence: Evidence {
            level: EvidenceLevel::Confirmed,
            source: "test".into(),
            summary: "system proxy".into(),
        },
    }
}

fn unknown_traffic() -> TrafficDecision {
    TrafficDecision::unknown("mihomo", "未能确认 Clash 最终决策")
}

fn traffic(kind: TrafficDecisionKind, level: EvidenceLevel) -> TrafficDecision {
    TrafficDecision {
        kind,
        mode: Some("rule".into()),
        tun_enabled: Some(true),
        rule: None,
        chain: vec![],
        evidence: vec![Evidence {
            level,
            source: "mihomo_connection".into(),
            summary: "matched".into(),
        }],
    }
}

fn successful_http() -> HttpObservation {
    HttpObservation {
        status: Some(200),
        final_url: "https://example.com/".into(),
        elapsed_ms: 12,
        error_code: None,
        peer_endpoint: None,
    }
}

fn failed_http() -> HttpObservation {
    HttpObservation {
        status: None,
        final_url: "https://example.com/".into(),
        elapsed_ms: 12,
        error_code: Some("connect".into()),
        peer_endpoint: None,
    }
}

#[test]
fn local_proxy_result_is_not_called_direct() {
    let proxy = system_proxy(ProxyKind::Https, Some("127.0.0.1"), Some(2023));

    let result = build_conclusion(&proxy, &unknown_traffic(), None, &successful_http());

    assert_eq!(result.title, "不是直连");
    assert!(result.summary.contains("本机代理 127.0.0.1:2023"));
    assert_eq!(result.level, EvidenceLevel::Confirmed);
}

#[test]
fn direct_conclusion_names_the_system_configuration_scope() {
    let proxy = system_proxy(ProxyKind::Direct, None, None);

    assert_eq!(
        build_conclusion(&proxy, &unknown_traffic(), None, &successful_http()).title,
        "系统代理配置：直连"
    );
}

#[test]
fn malformed_proxy_endpoint_is_unknown_instead_of_fabricated() {
    let proxy = system_proxy(ProxyKind::Https, None, None);

    let result = build_conclusion(&proxy, &unknown_traffic(), None, &failed_http());

    assert_eq!(result.level, EvidenceLevel::Unknown);
    assert_eq!(result.title, "代理路径未知");
    assert!(!result.summary.contains("未知主机:0"));
}

#[test]
fn reject_conclusion_stops_at_clash() {
    let proxy = system_proxy(ProxyKind::Direct, None, None);

    let conclusion = build_conclusion(
        &proxy,
        &traffic(TrafficDecisionKind::Reject, EvidenceLevel::Confirmed),
        None,
        &failed_http(),
    );

    assert_eq!(conclusion.title, "已被 Clash 阻止");
    assert_eq!(conclusion.level, EvidenceLevel::Confirmed);
}

#[test]
fn confirmed_proxy_decision_is_distinct_from_system_proxy_configuration() {
    let proxy = system_proxy(ProxyKind::Direct, None, None);

    let conclusion = build_conclusion(
        &proxy,
        &traffic(TrafficDecisionKind::Proxy, EvidenceLevel::Confirmed),
        None,
        &successful_http(),
    );

    assert_eq!(conclusion.title, "Clash 最终决策：代理");
    assert!(conclusion.summary.contains("Mihomo"));
    assert!(!conclusion.summary.contains("系统代理配置选择直连"));
}

#[test]
fn confirmed_direct_decision_is_never_described_as_domestic() {
    let proxy = system_proxy(ProxyKind::Https, Some("127.0.0.1"), Some(7890));

    let conclusion = build_conclusion(
        &proxy,
        &traffic(TrafficDecisionKind::Direct, EvidenceLevel::Confirmed),
        None,
        &successful_http(),
    );

    assert_eq!(conclusion.title, "Clash 最终决策：直连");
    assert!(!conclusion.title.contains("国内"));
    assert!(!conclusion.summary.contains("国内"));
    assert!(conclusion.summary.contains("不表示目标地域"));
}

#[test]
fn unconfirmed_mihomo_decision_falls_back_to_system_proxy_wording() {
    let proxy = system_proxy(ProxyKind::Direct, None, None);

    let conclusion = build_conclusion(
        &proxy,
        &traffic(TrafficDecisionKind::Direct, EvidenceLevel::Inferred),
        None,
        &successful_http(),
    );

    assert_eq!(conclusion.title, "系统代理配置：直连");
}
