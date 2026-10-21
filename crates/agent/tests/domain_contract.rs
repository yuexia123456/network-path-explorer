use network_path_agent::{
    domain::{
        Evidence, EvidenceLevel, HttpObservation, MihomoRuntime, PeerEndpoint, TrafficDecision,
        TrafficDecisionKind, TrafficNode, TrafficNodeKind, TrafficRule,
    },
    ports::{TrafficDecisionProvider, TrafficProbeScheme, TrafficProbeTarget},
    traffic::NoopTrafficDecisionProvider,
};

#[test]
fn evidence_serializes_with_stable_snake_case_level() {
    let evidence = Evidence {
        level: EvidenceLevel::Confirmed,
        source: "system_proxy".into(),
        summary: "已读取系统代理配置".into(),
    };
    let json = serde_json::to_value(evidence).unwrap();
    assert_eq!(json["level"], "confirmed");
    assert_eq!(json["source"], "system_proxy");
}

#[test]
fn http_peer_endpoint_has_a_stable_structured_json_contract() {
    let observation = HttpObservation {
        status: Some(204),
        final_url: "https://example.com/".into(),
        elapsed_ms: 7,
        error_code: None,
        peer_endpoint: Some(PeerEndpoint {
            ip: "203.0.113.10".parse().unwrap(),
            port: 443,
        }),
    };

    let json = serde_json::to_value(observation).unwrap();

    assert_eq!(json["peer_endpoint"]["ip"], "203.0.113.10");
    assert_eq!(json["peer_endpoint"]["port"], 443);
}

#[test]
fn missing_http_peer_endpoint_serializes_as_null() {
    let observation = HttpObservation {
        status: None,
        final_url: "https://example.com/".into(),
        elapsed_ms: 7,
        error_code: Some("connect".into()),
        peer_endpoint: None,
    };

    assert!(serde_json::to_value(observation).unwrap()["peer_endpoint"].is_null());
}

#[test]
fn traffic_decision_contract_preserves_chain_order() {
    let json = serde_json::to_value(proxy_decision_with_four_nodes()).unwrap();

    assert_eq!(json["kind"], "proxy");
    assert_eq!(json["chain"][0]["kind"], "tun");
    assert_eq!(json["chain"][1]["kind"], "traffic_rule");
    assert_eq!(json["chain"][2]["kind"], "policy_group");
    assert_eq!(json["chain"][3]["kind"], "proxy_node");
}

#[test]
fn traffic_decision_unknown_retains_its_unknown_evidence() {
    let decision = TrafficDecision::unknown("traffic_adapter", "provider is unavailable");

    assert_eq!(decision.kind, TrafficDecisionKind::Unknown);
    assert!(decision.chain.is_empty());
    assert_eq!(decision.evidence.len(), 1);
    assert_eq!(decision.evidence[0].level, EvidenceLevel::Unknown);
    assert_eq!(decision.evidence[0].source, "traffic_adapter");
    assert_eq!(decision.evidence[0].summary, "provider is unavailable");
}

#[test]
fn traffic_probe_target_defaults_to_tcp() {
    let target = TrafficProbeTarget::new(
        TrafficProbeScheme::Https,
        "example.com",
        443,
        vec!["203.0.113.10".parse().unwrap()],
        42,
    );

    assert_eq!(target.host, "example.com");
    assert_eq!(target.scheme, TrafficProbeScheme::Https);
    assert_eq!(target.port, 443);
    assert_eq!(target.protocol, "tcp");
    assert_eq!(target.process_id, 42);
    assert_eq!(
        target.resolved_ips,
        vec!["203.0.113.10".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn noop_traffic_provider_degrades_to_unknown() {
    let provider = NoopTrafficDecisionProvider;
    let target = TrafficProbeTarget::new(
        TrafficProbeScheme::Https,
        "example.com",
        443,
        vec![],
        std::process::id(),
    );

    let first_id = provider.begin(&target).await.unwrap();
    let second_id = provider.begin(&target).await.unwrap();
    let decision = provider.finish(first_id).await.unwrap();

    assert_ne!(first_id, second_id);
    assert_eq!(decision.kind, TrafficDecisionKind::Unknown);
    assert!(decision.chain.is_empty());
    assert_eq!(decision.evidence[0].level, EvidenceLevel::Unknown);
    assert_eq!(decision.evidence[0].source, "traffic_adapter");
}

#[tokio::test]
async fn noop_traffic_provider_runtime_exposes_unavailable_controller_label() {
    let runtime = NoopTrafficDecisionProvider.runtime().await;

    assert_eq!(runtime.controller.as_deref(), Some("unavailable"));
}

#[test]
fn mihomo_runtime_serialization_rejects_unsafe_controller_labels() {
    for controller in [
        "/var/run/mihomo.sock",
        "127.0.0.1:9090",
        "secret=controller-token",
    ] {
        assert!(
            serde_json::to_value(mihomo_runtime(Some(controller))).is_err(),
            "unsafe controller label leaked into JSON: {controller}"
        );
    }
}

#[test]
fn mihomo_runtime_deserialization_rejects_unsafe_controller_labels() {
    for controller in [
        "/var/run/mihomo.sock",
        "127.0.0.1:9090",
        "secret=controller-token",
    ] {
        let value = serde_json::json!({
            "available": true,
            "mode": "rule",
            "tun_enabled": true,
            "controller": controller,
        });

        assert!(
            serde_json::from_value::<MihomoRuntime>(value).is_err(),
            "unsafe controller label was accepted from JSON: {controller}"
        );
    }
}

#[test]
fn mihomo_runtime_missing_controller_deserializes_to_none() {
    let value = serde_json::json!({
        "available": false,
        "mode": null,
        "tun_enabled": null,
    });

    let runtime = serde_json::from_value::<MihomoRuntime>(value).unwrap();

    assert_eq!(runtime.controller, None);
}

fn proxy_decision_with_four_nodes() -> TrafficDecision {
    let evidence = Evidence {
        level: EvidenceLevel::Confirmed,
        source: "mihomo_api".into(),
        summary: "route reported by local controller".into(),
    };

    TrafficDecision {
        kind: TrafficDecisionKind::Proxy,
        mode: Some("rule".into()),
        tun_enabled: Some(true),
        rule: Some(TrafficRule {
            rule_type: "DOMAIN".into(),
            payload: Some("example.com".into()),
            target: "PROXY".into(),
            level: EvidenceLevel::Confirmed,
        }),
        chain: vec![
            TrafficNode {
                kind: TrafficNodeKind::Tun,
                name: "utun2".into(),
                node_type: None,
                endpoint: None,
                alive: Some(true),
                delay_ms: None,
                level: EvidenceLevel::Confirmed,
                evidence: vec![evidence.clone()],
            },
            TrafficNode {
                kind: TrafficNodeKind::TrafficRule,
                name: "DOMAIN,example.com,PROXY".into(),
                node_type: Some("DOMAIN".into()),
                endpoint: None,
                alive: None,
                delay_ms: None,
                level: EvidenceLevel::Confirmed,
                evidence: vec![evidence.clone()],
            },
            TrafficNode {
                kind: TrafficNodeKind::PolicyGroup,
                name: "PROXY".into(),
                node_type: Some("select".into()),
                endpoint: None,
                alive: Some(true),
                delay_ms: Some(12),
                level: EvidenceLevel::Confirmed,
                evidence: vec![evidence.clone()],
            },
            TrafficNode {
                kind: TrafficNodeKind::ProxyNode,
                name: "example-proxy".into(),
                node_type: Some("ss".into()),
                endpoint: Some(PeerEndpoint {
                    ip: "203.0.113.20".parse().unwrap(),
                    port: 443,
                }),
                alive: Some(true),
                delay_ms: Some(12),
                level: EvidenceLevel::Confirmed,
                evidence: vec![evidence.clone()],
            },
        ],
        evidence: vec![evidence],
    }
}

fn mihomo_runtime(controller: Option<&str>) -> MihomoRuntime {
    MihomoRuntime {
        available: true,
        mode: Some("rule".into()),
        tun_enabled: Some(true),
        controller: controller.map(str::to_owned),
    }
}
