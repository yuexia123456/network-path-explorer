use crate::domain::{
    EvidenceLevel, TraceTarget, TraceTargetKind, TrafficDecisionKind, UrlDiagnosticResult,
};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceRequestKind {
    Actual,
    Reference,
}

pub fn select_trace_target(
    result: &UrlDiagnosticResult,
    request_kind: TraceRequestKind,
) -> Option<TraceTarget> {
    match request_kind {
        TraceRequestKind::Reference => result.resolved_ips.first().copied().map(|ip| TraceTarget {
            kind: TraceTargetKind::ReferenceDestination,
            ip,
        }),
        TraceRequestKind::Actual => match result.traffic_decision.kind {
            TrafficDecisionKind::Direct => confirmed_direct_target(result),
            TrafficDecisionKind::Proxy => confirmed_proxy_target(result),
            TrafficDecisionKind::Reject | TrafficDecisionKind::Unknown => None,
        },
    }
}

fn confirmed_direct_target(result: &UrlDiagnosticResult) -> Option<TraceTarget> {
    if !has_confirmed_evidence(&result.traffic_decision.evidence) {
        return None;
    }
    let endpoint = result.http.peer_endpoint.as_ref()?;
    (!is_loopback(endpoint.ip)).then_some(TraceTarget {
        kind: TraceTargetKind::ActualDestination,
        ip: endpoint.ip,
    })
}

fn confirmed_proxy_target(result: &UrlDiagnosticResult) -> Option<TraceTarget> {
    if !has_confirmed_evidence(&result.traffic_decision.evidence) {
        return None;
    }
    result
        .traffic_decision
        .chain
        .iter()
        .filter(|node| node.level == EvidenceLevel::Confirmed)
        .filter_map(|node| node.endpoint.as_ref())
        .find(|endpoint| !is_loopback(endpoint.ip))
        .map(|endpoint| TraceTarget {
            kind: TraceTargetKind::ActualProxy,
            ip: endpoint.ip,
        })
}

fn has_confirmed_evidence(evidence: &[crate::domain::Evidence]) -> bool {
    evidence
        .iter()
        .any(|item| item.level == EvidenceLevel::Confirmed)
}

fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
        || matches!(ip, IpAddr::V6(address) if address.to_ipv4().is_some_and(|mapped| mapped.is_loopback()))
}
