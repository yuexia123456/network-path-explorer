use crate::domain::{
    Conclusion, EvidenceLevel, HttpObservation, ProxyDecision, ProxyKind, RouteInfo,
    TrafficDecision, TrafficDecisionKind,
};
use std::net::IpAddr;

pub fn build_conclusion(
    proxy: &ProxyDecision,
    traffic_decision: &TrafficDecision,
    route: Option<&RouteInfo>,
    http: &HttpObservation,
) -> Conclusion {
    let route_summary = match route {
        Some(route) => format!(
            "本机路由查询显示先经接口 {} 到达 {}。",
            route.interface, route.destination
        ),
        None => "未能确认本机路由。".into(),
    };
    let http_summary = match (http.status, http.error_code.as_deref()) {
        (Some(status), _) => format!(
            "连接测试观察到 HTTP 状态 {status}，耗时 {}ms。",
            http.elapsed_ms
        ),
        (None, Some(error)) => format!("连接测试观察到 {error} 错误，耗时 {}ms。", http.elapsed_ms),
        (None, None) => format!("连接测试未返回 HTTP 状态，耗时 {}ms。", http.elapsed_ms),
    };

    if traffic_decision
        .evidence
        .iter()
        .any(|evidence| evidence.level == EvidenceLevel::Confirmed)
    {
        match traffic_decision.kind {
            TrafficDecisionKind::Reject => {
                return Conclusion {
                    title: "已被 Clash 阻止".into(),
                    summary: "Mihomo 的关联事件确认此次请求被 Clash 阻止。".into(),
                    level: EvidenceLevel::Confirmed,
                };
            }
            TrafficDecisionKind::Proxy => {
                return Conclusion {
                    title: "Clash 最终决策：代理".into(),
                    summary: format!(
                        "Mihomo 的关联连接确认此次请求使用代理；该结论独立于系统代理配置。{route_summary}{http_summary}"
                    ),
                    level: EvidenceLevel::Confirmed,
                };
            }
            TrafficDecisionKind::Direct => {
                return Conclusion {
                    title: "Clash 最终决策：直连".into(),
                    summary: format!(
                        "Mihomo 的关联连接确认此次请求未使用远程代理；DIRECT 只描述此次 Mihomo 决策，不表示目标地域。{route_summary}{http_summary}"
                    ),
                    level: EvidenceLevel::Confirmed,
                };
            }
            TrafficDecisionKind::Unknown => {}
        }
    }

    match proxy.kind {
        ProxyKind::Direct => Conclusion {
            title: "系统代理配置：直连".into(),
            summary: format!(
                "系统代理配置选择直连；这不确认网络中不存在透明代理。{route_summary}{http_summary}"
            ),
            level: proxy.evidence.level,
        },
        ProxyKind::Http | ProxyKind::Https | ProxyKind::Socks => {
            let Some(endpoint) = proxy_endpoint(proxy) else {
                return unknown_conclusion(route_summary, http_summary);
            };
            let description = if endpoint
                .host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
            {
                format!("本机代理 {}:{}", endpoint.host, endpoint.port)
            } else {
                format!("代理 {}:{}", endpoint.host, endpoint.port)
            };
            Conclusion {
                title: "不是直连".into(),
                summary: format!(
                    "系统代理配置选择{description}；这只确认本机到代理端点的配置，不确认代理后的隐藏网络路径。{route_summary}{http_summary}"
                ),
                level: proxy.evidence.level,
            }
        }
        ProxyKind::Unknown => unknown_conclusion(route_summary, http_summary),
    }
}

struct ProxyEndpoint<'a> {
    host: &'a str,
    port: u16,
}

fn proxy_endpoint(proxy: &ProxyDecision) -> Option<ProxyEndpoint<'_>> {
    Some(ProxyEndpoint {
        host: proxy.host.as_deref().filter(|host| !host.is_empty())?,
        port: proxy.port.filter(|port| *port != 0)?,
    })
}

fn unknown_conclusion(route_summary: String, http_summary: String) -> Conclusion {
    Conclusion {
        title: "代理路径未知".into(),
        summary: format!("系统代理配置无法确定代理路径。{route_summary}{http_summary}"),
        level: EvidenceLevel::Unknown,
    }
}
