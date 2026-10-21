use crate::{domain::RouteInfo, error::DiagnosticError, ports::RouteInspector};
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::process::Command;

pub fn parse_route_get(output: &str, destination: IpAddr) -> Result<RouteInfo, DiagnosticError> {
    let gateway = value_for(output, "gateway:").and_then(parse_gateway);
    let interface = value_for(output, "interface:")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DiagnosticError::System("route returned no interface".into()))?
        .to_owned();

    Ok(RouteInfo {
        destination,
        gateway,
        interface,
    })
}

fn parse_gateway(value: &str) -> Option<IpAddr> {
    if let Ok(address) = value.parse() {
        return Some(address);
    }
    let (address, scope) = value.split_once('%')?;
    if scope.is_empty()
        || !scope
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    match address.parse().ok()? {
        IpAddr::V6(address) => Some(IpAddr::V6(address)),
        IpAddr::V4(_) => None,
    }
}

#[derive(Debug, Default)]
pub struct MacRouteInspector;

#[async_trait]
impl RouteInspector for MacRouteInspector {
    async fn route_to(&self, destination: IpAddr) -> Result<RouteInfo, DiagnosticError> {
        let output = Command::new("/sbin/route")
            .args(route_get_arguments(destination))
            .output()
            .await
            .map_err(|error| DiagnosticError::System(error.to_string()))?;
        if !output.status.success() {
            return Err(DiagnosticError::System(format!(
                "{} exited with {}",
                route_get_description(destination),
                output.status
            )));
        }
        let output = String::from_utf8(output.stdout)
            .map_err(|error| DiagnosticError::System(error.to_string()))?;
        parse_route_get(&output, destination)
    }
}

fn route_get_arguments(destination: IpAddr) -> Vec<String> {
    let mut arguments = vec!["-n".to_owned(), "get".to_owned()];
    if destination.is_ipv6() {
        arguments.push("-inet6".to_owned());
    }
    arguments.push(destination.to_string());
    arguments
}

fn route_get_description(destination: IpAddr) -> String {
    format!("route {}", route_get_arguments(destination).join(" "))
}

fn value_for<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(key).map(str::trim))
}

#[cfg(test)]
mod tests {
    use super::{route_get_arguments, route_get_description};
    use std::net::IpAddr;

    #[test]
    fn uses_inet6_only_for_ipv6_route_queries() {
        assert_eq!(
            route_get_arguments("93.184.216.34".parse().unwrap()),
            vec!["-n", "get", "93.184.216.34"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            route_get_arguments("2001:db8::1".parse().unwrap()),
            vec!["-n", "get", "-inet6", "2001:db8::1"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn describes_the_selected_ipv6_route_invocation() {
        let destination: IpAddr = "2001:db8::1".parse().unwrap();

        assert_eq!(
            route_get_description(destination),
            "route -n get -inet6 2001:db8::1"
        );
    }
}
