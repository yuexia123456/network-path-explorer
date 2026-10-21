use crate::{error::DiagnosticError, ports::Resolver};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use tokio::net::lookup_host;

#[derive(Debug, Default)]
pub struct TokioResolver;

#[async_trait]
impl Resolver for TokioResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, DiagnosticError> {
        collect_lookup_result(lookup_host((host, port)).await)
    }
}

fn collect_lookup_result<I>(lookup: std::io::Result<I>) -> Result<Vec<IpAddr>, DiagnosticError>
where
    I: IntoIterator<Item = SocketAddr>,
{
    let mut ips = Vec::new();
    for address in lookup.map_err(|_| DiagnosticError::DnsFailed)? {
        if !ips.contains(&address.ip()) {
            ips.push(address.ip());
        }
    }

    if ips.is_empty() {
        return Err(DiagnosticError::DnsFailed);
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::collect_lookup_result;
    use crate::error::DiagnosticError;
    use std::{
        io,
        net::{IpAddr, SocketAddr},
    };

    #[test]
    fn preserves_first_seen_ip_order_when_lookup_returns_duplicates() {
        let addresses = [
            "192.0.2.1:443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
            "192.0.2.1:8443".parse::<SocketAddr>().unwrap(),
        ];

        let ips = collect_lookup_result(Ok(addresses)).unwrap();

        assert_eq!(
            ips,
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn returns_dns_failed_for_an_empty_lookup() {
        let result = collect_lookup_result(Ok(Vec::<SocketAddr>::new()));

        assert!(matches!(result, Err(DiagnosticError::DnsFailed)));
    }

    #[test]
    fn returns_dns_failed_when_lookup_fails() {
        let result =
            collect_lookup_result::<Vec<SocketAddr>>(Err(io::Error::other("lookup failed")));

        assert!(matches!(result, Err(DiagnosticError::DnsFailed)));
    }
}
