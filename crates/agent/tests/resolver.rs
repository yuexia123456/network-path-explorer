use network_path_agent::{network::resolver::TokioResolver, ports::Resolver};

#[tokio::test]
async fn resolves_ipv4_literal_without_public_dns() {
    let ips = TokioResolver.resolve("127.0.0.1", 443).await.unwrap();
    assert_eq!(ips, vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]);
}
