use network_path_agent::api::bind_listener;

#[tokio::test]
async fn listener_binds_to_a_random_loopback_address() {
    let listener = bind_listener().await.unwrap();
    let address = listener.local_addr().unwrap();

    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
}
