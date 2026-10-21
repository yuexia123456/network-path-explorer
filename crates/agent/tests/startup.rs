use network_path_agent::{
    api::bind_listener,
    startup::{launch_url, open_browser_with, session_token},
};
use std::{io, os::unix::process::ExitStatusExt};

#[test]
fn session_token_is_exactly_64_lowercase_hex_characters() {
    let token = session_token();

    assert_eq!(token.len(), 64);
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[tokio::test]
async fn launch_url_uses_the_actual_loopback_listener_port() {
    let listener = bind_listener().await.unwrap();
    let address = listener.local_addr().unwrap();
    let token = "a".repeat(64);

    assert_eq!(
        launch_url(address, &token),
        format!("http://127.0.0.1:{}/#token={token}", address.port())
    );
}

#[test]
fn failed_browser_launch_uses_open_with_one_url_argument_and_prints_the_fallback_once() {
    let launch_url = "http://127.0.0.1:43123/#token=abc";
    let mut fallback = Vec::new();

    open_browser_with(
        launch_url,
        |command| {
            assert_eq!(command.get_program(), "/usr/bin/open");
            assert_eq!(command.get_args().collect::<Vec<_>>(), vec![launch_url]);
            Err(io::Error::other("open unavailable"))
        },
        &mut fallback,
    );

    assert_eq!(
        String::from_utf8(fallback).unwrap(),
        format!("Open this URL manually: {launch_url}\n")
    );
}

#[test]
fn successful_browser_launch_does_not_print_a_fallback() {
    let mut fallback = Vec::new();

    open_browser_with(
        "http://127.0.0.1:43123/#token=abc",
        |_| Ok(std::process::ExitStatus::from_raw(0)),
        &mut fallback,
    );

    assert!(fallback.is_empty());
}
