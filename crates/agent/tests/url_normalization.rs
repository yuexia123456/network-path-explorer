use network_path_agent::diagnostics::url::normalize_http_url;

#[test]
fn adds_https_when_scheme_is_missing() {
    assert_eq!(
        normalize_http_url("example.com").unwrap().as_str(),
        "https://example.com/"
    );
}

#[test]
fn rejects_non_http_schemes_and_embedded_credentials() {
    assert!(normalize_http_url("file:///etc/passwd").is_err());
    assert!(normalize_http_url("https://user:secret@example.com").is_err());
}

#[test]
fn rejects_blank_and_oversized_input() {
    assert!(normalize_http_url("  ").is_err());
    assert!(normalize_http_url(&"a".repeat(2049)).is_err());
}
