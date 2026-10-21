use super::{ApiError, AppState};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub(crate) async fn require_local_session(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let host = state.expected_host();
    let origin = state.expected_origin();
    let has_valid_origin = has_single_exact_header(headers, header::ORIGIN, &origin);
    let fetch_site = HeaderName::from_static("sec-fetch-site");
    let is_same_origin_browser_read = matches!(request.method(), &Method::GET | &Method::HEAD)
        && !headers.contains_key(header::ORIGIN)
        && (!headers.contains_key(&fetch_site)
            || has_single_exact_header(headers, fetch_site, "same-origin"));
    if !has_single_exact_header(headers, header::HOST, &host)
        || !(has_valid_origin || is_same_origin_browser_read)
    {
        return ApiError::forbidden().into_response();
    }
    let is_token_exempt_capabilities = request.method() == Method::GET
        && request.uri().path() == "/v1/capabilities"
        && has_valid_origin;
    if !is_token_exempt_capabilities
        && !has_single_exact_header(
            headers,
            HeaderName::from_static("x-npe-session"),
            state.session_token(),
        )
    {
        return ApiError::unauthorized().into_response();
    }
    next.run(request).await
}

fn has_single_exact_header(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None) if value.as_bytes() == expected.as_bytes()
    )
}
