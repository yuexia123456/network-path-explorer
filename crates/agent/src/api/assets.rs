use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/dist/"]
struct WebAssets;

pub async fn serve(request: Request) -> Response {
    let path = request.uri().path();
    if path.starts_with("/assets/") {
        return embedded_response(path.trim_start_matches('/')).unwrap_or_else(not_found);
    }

    embedded_response("index.html").expect("the bundled Vite application must contain index.html")
}

fn embedded_response(path: &str) -> Option<Response> {
    safe_embedded_path(path)?;
    let asset = WebAssets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut response = Response::new(Body::from(asset.data.into_owned()));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        mime.as_ref().parse().expect("valid MIME type"),
    );
    Some(response)
}

fn safe_embedded_path(path: &str) -> Option<()> {
    (!path.is_empty()
        && !path.contains(['\\', '%'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."))
    .then_some(())
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}
