use axum::{
    extract::Path,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use include_dir::{include_dir, Dir};

static STATIC_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

/// Serve assets embedded into the compiled binary.
pub async fn static_asset_handler(Path(path): Path<String>) -> Response {
    if is_invalid_asset_path(&path) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(file) = STATIC_ASSETS.get_file(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let content_type = mime_guess::from_path(&path)
        .first_or_octet_stream()
        .to_string();

    let mut response = file.contents().to_vec().into_response();
    let headers = response.headers_mut();

    if let Ok(value) = HeaderValue::from_str(&content_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }

    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    response
}

fn is_invalid_asset_path(path: &str) -> bool {
    path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

#[cfg(test)]
mod tests {
    use axum::extract::Path;
    use axum::http::{header, StatusCode};

    use super::is_invalid_asset_path;
    use super::static_asset_handler;

    #[test]
    fn validates_embedded_asset_paths() {
        assert!(!is_invalid_asset_path("css/app.css"));
        assert!(!is_invalid_asset_path(
            "fonts/manrope-latin-400-normal.woff2"
        ));

        assert!(is_invalid_asset_path(""));
        assert!(is_invalid_asset_path("/css/app.css"));
        assert!(is_invalid_asset_path("css/../app.css"));
        assert!(is_invalid_asset_path("css//app.css"));
    }

    #[tokio::test]
    async fn serves_embedded_css_asset() {
        let response = static_asset_handler(Path("css/app.css".to_owned())).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/css"
        );
    }
}
