use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::{ConnectInfo, Path as AxumPath, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use tokio::fs;
use tokio_util::io::ReaderStream;
use tracing::{error, info, warn};

use crate::{app_state::AppState, files, rate_limit::RateLimitError};

use crate::direct_links::TokenError as DownloadTokenError;
use crate::server::utils::{
    attach_retry_after, build_content_disposition_header, download_unauthorized_response,
    file_expired_response, sanitize_filename, server_error_response,
};

pub async fn download_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(token): AxumPath<String>,
) -> Response {
    let client_ip = addr.ip();

    if let Err(err) = state.direct_download_rate_limiter().check_ip(client_ip) {
        warn!(
            target: "links",
            ip = %client_ip,
            %err,
            "rate limited direct download request"
        );
        return rate_limited_download_response(&err);
    }

    let now = time::OffsetDateTime::now_utc();

    let claims = match state.download_tokens().parse(&token, now) {
        Ok(claims) => claims,
        Err(err) => {
            return match err {
                DownloadTokenError::Expired
                | DownloadTokenError::InvalidFormat
                | DownloadTokenError::InvalidData
                | DownloadTokenError::InvalidSignature => {
                    warn!(
                        target: "links",
                        ip = %client_ip,
                        %err,
                        "invalid direct download token"
                    );
                    download_unauthorized_response()
                }
                DownloadTokenError::SecretTooShort | DownloadTokenError::SecretDecode(_) => {
                    error!(
                        target: "links",
                        %err,
                        "download token validation failed due to secret configuration"
                    );
                    server_error_response()
                }
            };
        }
    };

    let record = match files::find_file_by_id(state.db(), &claims.file_id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            warn!(
                target: "links",
                ip = %client_ip,
                file_id = %claims.file_id,
                "download requested for missing file"
            );
            return file_expired_response();
        }
        Err(err) => {
            error!(
                target: "files",
                %err,
                file_id = %claims.file_id,
                "database error while loading file for download"
            );
            return server_error_response();
        }
    };

    if let Some(expires_at) = record.expires_at {
        if expires_at <= now.unix_timestamp() {
            return file_expired_response();
        }
    }

    if record.size_bytes < 0 {
        error!(
            target: "links",
            file_id = %record.id,
            size = record.size_bytes,
            "stored file size invalid during download"
        );
        return server_error_response();
    }

    let storage_path = state.config().storage.root.join(&record.stored_path);
    let file = match fs::File::open(&storage_path).await {
        Ok(file) => file,
        Err(err) => {
            error!(
                target: "links",
                %err,
                path = %storage_path.display(),
                file_id = %record.id,
                "failed to open file for direct download"
            );
            return file_expired_response();
        }
    };

    let guessed_type = record
        .content_type
        .as_deref()
        .and_then(|value| HeaderValue::from_str(value).ok())
        .unwrap_or_else(|| {
            let guess = mime_guess::from_path(&record.original_name).first_or_octet_stream();
            HeaderValue::from_str(guess.essence_str())
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
        });

    let download_name = sanitize_filename(Some(&record.original_name));
    let content_disposition = build_content_disposition_header(&download_name);

    let mut response = Response::new(Body::from_stream(ReaderStream::new(file)));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, guessed_type);
    headers.insert(header::CONTENT_DISPOSITION, content_disposition);
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    let size_bytes = record.size_bytes as u64;
    if let Ok(value) = HeaderValue::from_str(&size_bytes.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }

    info!(
        target: "links",
        ip = %client_ip,
        file_id = %record.id,
        code = %record.code,
        token_expires_at = claims.expires_at.unix_timestamp(),
        "serving direct download"
    );

    if let Err(err) =
        files::update_last_accessed(state.db(), &record.id, now.unix_timestamp()).await
    {
        warn!(
            target: "files",
            %err,
            file_id = %record.id,
            "failed to update last accessed timestamp after download"
        );
    }

    response
}

fn rate_limited_download_response(error: &RateLimitError) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        "Too many downloads from this IP address. Please wait and try again.",
    )
        .into_response();

    attach_retry_after(&mut response, error.retry_after().as_secs());
    response
}
