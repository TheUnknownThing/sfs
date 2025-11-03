use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use time::{Duration as TimeDuration, OffsetDateTime};
use tower_sessions::Session;
use tracing::{debug, error, info, warn};
use ulid::Ulid;

use crate::{
    app_state::AppState,
    csrf, files,
    rate_limit::RateLimitError,
    server::constants::DEFAULT_PREVIEW_MAX_SIZE_BYTES,
    templates::{DirectLinkErrorTemplate, DirectLinkSnippetTemplate, FileTemplate, HtmlTemplate},
};

use crate::server::utils::{
    attach_retry_after, file_expired_response, file_not_found_response, format_datetime_utc,
    human_readable_size, normalize_lookup_code, server_error_response,
};

use super::shared::{current_app_settings, layout_from_session};

/// GET /f/:code — present a file page with metadata and action controls.
pub async fn file_lookup_handler(
    State(state): State<AppState>,
    session: Session,
    AxumPath(raw_code): AxumPath<String>,
) -> Response {
    let Some(code) = normalize_lookup_code(&raw_code) else {
        return file_not_found_response();
    };

    let record = match fetch_active_file_by_code(&state, &code).await {
        Ok(record) => record,
        Err(response) => return response,
    };

    let owner_user_id = record.owner_user_id;
    let files::FileLookup {
        original_name,
        size_bytes,
        content_type,
        checksum,
        created_at,
        expires_at,
        ..
    } = record;

    if size_bytes < 0 {
        error!(
            target = "files",
            code = %code,
            size = size_bytes,
            "stored file size is invalid"
        );
        return server_error_response();
    }

    let created_display = match OffsetDateTime::from_unix_timestamp(created_at) {
        Ok(dt) => format_datetime_utc(dt),
        Err(err) => {
            error!(
                target = "files",
                %err,
                code = %code,
                created_at,
                "invalid created_at stored for file"
            );
            return server_error_response();
        }
    };

    let expires_display = match expires_at {
        Some(ts) => match OffsetDateTime::from_unix_timestamp(ts) {
            Ok(dt) => Some(format_datetime_utc(dt)),
            Err(err) => {
                error!(
                    target = "files",
                    %err,
                    code = %code,
                    expires_at = ts,
                    "invalid expires_at stored for file"
                );
                return server_error_response();
            }
        },
        None => None,
    };

    let size_display = human_readable_size(size_bytes as u64);
    let preview_limit = DEFAULT_PREVIEW_MAX_SIZE_BYTES;
    let preview_blocked_by_size = (size_bytes as u64) > preview_limit;
    let can_preview =
        !preview_blocked_by_size && files::is_text_mime_type(&content_type, &original_name);
    let preview_limit_display = human_readable_size(preview_limit);
    let layout = layout_from_session(&state, &session, "File details").await;
    let can_delete = match layout.current_user.as_ref() {
        Some(user) if user.is_admin => true,
        Some(user) => owner_user_id.map_or(false, |owner| owner == user.id),
        None => false,
    };

    let template = FileTemplate::new(
        layout,
        code,
        original_name,
        size_display,
        created_display,
        expires_display,
    )
    .with_content_type(content_type)
    .with_checksum(checksum)
    .with_delete_permission(can_delete)
    .with_preview_settings(
        can_preview,
        preview_limit_display,
        preview_limit,
        preview_blocked_by_size,
    )
    .with_preview_content("Loading preview...");

    HtmlTemplate::new(template).into_response()
}

/// POST /f/:code/link — issue a temporary direct download link.
pub async fn file_direct_link_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: Session,
    AxumPath(raw_code): AxumPath<String>,
    Form(form): Form<GenerateLinkForm>,
) -> Response {
    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token for direct link");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", "invalid CSRF token on direct link request");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after invalid direct link request");
        }
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }

    let Some(code) = normalize_lookup_code(&raw_code) else {
        return file_not_found_response();
    };

    let record = match fetch_active_file_by_code(&state, &code).await {
        Ok(record) => record,
        Err(response) => {
            let status = response.status();
            return match status {
                StatusCode::NOT_FOUND => direct_link_error_response(
                    StatusCode::NOT_FOUND,
                    "We couldn't find that file anymore.",
                ),
                StatusCode::GONE => {
                    direct_link_error_response(StatusCode::GONE, "This file has already expired.")
                }
                _ => response,
            };
        }
    };

    let client_ip = addr.ip();

    if let Err(err) = state.direct_link_rate_limiter().check_ip(client_ip) {
        warn!(
            target: "links",
            ip = %client_ip,
            code = %code,
            file_id = %record.id,
            %err,
            "rate limited direct link generation"
        );
        return rate_limited_direct_link_response(&err);
    }

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    let ttl_minutes = settings.direct_link_ttl_minutes;
    if ttl_minutes == 0 {
        error!(target: "links", code = %code, "direct link TTL is misconfigured to zero");
        return server_error_response();
    }

    let ttl_minutes_i64 = match i64::try_from(ttl_minutes) {
        Ok(value) => value,
        Err(_) => {
            error!(
                target: "links",
                ttl = ttl_minutes,
                "direct link TTL exceeds supported range"
            );
            return server_error_response();
        }
    };

    let now = OffsetDateTime::now_utc();
    let ttl_duration = TimeDuration::minutes(ttl_minutes_i64);
    let mut expires_at = match now.checked_add(ttl_duration) {
        Some(ts) => ts,
        None => {
            error!(target: "links", code = %code, "failed to compute link expiration");
            return server_error_response();
        }
    };

    if let Some(file_expires_at) = record.expires_at {
        match OffsetDateTime::from_unix_timestamp(file_expires_at) {
            Ok(file_expiry) => {
                if file_expiry <= now {
                    return direct_link_error_response(
                        StatusCode::GONE,
                        "This file has already expired.",
                    );
                }

                if file_expiry < expires_at {
                    expires_at = file_expiry;
                }
            }
            Err(err) => {
                error!(
                    target: "links",
                    %err,
                    code = %code,
                    expires_at = file_expires_at,
                    "invalid expires_at stored for file during link generation"
                );
                return server_error_response();
            }
        }
    }

    let token = match state.download_tokens().issue(&record.id, expires_at) {
        Ok(token) => token,
        Err(err) => {
            error!(
                target: "links",
                %err,
                code = %code,
                file_id = %record.id,
                "failed to sign direct download token"
            );
            return server_error_response();
        }
    };

    let effective_seconds = (expires_at - now).whole_seconds();
    let effective_minutes = ((effective_seconds + 59) / 60).max(1);
    let ttl_display = match u64::try_from(effective_minutes) {
        Ok(value) => value,
        Err(_) => ttl_minutes,
    };

    let direct_url = format!("/d/{token}");
    let expires_display = format_datetime_utc(expires_at);
    let input_id = format!("direct-link-url-{}", Ulid::new());

    info!(
        target: "links",
        ip = %client_ip,
        code = %code,
        file_id = %record.id,
        expires_at = expires_at.unix_timestamp(),
        ttl_minutes = ttl_display,
        "issued temporary direct download link"
    );

    let template = DirectLinkSnippetTemplate::new(direct_url, expires_display, ttl_display)
        .with_input_id(input_id);

    HtmlTemplate::new(template).into_response()
}

/// POST /f/:code/delete — remove a file record and associated blob.
pub async fn file_delete_handler(
    State(state): State<AppState>,
    session: Session,
    AxumPath(raw_code): AxumPath<String>,
    Form(form): Form<DeleteFileForm>,
) -> Response {
    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token for file deletion");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", "invalid CSRF token on file delete request");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after delete validation failure");
        }
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }

    let session_user = match crate::sessions::current_user(&session).await {
        Ok(Some(user)) => user,
        Ok(None) => return axum::response::Redirect::to("/login").into_response(),
        Err(err) => {
            error!(target: "sessions", %err, "failed to read session during file delete");
            return server_error_response();
        }
    };

    let Some(code) = normalize_lookup_code(&raw_code) else {
        return file_not_found_response();
    };

    let record = match files::find_file_by_code(state.db(), &code).await {
        Ok(Some(record)) => record,
        Ok(None) => return file_not_found_response(),
        Err(err) => {
            error!(target: "files", %err, code = %code, "failed to load file for deletion");
            return server_error_response();
        }
    };

    let allowed = if session_user.is_admin {
        true
    } else {
        record
            .owner_user_id
            .map_or(false, |owner| owner == session_user.id)
    };

    if !allowed {
        warn!(
            target: "files",
            user_id = session_user.id,
            username = %session_user.username,
            code = %code,
            "user attempted to delete file they do not own"
        );
        return (
            StatusCode::FORBIDDEN,
            "You are not allowed to delete this file.",
        )
            .into_response();
    }

    let stored_path = record.stored_path.clone();
    let file_id = record.id.clone();
    let mut conn = match state.db().acquire().await {
        Ok(conn) => conn,
        Err(err) => {
            error!(target: "files", %err, code = %code, "failed to acquire connection for delete");
            return server_error_response();
        }
    };

    if let Err(err) = sqlx::query("BEGIN IMMEDIATE").execute(conn.as_mut()).await {
        error!(target: "files", %err, code = %code, "failed to begin delete transaction");
        return server_error_response();
    }

    let rows_deleted = match sqlx::query("DELETE FROM files WHERE id = ?")
        .bind(&file_id)
        .execute(conn.as_mut())
        .await
    {
        Ok(result) => result.rows_affected(),
        Err(err) => {
            error!(
                target: "files",
                %err,
                code = %code,
                file_id = %file_id,
                "failed to delete file record"
            );
            if let Err(rollback_err) = sqlx::query("ROLLBACK").execute(conn.as_mut()).await {
                error!(target: "files", %rollback_err, "failed to rollback file delete transaction");
            }
            return server_error_response();
        }
    };

    if rows_deleted == 0 {
        if let Err(rollback_err) = sqlx::query("ROLLBACK").execute(conn.as_mut()).await {
            error!(target: "files", %rollback_err, "failed to rollback file delete after missing record");
        }
        return file_not_found_response();
    }

    if let Err(err) = sqlx::query("COMMIT").execute(conn.as_mut()).await {
        error!(
            target: "files",
            %err,
            code = %code,
            file_id = %file_id,
            "failed to commit file delete transaction"
        );
        if let Err(rollback_err) = sqlx::query("ROLLBACK").execute(conn.as_mut()).await {
            error!(target: "files", %rollback_err, "failed to rollback after commit error");
        }
        return server_error_response();
    }

    let storage_path = state.config().storage.root.join(&stored_path);
    let mut missing_on_disk = false;
    match tokio::fs::remove_file(&storage_path).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            missing_on_disk = true;
            debug!(
                target: "files",
                code = %code,
                file_id = %file_id,
                path = %storage_path.display(),
                "file already missing on disk during delete"
            );
        }
        Err(err) => {
            warn!(
                target: "files",
                %err,
                code = %code,
                file_id = %file_id,
                path = %storage_path.display(),
                "file blob removal failed after manual delete"
            );
        }
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after file delete");
    }

    info!(
        target: "files",
        user_id = session_user.id,
        username = %session_user.username,
        code = %code,
        file_id = %file_id,
        missing_on_disk,
        "file removed by user"
    );

    axum::response::Redirect::to("/?flash=deleted").into_response()
}

async fn fetch_active_file_by_code(
    state: &AppState,
    code: &str,
) -> Result<files::FileLookup, Response> {
    let lookup_result = match files::find_file_by_code(state.db(), code).await {
        Ok(record) => record,
        Err(err) => {
            error!(
                target: "files",
                %err,
                code = %code,
                "database error while looking up file by code"
            );
            return Err(server_error_response());
        }
    };

    let Some(record) = lookup_result else {
        return Err(file_not_found_response());
    };

    if let Some(expires_at) = record.expires_at {
        if expires_at <= OffsetDateTime::now_utc().unix_timestamp() {
            debug!(
                target: "files",
                code = %code,
                expires_at,
                "file lookup attempted after expiration"
            );
            return Err(file_expired_response());
        }
    }

    Ok(record)
}

fn direct_link_error_response(status: StatusCode, message: &str) -> Response {
    let template = DirectLinkErrorTemplate::new(message);
    HtmlTemplate::with_status(template, status).into_response()
}

fn rate_limited_direct_link_response(error: &RateLimitError) -> Response {
    let mut response = direct_link_error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "You are requesting links too quickly. Please wait and try again.",
    );

    attach_retry_after(&mut response, error.retry_after().as_secs());
    response
}

#[derive(Debug, Deserialize)]
pub(crate) struct GenerateLinkForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteFileForm {
    csrf_token: String,
}
