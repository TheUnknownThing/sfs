use axum::extract::multipart::{Field, Multipart};
use axum::{
    extract::multipart::MultipartError,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::{fs, io::AsyncWriteExt};
use tower_sessions::Session;
use tracing::{debug, error, info, warn};
use ulid::Ulid;

use crate::{
    app_state::AppState,
    csrf, files,
    sessions::current_user,
    templates::{HtmlTemplate, UploadTemplate},
};

use crate::server::{
    constants::{MAX_CODE_GENERATION_ATTEMPTS, MAX_EXPIRATION_HOURS},
    utils::{
        generate_download_code, human_readable_size, sanitize_filename, server_error_response,
    },
};

use super::shared::{current_app_settings, layout_from_session};

/// GET /upload — display file upload form.
pub async fn upload_form_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: Session,
) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => render_upload_form(&state, &session, StatusCode::OK, None, None).await,
        Ok(None) => axum::response::Redirect::to("/login").into_response(),
        Err(err) => {
            error!(target: "sessions", %err, "failed to read session while rendering upload form");
            server_error_response()
        }
    }
}

/// POST /upload — handle multipart file uploads.
pub async fn upload_submit_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: Session,
    mut multipart: Multipart,
) -> Response {
    let session_user = match current_user(&session).await {
        Ok(Some(user)) => user,
        Ok(None) => return axum::response::Redirect::to("/login").into_response(),
        Err(err) => {
            error!(target: "sessions", %err, "failed to read session for upload");
            return server_error_response();
        }
    };

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    let storage_root = state.config().storage.root.clone();
    let max_file_size = settings.max_file_size_bytes;
    let default_expiration = settings.default_expiration_hours;

    let mut expires_in_input: Option<String> = None;
    let mut expires_in_hours: Option<u64> = None;
    let mut csrf_token: Option<String> = None;
    let mut uploaded_file: Option<PersistedUpload> = None;

    loop {
        let next_field = match multipart.next_field().await {
            Ok(field) => field,
            Err(err) => {
                warn!(target: "upload", %err, "malformed multipart payload");
                return render_upload_form(
                    &state,
                    &session,
                    StatusCode::BAD_REQUEST,
                    Some("The upload form could not be processed. Please try again.".to_string()),
                    expires_in_input,
                )
                .await;
            }
        };

        let Some(field) = next_field else {
            break;
        };

        let field_name = field.name().map(|name| name.to_string());
        match field_name.as_deref() {
            Some("file") => {
                if uploaded_file.is_some() {
                    return render_upload_form(
                        &state,
                        &session,
                        StatusCode::BAD_REQUEST,
                        Some("Only one file can be uploaded at a time.".to_string()),
                        expires_in_input,
                    )
                    .await;
                }

                match persist_streamed_file(field, &storage_root, max_file_size).await {
                    Ok(file) => {
                        uploaded_file = Some(file);
                    }
                    Err(UploadStreamError::TooLarge { limit }) => {
                        let limit_display = human_readable_size(limit);
                        return render_upload_form(
                            &state,
                            &session,
                            StatusCode::PAYLOAD_TOO_LARGE,
                            Some(format!("Files must be {limit_display} or smaller.")),
                            expires_in_input,
                        )
                        .await;
                    }
                    Err(UploadStreamError::EmptyUpload) => {
                        return render_upload_form(
                            &state,
                            &session,
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Some("Select a file before uploading.".to_string()),
                            expires_in_input,
                        )
                        .await;
                    }
                    Err(UploadStreamError::Multipart(err)) => {
                        warn!(target: "upload", %err, "failed to read upload chunks");
                        return render_upload_form(
                            &state,
                            &session,
                            StatusCode::BAD_REQUEST,
                            Some(
                                "The file upload could not be read. Please try again.".to_string(),
                            ),
                            expires_in_input,
                        )
                        .await;
                    }
                    Err(UploadStreamError::Io(err)) => {
                        error!(target: "upload", %err, "failed to persist uploaded file");
                        return server_error_response();
                    }
                }
            }
            Some("expires_in") => match field.text().await {
                Ok(value) => {
                    let trimmed = value.trim().to_string();
                    if !trimmed.is_empty() {
                        match trimmed.parse::<u64>() {
                            Ok(parsed) => {
                                expires_in_hours = Some(parsed);
                                expires_in_input = Some(trimmed);
                            }
                            Err(_) => {
                                expires_in_input = Some(trimmed);
                                return render_upload_form(
                                    &state,
                                    &session,
                                    StatusCode::UNPROCESSABLE_ENTITY,
                                    Some("Expiration must be provided as whole hours.".to_string()),
                                    expires_in_input,
                                )
                                .await;
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(target: "upload", %err, "failed to read expires_in field");
                    return render_upload_form(
                        &state,
                        &session,
                        StatusCode::BAD_REQUEST,
                        Some("Unable to read the expiration value.".to_string()),
                        expires_in_input,
                    )
                    .await;
                }
            },
            Some("csrf_token") => match field.text().await {
                Ok(token) => csrf_token = Some(token),
                Err(err) => {
                    warn!(target: "upload", %err, "failed to read csrf field");
                    return render_upload_form(
                        &state,
                        &session,
                        StatusCode::BAD_REQUEST,
                        Some("Unable to validate your session. Please try again.".to_string()),
                        expires_in_input,
                    )
                    .await;
                }
            },
            Some("notes") => {
                if let Err(err) = field.text().await {
                    debug!(target: "upload", %err, "discarding notes field due to read error");
                }
            }
            _ => {
                if let Err(err) = field.text().await {
                    debug!(
                        target: "upload",
                        field = field_name.as_deref().unwrap_or(""),
                        %err,
                        "discarding unexpected multipart field"
                    );
                }
            }
        }
    }

    let expires_in_for_form = expires_in_input.clone();

    let Some(csrf_value) = csrf_token else {
        return render_upload_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("Your upload session expired. Refresh and try again.".to_string()),
            expires_in_for_form,
        )
        .await;
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &csrf_value).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate upload csrf token");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", "upload csrf token mismatch");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate csrf token after mismatch");
        }
        return render_upload_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("Your session expired. Please try again.".to_string()),
            expires_in_for_form,
        )
        .await;
    }

    let Some(upload) = uploaded_file else {
        return render_upload_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("Select a file before uploading.".to_string()),
            expires_in_for_form,
        )
        .await;
    };

    let expiration_hours = match expires_in_hours {
        Some(hours) if hours == 0 || hours > MAX_EXPIRATION_HOURS => {
            return render_upload_form(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                Some(format!(
                    "Expiration must be between 1 and {} hours.",
                    MAX_EXPIRATION_HOURS
                )),
                expires_in_for_form,
            )
            .await;
        }
        Some(hours) => hours,
        None => default_expiration,
    };

    let created_at = upload.completed_at.unix_timestamp();
    let expires_at = upload
        .completed_at
        .checked_add(TimeDuration::hours(expiration_hours as i64))
        .map(|dt| dt.unix_timestamp());

    let size_bytes = match i64::try_from(upload.size_bytes) {
        Ok(value) => value,
        Err(_) => {
            error!(target: "upload", size = upload.size_bytes, "uploaded file size exceeds supported range");
            if let Err(err) = cleanup_orphaned_file(&upload.absolute_path).await {
                warn!(
                    target: "upload",
                    path = %upload.absolute_path.display(),
                    %err,
                    "failed to remove oversized file from disk"
                );
            }
            return server_error_response();
        }
    };

    let mut attempts = 0usize;
    let code = loop {
        let candidate = generate_download_code();
        let record = files::NewFileRecord {
            id: &upload.file_id,
            owner_user_id: Some(session_user.id),
            code: &candidate,
            original_name: &upload.original_name,
            stored_path: &upload.storage_key,
            size_bytes,
            content_type: upload.content_type.as_deref(),
            checksum: Some(upload.checksum_hex.as_str()),
            created_at,
            expires_at,
        };

        match files::insert_file_record(state.db(), &record).await {
            Ok(_) => break candidate,
            Err(err)
                if crate::server::utils::is_unique_violation(&err)
                    && attempts < MAX_CODE_GENERATION_ATTEMPTS =>
            {
                attempts += 1;
                debug!(target: "files", %err, attempt = attempts, "retrying file code generation");
                continue;
            }
            Err(err) => {
                error!(target: "files", %err, "failed to persist uploaded file record");
                if let Err(clean_err) = cleanup_orphaned_file(&upload.absolute_path).await {
                    warn!(
                        target: "upload",
                        path = %upload.absolute_path.display(),
                        %clean_err,
                        "failed to remove orphaned file after database error"
                    );
                }
                return server_error_response();
            }
        }
    };

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate csrf token after successful upload");
    }

    info!(
        target: "upload",
        user_id = session_user.id,
        username = session_user.username,
        file_id = upload.file_id,
        code = code,
        size_bytes = upload.size_bytes,
        "file uploaded successfully"
    );

    axum::response::Redirect::to(&format!("/f/{}", code)).into_response()
}

async fn render_upload_form(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    error_message: Option<String>,
    expires_in_value: Option<String>,
) -> Response {
    let settings = match current_app_settings(state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    let layout = layout_from_session(state, session, "Upload").await;

    let max_file_size_display = human_readable_size(settings.max_file_size_bytes);
    let expires_value =
        expires_in_value.unwrap_or_else(|| settings.default_expiration_hours.to_string());

    let mut template = UploadTemplate::new(
        layout,
        max_file_size_display,
        MAX_EXPIRATION_HOURS,
        expires_value,
    );

    if let Some(message) = error_message {
        template = template.with_error_message(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}

async fn persist_streamed_file(
    mut field: Field<'_>,
    storage_root: &std::path::Path,
    max_file_size: u64,
) -> Result<PersistedUpload, UploadStreamError> {
    let started_at = OffsetDateTime::now_utc();
    let original_name = sanitize_filename(field.file_name());
    let content_type = field.content_type().map(|mime| mime.to_string());
    let file_id = Ulid::new().to_string();

    let date_path = format!(
        "{:04}/{:02}/{:02}",
        started_at.year(),
        u8::from(started_at.month()),
        started_at.day()
    );

    let final_dir = storage_root.join(&date_path);
    fs::create_dir_all(&final_dir)
        .await
        .map_err(UploadStreamError::Io)?;

    let temp_path = final_dir.join(format!("{}.uploading", file_id));
    let final_path = final_dir.join(&file_id);

    let mut file = fs::File::create(&temp_path)
        .await
        .map_err(UploadStreamError::Io)?;
    let mut hasher = Sha256::new();
    let mut bytes_written: u64 = 0;
    let mut saw_data = false;

    while let Some(chunk) = field.chunk().await.map_err(UploadStreamError::Multipart)? {
        if chunk.is_empty() {
            continue;
        }

        saw_data = true;
        bytes_written = bytes_written.saturating_add(chunk.len() as u64);
        if bytes_written > max_file_size {
            drop(file);
            let _ = fs::remove_file(&temp_path).await;
            return Err(UploadStreamError::TooLarge {
                limit: max_file_size,
            });
        }

        if let Err(err) = file.write_all(&chunk).await {
            drop(file);
            let _ = fs::remove_file(&temp_path).await;
            return Err(UploadStreamError::Io(err));
        }

        hasher.update(&chunk);
    }

    if let Err(err) = file.flush().await {
        drop(file);
        let _ = fs::remove_file(&temp_path).await;
        return Err(UploadStreamError::Io(err));
    }
    drop(file);

    if !saw_data {
        let _ = fs::remove_file(&temp_path).await;
        return Err(UploadStreamError::EmptyUpload);
    }

    if let Err(err) = fs::rename(&temp_path, &final_path).await {
        let _ = fs::remove_file(&temp_path).await;
        return Err(UploadStreamError::Io(err));
    }

    let completed_at = OffsetDateTime::now_utc();
    let storage_key = format!("{}/{}", date_path, file_id);
    let checksum_hex = format!("{:x}", hasher.finalize());

    Ok(PersistedUpload {
        file_id,
        storage_key,
        absolute_path: final_path,
        original_name,
        size_bytes: bytes_written,
        content_type,
        checksum_hex,
        completed_at,
    })
}

async fn cleanup_orphaned_file(path: &std::path::Path) -> Result<(), std::io::Error> {
    match fs::remove_file(path).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[derive(Debug)]
struct PersistedUpload {
    file_id: String,
    storage_key: String,
    absolute_path: std::path::PathBuf,
    original_name: String,
    size_bytes: u64,
    content_type: Option<String>,
    checksum_hex: String,
    completed_at: OffsetDateTime,
}

#[derive(Debug)]
enum UploadStreamError {
    Io(std::io::Error),
    Multipart(MultipartError),
    TooLarge { limit: u64 },
    EmptyUpload,
}
