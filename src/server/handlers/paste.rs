use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};
use serde::Deserialize;
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
    settings::AppSettings,
    templates::{HtmlTemplate, PasteFieldErrors, PasteFormValues, PasteTemplate, PASTE_LANGUAGES},
};

use crate::server::{
    constants::{MAX_CODE_GENERATION_ATTEMPTS, MAX_EXPIRATION_HOURS, MAX_PASTE_SIZE_BYTES},
    utils::{
        generate_download_code, human_readable_size, resolve_paste_language, sanitize_filename,
        server_error_response,
    },
};

use super::shared::{current_app_settings, layout_from_session};

#[derive(Debug, Deserialize)]
pub(crate) struct PasteForm {
    csrf_token: String,
    title: String,
    language: String,
    expires_in: String,
    content: String,
}

pub async fn paste_form_handler(State(state): State<AppState>, session: Session) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => {}
        Ok(None) => return axum::response::Redirect::to("/login").into_response(),
        Err(err) => {
            error!(target: "sessions", %err, "failed to read session while rendering paste form");
            return server_error_response();
        }
    }

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    let default_language = PASTE_LANGUAGES
        .first()
        .map(|option| option.value)
        .unwrap_or("plain");

    let form = PasteFormValues {
        title: String::new(),
        language: default_language.to_string(),
        expires_in: settings.default_expiration_hours.to_string(),
        content: String::new(),
    };

    render_paste_form(
        &state,
        &session,
        settings.as_ref(),
        StatusCode::OK,
        form,
        PasteFieldErrors::default(),
        None,
    )
    .await
}

pub async fn paste_submit_handler(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<PasteForm>,
) -> Response {
    let session_user = match current_user(&session).await {
        Ok(Some(user)) => user,
        Ok(None) => return axum::response::Redirect::to("/login").into_response(),
        Err(err) => {
            error!(target: "sessions", %err, "failed to read session while submitting paste");
            return server_error_response();
        }
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token on paste submit");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", user_id = session_user.id, "paste form submitted with invalid CSRF token");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after paste CSRF failure");
        }
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    let language_option = resolve_paste_language(form.language.trim(), PASTE_LANGUAGES);
    let canonical_language = language_option.value.to_string();
    let title_input = form.title.trim();
    let expires_input = form.expires_in.trim();
    let content = form.content;

    let form_values = PasteFormValues {
        title: title_input.to_string(),
        language: canonical_language.clone(),
        expires_in: expires_input.to_string(),
        content: content.clone(),
    };

    let mut field_errors = PasteFieldErrors::default();
    let mut has_errors = false;

    if title_input.len() > 120 {
        field_errors.title = Some("Title cannot exceed 120 characters.".to_string());
        has_errors = true;
    }

    if content.trim().is_empty() {
        field_errors.content = Some("Enter some content before sharing.".to_string());
        has_errors = true;
    }

    let paste_limit = settings.max_file_size_bytes.min(MAX_PASTE_SIZE_BYTES);
    let content_len = content.as_bytes().len() as u64;
    if content_len > paste_limit {
        let limit_display = human_readable_size(paste_limit);
        field_errors.content = Some(format!("Pastes must be {limit_display} or smaller."));
        has_errors = true;
    }

    let expiration_hours = match form_values.expires_in.parse::<u64>() {
        Ok(value) if (1..=MAX_EXPIRATION_HOURS).contains(&value) => value,
        Ok(_) => {
            field_errors.expires_in = Some(format!(
                "Expiration must be between 1 and {} hours.",
                MAX_EXPIRATION_HOURS
            ));
            has_errors = true;
            0
        }
        Err(_) => {
            field_errors.expires_in =
                Some("Expiration must be provided as whole hours.".to_string());
            has_errors = true;
            0
        }
    };

    if has_errors {
        return render_paste_form(
            &state,
            &session,
            settings.as_ref(),
            StatusCode::UNPROCESSABLE_ENTITY,
            form_values,
            field_errors,
            Some("Please correct the highlighted fields.".to_string()),
        )
        .await;
    }

    let snippet_bytes = content.into_bytes();
    let size_bytes = match i64::try_from(snippet_bytes.len()) {
        Ok(value) => value,
        Err(_) => {
            error!(
                target: "paste",
                size = snippet_bytes.len(),
                "snippet size exceeds supported range"
            );
            return server_error_response();
        }
    };

    let created_at = OffsetDateTime::now_utc();
    let expires_at = created_at
        .checked_add(TimeDuration::hours(expiration_hours as i64))
        .map(|dt| dt.unix_timestamp());
    let created_at_ts = created_at.unix_timestamp();

    let file_id = Ulid::new().to_string();
    let date_path = format!(
        "{:04}/{:02}/{:02}",
        created_at.year(),
        u8::from(created_at.month()),
        created_at.day()
    );
    let final_dir = state.config().storage.root.join(&date_path);

    if let Err(err) = fs::create_dir_all(&final_dir).await {
        error!(target: "paste", %err, "failed to prepare paste storage directory");
        return server_error_response();
    }

    let temp_path = final_dir.join(format!("{}.uploading", file_id));
    let final_path = final_dir.join(&file_id);

    let mut file = match fs::File::create(&temp_path).await {
        Ok(file) => file,
        Err(err) => {
            error!(target: "paste", %err, "failed to create temp file for paste");
            return server_error_response();
        }
    };

    if let Err(err) = file.write_all(&snippet_bytes).await {
        drop(file);
        let _ = fs::remove_file(&temp_path).await;
        error!(target: "paste", %err, "failed to write paste contents to disk");
        return server_error_response();
    }

    if let Err(err) = file.flush().await {
        drop(file);
        let _ = fs::remove_file(&temp_path).await;
        error!(target: "paste", %err, "failed to flush paste contents to disk");
        return server_error_response();
    }
    drop(file);

    if let Err(err) = fs::rename(&temp_path, &final_path).await {
        let _ = fs::remove_file(&temp_path).await;
        error!(target: "paste", %err, "failed to finalize paste file");
        return server_error_response();
    }

    let storage_key = format!("{}/{}", date_path, file_id);
    let checksum_hex = format!("{:x}", Sha256::digest(&snippet_bytes));

    let mut base_name = title_input.to_string();
    if base_name.is_empty() {
        base_name = format!("paste-{}", &file_id[..8]);
    }

    if !base_name
        .to_ascii_lowercase()
        .ends_with(&format!(".{}", language_option.extension))
    {
        if !base_name.ends_with('.') {
            base_name.push('.');
        }
        base_name.push_str(language_option.extension);
    }

    let mut original_name = sanitize_filename(Some(&base_name));
    if original_name == "upload.bin" {
        let fallback = format!("paste-{}.{}", &file_id[..8], language_option.extension);
        original_name = sanitize_filename(Some(&fallback));
    }

    let mut attempts = 0usize;
    let record_path = final_path.clone();
    let content_type = Some(language_option.content_type.to_string());
    let code = loop {
        let candidate = generate_download_code();
        let record = files::NewFileRecord {
            id: &file_id,
            owner_user_id: Some(session_user.id),
            code: &candidate,
            original_name: &original_name,
            stored_path: &storage_key,
            size_bytes,
            content_type: content_type.as_deref(),
            checksum: Some(checksum_hex.as_str()),
            created_at: created_at_ts,
            expires_at,
        };

        match files::insert_file_record(state.db(), &record).await {
            Ok(_) => break candidate,
            Err(err)
                if crate::server::utils::is_unique_violation(&err)
                    && attempts < MAX_CODE_GENERATION_ATTEMPTS =>
            {
                attempts += 1;
                debug!(
                    target: "files",
                    %err,
                    attempt = attempts,
                    "retrying paste code generation"
                );
                continue;
            }
            Err(err) => {
                error!(target: "files", %err, "failed to persist paste record");
                if let Err(clean_err) = cleanup_orphaned_file(&record_path).await {
                    warn!(
                        target: "paste",
                        path = %record_path.display(),
                        %clean_err,
                        "failed to remove orphaned paste file"
                    );
                }
                return server_error_response();
            }
        }
    };

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after paste");
    }

    info!(
        target: "paste",
        user_id = session_user.id,
        username = session_user.username,
        file_id = %file_id,
        code = %code,
        size_bytes = size_bytes,
        language = canonical_language,
        "paste created successfully"
    );

    axum::response::Redirect::to(&format!("/f/{}", code)).into_response()
}

async fn render_paste_form(
    state: &AppState,
    session: &Session,
    settings: &AppSettings,
    status: StatusCode,
    form: PasteFormValues,
    field_errors: PasteFieldErrors,
    general_error: Option<String>,
) -> Response {
    let layout = layout_from_session(state, session, "Paste").await;
    let limit_bytes = settings.max_file_size_bytes.min(MAX_PASTE_SIZE_BYTES);
    let max_size_display = human_readable_size(limit_bytes);

    let mut template = PasteTemplate::new(layout, form, MAX_EXPIRATION_HOURS, max_size_display)
        .with_field_errors(field_errors);

    if let Some(message) = general_error {
        template = template.with_general_error(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}

async fn cleanup_orphaned_file(path: &std::path::Path) -> Result<(), std::io::Error> {
    match fs::remove_file(path).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}
