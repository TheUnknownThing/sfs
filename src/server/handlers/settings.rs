use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use tower_sessions::Session;
use tracing::{error, info, warn};

use crate::{
    app_state::AppState,
    csrf,
    settings::SettingsUpdate,
    templates::{HtmlTemplate, SettingsFieldErrors, SettingsFormValues, SettingsTemplate},
};

use crate::server::constants::{
    MAX_DIRECT_LINK_TTL_MINUTES, MAX_EXPIRATION_HOURS, MAX_MAX_FILE_SIZE_BYTES,
    MIN_DIRECT_LINK_TTL_MINUTES, MIN_MAX_FILE_SIZE_BYTES,
};
use crate::server::utils::{human_readable_size, server_error_response};

use super::shared::{current_app_settings, layout_from_session, require_admin};

#[derive(Debug, Deserialize)]
pub(crate) struct SettingsFormSubmission {
    csrf_token: String,
    ui_brand_name: String,
    max_file_size_bytes: String,
    default_expiration_hours: String,
    direct_link_ttl_minutes: String,
    allow_anonymous_download: Option<String>,
    allow_registration: Option<String>,
}

pub async fn settings_form_handler(State(state): State<AppState>, session: Session) -> Response {
    if let Err(response) = require_admin(&session).await.map(|_| ()) {
        return response;
    }

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    render_settings_page(
        &state,
        &session,
        SettingsFormValues::from_settings(&settings),
        SettingsFieldErrors::default(),
        None,
        None,
        StatusCode::OK,
    )
    .await
}

pub async fn settings_submit_handler(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<SettingsFormSubmission>,
) -> Response {
    let admin = match require_admin(&session).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let form_values = SettingsFormValues {
        ui_brand_name: form.ui_brand_name.trim().to_string(),
        max_file_size_bytes: form.max_file_size_bytes.trim().to_string(),
        default_expiration_hours: form.default_expiration_hours.trim().to_string(),
        direct_link_ttl_minutes: form.direct_link_ttl_minutes.trim().to_string(),
        allow_anonymous_download: form.allow_anonymous_download.is_some(),
        allow_registration: form.allow_registration.is_some(),
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token on settings form");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", "settings form submitted with invalid CSRF token");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after settings CSRF failure");
        }

        return render_settings_page(
            &state,
            &session,
            form_values,
            SettingsFieldErrors::default(),
            Some("Your session expired. Please refresh and try again.".to_string()),
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    let mut field_errors = SettingsFieldErrors::default();
    let mut has_errors = false;

    let brand_name = form_values.ui_brand_name.trim();
    if brand_name.len() < 2 {
        field_errors.ui_brand_name = Some("Brand name must be at least 2 characters.".to_string());
        has_errors = true;
    } else if brand_name.len() > 80 {
        field_errors.ui_brand_name = Some("Brand name cannot exceed 80 characters.".to_string());
        has_errors = true;
    }

    let max_file_size_bytes = match form_values.max_file_size_bytes.parse::<u64>() {
        Ok(value) if value >= MIN_MAX_FILE_SIZE_BYTES && value <= MAX_MAX_FILE_SIZE_BYTES => value,
        Ok(_) => {
            let min_display = human_readable_size(MIN_MAX_FILE_SIZE_BYTES);
            let max_display = human_readable_size(MAX_MAX_FILE_SIZE_BYTES);
            field_errors.max_file_size_bytes = Some(format!(
                "Value must be between {} and {} bytes ({} - {}).",
                MIN_MAX_FILE_SIZE_BYTES, MAX_MAX_FILE_SIZE_BYTES, min_display, max_display
            ));
            has_errors = true;
            0
        }
        Err(_) => {
            field_errors.max_file_size_bytes =
                Some("Enter a whole number of bytes between 1 MB and 5 GB.".to_string());
            has_errors = true;
            0
        }
    };

    let default_expiration_hours = match form_values.default_expiration_hours.parse::<u64>() {
        Ok(value) if (1..=MAX_EXPIRATION_HOURS).contains(&value) => value,
        Ok(_) => {
            field_errors.default_expiration_hours = Some(format!(
                "Expiration must be between 1 and {} hours.",
                MAX_EXPIRATION_HOURS
            ));
            has_errors = true;
            0
        }
        Err(_) => {
            field_errors.default_expiration_hours =
                Some("Enter the number of hours as a whole number.".to_string());
            has_errors = true;
            0
        }
    };

    let direct_link_ttl_minutes = match form_values.direct_link_ttl_minutes.parse::<u64>() {
        Ok(value)
            if (MIN_DIRECT_LINK_TTL_MINUTES..=MAX_DIRECT_LINK_TTL_MINUTES).contains(&value) =>
        {
            value
        }
        Ok(_) => {
            field_errors.direct_link_ttl_minutes = Some(format!(
                "Direct link lifetime must be between {} and {} minutes.",
                MIN_DIRECT_LINK_TTL_MINUTES, MAX_DIRECT_LINK_TTL_MINUTES
            ));
            has_errors = true;
            0
        }
        Err(_) => {
            field_errors.direct_link_ttl_minutes =
                Some("Enter the link lifetime in whole minutes.".to_string());
            has_errors = true;
            0
        }
    };

    if has_errors {
        return render_settings_page(
            &state,
            &session,
            form_values,
            field_errors,
            Some("Please correct the highlighted fields.".to_string()),
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    let update = SettingsUpdate {
        max_file_size_bytes,
        default_expiration_hours,
        direct_link_ttl_minutes,
        allow_anonymous_download: form_values.allow_anonymous_download,
        allow_registration: form_values.allow_registration,
        ui_brand_name: brand_name.to_string(),
    };

    let updated_settings = match state.settings().update(update).await {
        Ok(settings) => settings,
        Err(err) => {
            error!(
                target: "settings",
                %err,
                user_id = admin.id,
                username = %admin.username,
                "failed to persist settings update"
            );

            return render_settings_page(
                &state,
                &session,
                form_values,
                SettingsFieldErrors::default(),
                Some("Failed to save settings. Please try again.".to_string()),
                None,
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .await;
        }
    };

    info!(
        target: "settings",
        user_id = admin.id,
        username = %admin.username,
        "updated application settings"
    );

    render_settings_page(
        &state,
        &session,
        SettingsFormValues::from_settings(&updated_settings),
        SettingsFieldErrors::default(),
        None,
        Some("Settings updated successfully.".to_string()),
        StatusCode::OK,
    )
    .await
}

async fn render_settings_page(
    state: &AppState,
    session: &Session,
    form: SettingsFormValues,
    field_errors: SettingsFieldErrors,
    general_error: Option<String>,
    success_message: Option<String>,
    status: StatusCode,
) -> Response {
    let layout = layout_from_session(state, session, "Settings").await;
    let mut template = SettingsTemplate::new(layout, form).with_field_errors(field_errors);

    if let Some(message) = general_error {
        template = template.with_general_error(message);
    }

    if let Some(message) = success_message {
        template = template.with_success_message(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}
