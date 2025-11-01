mod app_state;
mod auth;
mod cleanup;
mod config;
mod csrf;
mod database;
mod direct_links;
mod files;
mod logging;
mod rate_limit;
mod sessions;
mod settings;
mod templates;

use app_state::AppState;
use auth::{
    bootstrap_admin_user, find_user_by_username, hash_password, normalize_username,
    randomized_backoff, touch_user_login, update_password_hash, verify_password, AuthError,
};
use axum::{
    body::Body,
    extract::{
        multipart::{Field, Multipart, MultipartError},
        ConnectInfo, Path as AxumPath, State,
    },
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use config::AppConfig;
use database::initialize_database;
use direct_links::TokenError as DownloadTokenError;
use logging::init_logging;
use rate_limit::RateLimitError;
use serde::Deserialize;
use sessions::{clear_user, current_user, store_user, SessionUser};
use settings::{AppSettings, SettingsUpdate};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use templates::{
    DirectLinkErrorTemplate, DirectLinkSnippetTemplate, FileTemplate, HomeTemplate, HomeUploadRow,
    HtmlTemplate, LayoutContext, LoginTemplate, SettingsFieldErrors, SettingsFormValues,
    SettingsTemplate, UploadTemplate,
};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::{fs, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tower_sessions::{cookie::SameSite, Session, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;
use tracing::{debug, error, info, warn};
use ulid::Ulid;

#[derive(Debug, Error)]
enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Database initialization error: {0}")]
    DatabaseInit(#[from] database::DatabaseError),
    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("Logging error: {0}")]
    Logging(String),
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),
    #[error("Application state error: {0}")]
    AppState(#[from] app_state::AppStateError),
}

const MULTIPART_OVERHEAD_BYTES: u64 = 64_u64 * 1024;
const MAX_CODE_GENERATION_ATTEMPTS: usize = 5;
const MAX_EXPIRATION_HOURS: u64 = 2160;
const MIN_MAX_FILE_SIZE_BYTES: u64 = 1 * 1024 * 1024;
const MAX_MAX_FILE_SIZE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const MIN_DIRECT_LINK_TTL_MINUTES: u64 = 1;
const MAX_DIRECT_LINK_TTL_MINUTES: u64 = 1440;
const DEFAULT_RECENT_UPLOADS_LIMIT: i64 = 10;
const CODE_SEGMENT_LENGTH: usize = 4;
const CODE_TOTAL_LENGTH: usize = CODE_SEGMENT_LENGTH * 2;
const CODE_ALPHABET: [char; 31] = [
    '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M',
    'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Initialize logging first
    init_logging().map_err(|e| AppError::Logging(e.to_string()))?;
    info!("Starting Simple File Server");

    // Load configuration
    let config = AppConfig::load()?;
    info!("Configuration loaded successfully");

    // Initialize database with connection pool, migrations, and settings
    let db_pool = initialize_database(&config).await?;

    // Ensure a bootstrap administrator exists when configured
    bootstrap_admin_user(&db_pool, &config).await?;

    // Create session store
    let session_store = SqliteStore::new(db_pool.clone());

    // Configure session manager with proper security settings
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(config.security.cookie_secure)
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_path("/")
        .with_name("__Host.sfs.sid");

    // Create app state
    let app_state = AppState::new(db_pool, config.clone())?;

    // Spawn periodic cleanup job for expired files and sessions
    cleanup::spawn_cleanup_job(app_state.clone());

    // Configure per-route upload limits with a small multipart overhead allowance
    let upload_body_limit = config
        .storage
        .max_file_size_bytes
        .saturating_add(MULTIPART_OVERHEAD_BYTES);

    let upload_routes = Router::new()
        .route(
            "/upload",
            get(upload_form_handler).post(upload_submit_handler),
        )
        .layer(RequestBodyLimitLayer::new(upload_body_limit as usize));

    // Create router with middleware in correct order: Trace -> Sessions -> Routes
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/f/:code", get(file_lookup_handler))
        .route("/f/:code/link", post(file_direct_link_handler))
        .route("/d/:token", get(download_handler))
        .route("/login", get(login_form_handler).post(login_submit_handler))
        .route("/logout", post(logout_handler))
        .route(
            "/settings",
            get(settings_form_handler).post(settings_submit_handler),
        )
        .merge(upload_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(session_layer),
        )
        .with_state(app_state);

    // Start server
    let addr = SocketAddr::new(config.server.bind_addr.parse()?, config.server.port);
    info!("Starting server on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn home_handler(State(state): State<AppState>, session: Session) -> impl IntoResponse {
    let session_user = match current_user(&session).await {
        Ok(user) => user,
        Err(err) => {
            error!(target: "sessions", %err, "failed to read session while rendering home");
            None
        }
    };

    let layout = layout_from_session(&state, &session, "Home").await;
    let mut template = HomeTemplate::new(layout);

    if let Some(user) = session_user {
        match files::list_recent_files_for_user(state.db(), user.id, DEFAULT_RECENT_UPLOADS_LIMIT)
            .await
        {
            Ok(records) => {
                let uploads = records
                    .into_iter()
                    .filter_map(map_user_file_summary_for_home)
                    .collect();
                template = template.with_recent_uploads(uploads);
            }
            Err(err) => {
                error!(target: "files", user_id = user.id, %err, "failed to load recent uploads");
            }
        }
    }

    HtmlTemplate::new(template)
}

async fn file_lookup_handler(
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
    let layout = layout_from_session(&state, &session, "File details").await;

    let template = FileTemplate::new(
        layout,
        code,
        original_name,
        size_display,
        created_display,
        expires_display,
    )
    .with_content_type(content_type)
    .with_checksum(checksum);

    HtmlTemplate::new(template).into_response()
}

async fn file_direct_link_handler(
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

async fn download_handler(
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

    let now = OffsetDateTime::now_utc();

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
            debug!(
                target: "links",
                file_id = %record.id,
                expires_at,
                "download attempted after file expiration"
            );
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

async fn settings_form_handler(State(state): State<AppState>, session: Session) -> Response {
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

async fn settings_submit_handler(
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

async fn require_admin(session: &Session) -> Result<SessionUser, Response> {
    match current_user(session).await {
        Ok(Some(user)) if user.is_admin => Ok(user),
        Ok(Some(user)) => {
            warn!(
                target: "settings",
                user_id = user.id,
                username = %user.username,
                "non-admin attempted to manage settings"
            );
            Err((
                StatusCode::FORBIDDEN,
                "You are not authorized to manage settings.",
            )
                .into_response())
        }
        Ok(None) => Err(Redirect::to("/login").into_response()),
        Err(err) => {
            error!(
                target: "sessions",
                %err,
                "failed to read session while enforcing admin access"
            );
            Err(server_error_response())
        }
    }
}

async fn upload_form_handler(State(state): State<AppState>, session: Session) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => render_upload_form(&state, &session, StatusCode::OK, None, None).await,
        Ok(None) => Redirect::to("/login").into_response(),
        Err(err) => {
            error!(target: "sessions", %err, "failed to read session while rendering upload form");
            server_error_response()
        }
    }
}

async fn upload_submit_handler(
    State(state): State<AppState>,
    session: Session,
    mut multipart: Multipart,
) -> Response {
    let session_user = match current_user(&session).await {
        Ok(Some(user)) => user,
        Ok(None) => return Redirect::to("/login").into_response(),
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
                            Some(format!("Files must be {} or smaller.", limit_display)),
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
                    debug!(target: "upload", field = field_name.as_deref().unwrap_or(""), %err, "discarding unexpected multipart field");
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
            Err(err) if is_unique_violation(&err) && attempts < MAX_CODE_GENERATION_ATTEMPTS => {
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

    Redirect::to(&format!("/f/{}", code)).into_response()
}

#[derive(Debug)]
struct PersistedUpload {
    file_id: String,
    storage_key: String,
    absolute_path: PathBuf,
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

fn map_user_file_summary_for_home(record: files::UserFileSummary) -> Option<HomeUploadRow> {
    if record.size_bytes < 0 {
        debug!(
            target: "files",
            size = record.size_bytes,
            code = record.code,
            "ignoring file with negative size"
        );
        return None;
    }

    let size_display = human_readable_size(record.size_bytes as u64);
    let created_display = match OffsetDateTime::from_unix_timestamp(record.created_at) {
        Ok(dt) => format_datetime_utc(dt),
        Err(err) => {
            debug!(
                target: "files",
                %err,
                created_at = record.created_at,
                code = record.code,
                "invalid created_at stored for file"
            );
            return None;
        }
    };

    Some(HomeUploadRow {
        code: record.code,
        original_name: record.original_name,
        size_display,
        created_display,
    })
}

fn human_readable_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit_index])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit_index])
    } else {
        format!("{value:.2} {}", UNITS[unit_index])
    }
}

fn format_datetime_utc(dt: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute()
    )
}

fn generate_download_code() -> String {
    let raw = nanoid::nanoid!(CODE_TOTAL_LENGTH, &CODE_ALPHABET);
    format!(
        "{}-{}",
        &raw[..CODE_SEGMENT_LENGTH],
        &raw[CODE_SEGMENT_LENGTH..]
    )
}

fn normalize_lookup_code(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut normalized = String::with_capacity(CODE_TOTAL_LENGTH + 1);
    let mut collected = Vec::with_capacity(CODE_TOTAL_LENGTH);

    for ch in trimmed.chars() {
        if ch == '-' || ch.is_ascii_whitespace() {
            continue;
        }

        if !ch.is_ascii() {
            return None;
        }

        collected.push(ch.to_ascii_uppercase());
    }

    if collected.len() != CODE_TOTAL_LENGTH {
        return None;
    }

    for (index, ch) in collected.into_iter().enumerate() {
        if !CODE_ALPHABET.contains(&ch) {
            return None;
        }

        if index == CODE_SEGMENT_LENGTH {
            normalized.push('-');
        }

        normalized.push(ch);
    }

    Some(normalized)
}

fn sanitize_filename(raw: Option<&str>) -> String {
    const FALLBACK: &str = "upload.bin";
    let Some(name) = raw else {
        return FALLBACK.to_string();
    };

    let trimmed = name.trim();
    if trimmed.is_empty() {
        return FALLBACK.to_string();
    }

    let candidate = Path::new(trimmed)
        .file_name()
        .and_then(|segment| segment.to_str())
        .unwrap_or(FALLBACK);

    let cleaned: String = candidate.chars().filter(|c| !c.is_control()).collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return FALLBACK.to_string();
    }

    cleaned.chars().take(255).collect()
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
    field: Field<'_>,
    storage_root: &Path,
    max_file_size: u64,
) -> Result<PersistedUpload, UploadStreamError> {
    let mut field = field;
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

async fn cleanup_orphaned_file(path: &Path) -> Result<(), std::io::Error> {
    match fs::remove_file(path).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn file_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        "We couldn't find a file with that code. Double-check the code and try again.",
    )
        .into_response()
}

fn file_expired_response() -> Response {
    (
        StatusCode::GONE,
        "This file is no longer available. The link has expired.",
    )
        .into_response()
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

fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err
            .code()
            .map(|code| code.as_ref() == "2067" || code.as_ref() == "1555")
            .unwrap_or(false),
        _ => false,
    }
}

async fn login_form_handler(State(state): State<AppState>, session: Session) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => Redirect::to("/").into_response(),
        Ok(None) => {
            let layout = layout_from_session(&state, &session, "Sign in").await;
            HtmlTemplate::new(LoginTemplate::new(layout)).into_response()
        }
        Err(err) => {
            error!(target: "auth", %err, "failed to read user from session");
            let layout = LayoutContext::from_state(&state, "Sign in").await;
            HtmlTemplate::new(LoginTemplate::new(layout)).into_response()
        }
    }
}

async fn login_submit_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Response {
    const INVALID_CREDENTIALS_MESSAGE: &str = "Invalid username or password.";

    let client_ip = addr.ip();

    if let Err(err) = state.login_rate_limiter().check_ip(client_ip) {
        warn!(target: "auth", ip = %client_ip, %err, "rate limited login by IP");
        return rate_limited_login_response(&state, &session, &form.username, &err).await;
    }

    let normalized_username = match normalize_username(&form.username) {
        Ok(username) => username,
        Err(_) => {
            randomized_backoff().await;
            return render_login_page(
                &state,
                &session,
                &form.username,
                Some(INVALID_CREDENTIALS_MESSAGE.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
    };

    if let Err(err) = state
        .login_rate_limiter()
        .check_username(&normalized_username)
    {
        warn!(target: "auth", username = %normalized_username, %err, "rate limited login by username");
        return rate_limited_login_response(&state, &session, &form.username, &err).await;
    }

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "auth", %err, "failed to validate CSRF token");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "auth", username = %normalized_username, "invalid CSRF token on login");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "auth", %err, "failed to rotate CSRF token after validation error");
        }
        randomized_backoff().await;
        return render_login_page(
            &state,
            &session,
            &form.username,
            Some("Your session expired. Please try again.".to_string()),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    let maybe_user = match find_user_by_username(state.db(), &normalized_username).await {
        Ok(user) => user,
        Err(err) => {
            error!(target: "auth", %err, "failed to load user during login");
            return server_error_response();
        }
    };

    let user = match maybe_user {
        Some(user) => user,
        None => {
            randomized_backoff().await;
            return render_login_page(
                &state,
                &session,
                &form.username,
                Some(INVALID_CREDENTIALS_MESSAGE.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
    };

    let verification = match verify_password(
        &form.password,
        &user.password_hash,
        state.config().security.password_pepper.as_deref(),
    )
    .await
    {
        Ok(result) => result,
        Err(AuthError::InvalidCredentials) => {
            randomized_backoff().await;
            return render_login_page(
                &state,
                &session,
                &form.username,
                Some(INVALID_CREDENTIALS_MESSAGE.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
        Err(err) => {
            error!(target: "auth", %err, "error verifying password");
            return server_error_response();
        }
    };

    if verification.needs_rehash {
        match hash_password(
            &form.password,
            state.config().security.password_pepper.as_deref(),
        )
        .await
        {
            Ok(new_hash) => {
                if let Err(err) = update_password_hash(state.db(), user.id, &new_hash).await {
                    error!(target: "auth", %err, "failed to update password hash during rehash");
                    if let Err(err) = touch_user_login(state.db(), user.id).await {
                        error!(target: "auth", %err, "failed to update last login timestamp");
                    }
                }
            }
            Err(err) => {
                error!(target: "auth", %err, "failed to rehash password");
                if let Err(err) = touch_user_login(state.db(), user.id).await {
                    error!(target: "auth", %err, "failed to update last login timestamp");
                }
            }
        }
    } else if let Err(err) = touch_user_login(state.db(), user.id).await {
        error!(target: "auth", %err, "failed to update last login timestamp");
    }

    if let Err(err) = session.cycle_id().await {
        error!(target: "auth", %err, "failed to cycle session ID on login");
        return server_error_response();
    }

    let session_user = SessionUser::new(user.id, user.username.clone(), user.is_admin);
    if let Err(err) = store_user(&session, &session_user).await {
        error!(target: "auth", %err, "failed to persist authenticated user in session");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "auth", %err, "failed to rotate CSRF token after login");
    }

    Redirect::to("/").into_response()
}

async fn logout_handler(session: Session, Form(form): Form<LogoutForm>) -> Response {
    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "auth", %err, "failed to validate CSRF token on logout");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "auth", "invalid CSRF token on logout");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "auth", %err, "failed to rotate CSRF token after logout validation failure");
        }
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }

    if let Err(err) = clear_user(&session).await {
        error!(target: "auth", %err, "failed to clear user session on logout");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "auth", %err, "failed to rotate CSRF token during logout");
    }

    if let Err(err) = session.cycle_id().await {
        error!(target: "auth", %err, "failed to cycle session after logout");
        return server_error_response();
    }

    Redirect::to("/login").into_response()
}

async fn layout_from_session(state: &AppState, session: &Session, title: &str) -> LayoutContext {
    match LayoutContext::from_session(state, session, title).await {
        Ok(layout) => layout,
        Err(err) => {
            error!(target: "templates", %err, "failed to build layout context from session");
            LayoutContext::from_state(state, title).await
        }
    }
}

async fn render_login_page(
    state: &AppState,
    session: &Session,
    username: &str,
    error_message: Option<String>,
    status: StatusCode,
) -> Response {
    let mut template = LoginTemplate::new(layout_from_session(state, session, "Sign in").await)
        .with_username(username);
    if let Some(message) = error_message {
        template = template.with_error_message(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}

async fn current_app_settings(state: &AppState) -> Result<Arc<AppSettings>, Response> {
    match state.settings().current().await {
        Ok(settings) => Ok(settings),
        Err(err) => {
            error!(
                target: "settings",
                %err,
                "failed to load application settings from database"
            );
            Err(server_error_response())
        }
    }
}

async fn rate_limited_login_response(
    state: &AppState,
    session: &Session,
    username: &str,
    error: &RateLimitError,
) -> Response {
    let message = match error {
        RateLimitError::Ip(_) => {
            "Too many login attempts from this IP address. Please wait and try again.".to_string()
        }
        RateLimitError::Username(_) => {
            "Too many login attempts for this username. Please wait before trying again."
                .to_string()
        }
        RateLimitError::DirectLink(_) | RateLimitError::DirectDownload(_) => {
            "Too many requests right now. Please wait before trying again.".to_string()
        }
    };

    let mut response = render_login_page(
        state,
        session,
        username,
        Some(message),
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;
    let retry_after_secs = error.retry_after().as_secs().max(1);

    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }

    response
}

fn server_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to process your request. Please try again later.",
    )
        .into_response()
}

fn direct_link_error_response(status: StatusCode, message: &str) -> Response {
    let template = DirectLinkErrorTemplate::new(message);
    HtmlTemplate::with_status(template, status).into_response()
}

fn rate_limited_direct_link_response(error: &RateLimitError) -> Response {
    let retry_after_secs = error.retry_after().as_secs().max(1);
    let mut response = direct_link_error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "You are requesting links too quickly. Please wait and try again.",
    );

    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }

    response
}

fn rate_limited_download_response(error: &RateLimitError) -> Response {
    let retry_after_secs = error.retry_after().as_secs().max(1);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        "Too many downloads from this IP address. Please wait and try again.",
    )
        .into_response();

    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }

    response
}

fn download_unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        "That direct link is no longer valid. Visit the file page to generate a new one.",
    )
        .into_response()
}

fn build_content_disposition_header(filename: &str) -> HeaderValue {
    let mut safe = String::with_capacity(filename.len());

    for ch in filename.chars() {
        if matches!(ch, ' '..='~') && ch != '"' && ch != '\\' {
            safe.push(ch);
        } else {
            safe.push('_');
        }
    }

    if safe.is_empty() {
        safe.push_str("download.bin");
    }

    if safe.len() > 255 {
        safe.truncate(255);
    }

    let header_value = format!("attachment; filename=\"{safe}\"");
    HeaderValue::from_str(&header_value).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct GenerateLinkForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct SettingsFormSubmission {
    csrf_token: String,
    ui_brand_name: String,
    max_file_size_bytes: String,
    default_expiration_hours: String,
    direct_link_ttl_minutes: String,
    allow_anonymous_download: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogoutForm {
    csrf_token: String,
}
