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
mod users;

use app_state::AppState;
use auth::{
    bootstrap_admin_user, find_user_by_username, hash_password, normalize_username,
    randomized_backoff, touch_user_login, update_password_hash, validate_password_strength,
    verify_password, AuthError,
};
use axum::{
    body::Body,
    extract::{
        multipart::{Field, Multipart, MultipartError},
        ConnectInfo, Path as AxumPath, Query, State,
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
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use templates::{
    AddUserFieldErrors, AddUserFormValues, DirectLinkErrorTemplate, DirectLinkSnippetTemplate,
    FileTemplate, HomeTemplate, HomeUploadRow, HtmlTemplate, LayoutContext, LoginTemplate,
    ManagedUserRow, PasteFieldErrors, PasteFormValues, PasteLanguageOption, PasteTemplate,
    RegisterTemplate, RegistrationFieldErrors, RegistrationFormValues, SettingsFieldErrors,
    SettingsFormValues, SettingsTemplate, UploadTemplate, UserManagementTemplate, PASTE_LANGUAGES,
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
const MAX_PASTE_SIZE_BYTES: u64 = 512 * 1024;
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
        .route("/f/:code/delete", post(file_delete_handler))
        .route("/d/:token", get(download_handler))
        .route("/login", get(login_form_handler).post(login_submit_handler))
        .route(
            "/register",
            get(register_form_handler).post(register_submit_handler),
        )
        .route("/logout", post(logout_handler))
        .route(
            "/settings",
            get(settings_form_handler).post(settings_submit_handler),
        )
        .route(
            "/admin/users",
            get(user_management_page_handler).post(user_create_handler),
        )
        .route(
            "/admin/users/:id/reset-password",
            post(user_reset_password_handler),
        )
        .route("/admin/users/:id/delete", post(user_delete_handler))
        .route("/paste", get(paste_form_handler).post(paste_submit_handler))
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

async fn home_handler(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<HomeQueryParams>,
) -> impl IntoResponse {
    let flash_message = match query.flash.as_deref() {
        Some("deleted") => Some("File deleted successfully.".to_string()),
        _ => None,
    };

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

    template = template.with_flash_message(flash_message);

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
    .with_delete_permission(can_delete);

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

async fn file_delete_handler(
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

    let session_user = match current_user(&session).await {
        Ok(Some(user)) => user,
        Ok(None) => return Redirect::to("/login").into_response(),
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
    match fs::remove_file(&storage_path).await {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {
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

    Redirect::to("/?flash=deleted").into_response()
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

async fn user_management_page_handler(State(state): State<AppState>, session: Session) -> Response {
    if let Err(response) = require_admin(&session).await.map(|_| ()) {
        return response;
    }

    let users = match fetch_user_rows(&state).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };

    render_user_management_page(
        &state,
        &session,
        StatusCode::OK,
        users,
        AddUserFormValues::default(),
        AddUserFieldErrors::default(),
        None,
        None,
    )
    .await
}

async fn user_create_handler(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<AddUserFormSubmission>,
) -> Response {
    let admin = match require_admin(&session).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token for add-user");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", user_id = admin.id, "add-user request failed CSRF validation");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after add-user failure");
        }
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues {
                        username: form.username.trim().to_string(),
                        is_admin: form.is_admin.is_some(),
                    },
                    AddUserFieldErrors::default(),
                    Some("Your session expired. Please try again.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    let mut field_errors = AddUserFieldErrors::default();
    let mut has_errors = false;
    let username_input = form.username.trim();
    let add_form = AddUserFormValues {
        username: username_input.to_string(),
        is_admin: form.is_admin.is_some(),
    };

    let normalized_username = match normalize_username(username_input) {
        Ok(username) => username,
        Err(_) => {
            field_errors.username =
                Some("Enter a username between 3 and 64 characters without spaces.".to_string());
            has_errors = true;
            String::new()
        }
    };

    if let Err(err) = validate_password_strength(&form.password) {
        match err {
            AuthError::InvalidPassword => {
                field_errors.password =
                    Some("Password must be at least 12 characters long.".to_string());
            }
            _ => {
                error!(target: "auth", %err, "unexpected password validation error while adding user");
                return server_error_response();
            }
        }
        has_errors = true;
    }

    if form.password != form.password_confirm {
        field_errors.password_confirm = Some("Passwords do not match.".to_string());
        has_errors = true;
    }

    if normalized_username.is_empty() {
        has_errors = true;
    }

    let users_snapshot = match fetch_user_rows(&state).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };

    if has_errors {
        return render_user_management_page(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            users_snapshot,
            add_form,
            field_errors,
            Some("Please correct the highlighted fields.".to_string()),
            None,
        )
        .await;
    }

    match find_user_by_username(state.db(), &normalized_username).await {
        Ok(Some(_)) => {
            field_errors.username = Some("That username is already taken.".to_string());
            return render_user_management_page(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                users_snapshot,
                add_form,
                field_errors,
                Some("Unable to create the user.".to_string()),
                None,
            )
            .await;
        }
        Ok(None) => {}
        Err(err) => {
            error!(target: "auth", %err, "failed to check existing user during add-user");
            return server_error_response();
        }
    }

    let password_hash = match hash_password(
        &form.password,
        state.config().security.password_pepper.as_deref(),
    )
    .await
    {
        Ok(hash) => hash,
        Err(err) => {
            error!(target: "auth", %err, "failed to hash password while adding user");
            return server_error_response();
        }
    };

    if let Err(err) = users::create_user(
        state.db(),
        &normalized_username,
        &password_hash,
        form.is_admin.is_some(),
    )
    .await
    {
        if is_unique_violation(&err) {
            field_errors.username = Some("That username is already taken.".to_string());
            return render_user_management_page(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                users_snapshot,
                add_form,
                field_errors,
                Some("Unable to create the user.".to_string()),
                None,
            )
            .await;
        }

        error!(target: "users", %err, "failed to insert new user from admin panel");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after adding user");
    }

    info!(
        target: "users",
        admin_id = admin.id,
        admin_username = %admin.username,
        new_username = %normalized_username,
        is_admin = form.is_admin.is_some(),
        "administrator created new user"
    );

    match fetch_user_rows(&state).await {
        Ok(users) => {
            render_user_management_page(
                &state,
                &session,
                StatusCode::OK,
                users,
                AddUserFormValues::default(),
                AddUserFieldErrors::default(),
                None,
                Some("User created successfully.".to_string()),
            )
            .await
        }
        Err(response) => response,
    }
}

async fn user_reset_password_handler(
    State(state): State<AppState>,
    session: Session,
    AxumPath(user_id): AxumPath<i64>,
    Form(form): Form<ResetUserPasswordForm>,
) -> Response {
    let admin = match require_admin(&session).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token for password reset");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", user_id = admin.id, "reset-password request failed CSRF validation");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after reset-password failure");
        }
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues::default(),
                    AddUserFieldErrors::default(),
                    Some("Your session expired. Please try again.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    if form.new_password != form.confirm_password {
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues::default(),
                    AddUserFieldErrors::default(),
                    Some("Passwords do not match.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    if let Err(err) = validate_password_strength(&form.new_password) {
        match err {
            AuthError::InvalidPassword => {
                return match fetch_user_rows(&state).await {
                    Ok(users) => {
                        render_user_management_page(
                            &state,
                            &session,
                            StatusCode::UNPROCESSABLE_ENTITY,
                            users,
                            AddUserFormValues::default(),
                            AddUserFieldErrors::default(),
                            Some("Password must be at least 12 characters long.".to_string()),
                            None,
                        )
                        .await
                    }
                    Err(response) => response,
                };
            }
            _ => {
                error!(target: "auth", %err, "unexpected password validation error during reset");
                return server_error_response();
            }
        }
    }

    let target_user = match users::find_user_by_id(state.db(), user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return match fetch_user_rows(&state).await {
                Ok(users) => {
                    render_user_management_page(
                        &state,
                        &session,
                        StatusCode::NOT_FOUND,
                        users,
                        AddUserFormValues::default(),
                        AddUserFieldErrors::default(),
                        Some("That user no longer exists.".to_string()),
                        None,
                    )
                    .await
                }
                Err(response) => response,
            };
        }
        Err(err) => {
            error!(target: "users", %err, user_id, "failed to load user for password reset");
            return server_error_response();
        }
    };

    let new_hash = match hash_password(
        &form.new_password,
        state.config().security.password_pepper.as_deref(),
    )
    .await
    {
        Ok(hash) => hash,
        Err(err) => {
            error!(target: "auth", %err, "failed to hash password during admin reset");
            return server_error_response();
        }
    };

    if let Err(err) = update_password_hash(state.db(), target_user.id, &new_hash).await {
        error!(target: "auth", %err, user_id = target_user.id, "failed to update password hash during reset");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after password reset");
    }

    info!(
        target: "users",
        admin_id = admin.id,
        admin_username = %admin.username,
        target_id = target_user.id,
        target_username = %target_user.username,
        "administrator reset user password"
    );

    match fetch_user_rows(&state).await {
        Ok(users) => {
            render_user_management_page(
                &state,
                &session,
                StatusCode::OK,
                users,
                AddUserFormValues::default(),
                AddUserFieldErrors::default(),
                None,
                Some(format!(
                    "Password reset for user '{}'.",
                    target_user.username
                )),
            )
            .await
        }
        Err(response) => response,
    }
}

async fn user_delete_handler(
    State(state): State<AppState>,
    session: Session,
    AxumPath(user_id): AxumPath<i64>,
    Form(form): Form<DeleteUserForm>,
) -> Response {
    let admin = match require_admin(&session).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token for delete-user");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", user_id = admin.id, "delete-user request failed CSRF validation");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after delete-user failure");
        }
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues::default(),
                    AddUserFieldErrors::default(),
                    Some("Your session expired. Please try again.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    let target_user = match users::find_user_by_id(state.db(), user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return match fetch_user_rows(&state).await {
                Ok(users) => {
                    render_user_management_page(
                        &state,
                        &session,
                        StatusCode::NOT_FOUND,
                        users,
                        AddUserFormValues::default(),
                        AddUserFieldErrors::default(),
                        Some("That user no longer exists.".to_string()),
                        None,
                    )
                    .await
                }
                Err(response) => response,
            };
        }
        Err(err) => {
            error!(target: "users", %err, user_id, "failed to load user for deletion");
            return server_error_response();
        }
    };

    if target_user.id == admin.id {
        return match fetch_user_rows(&state).await {
            Ok(users) => {
                render_user_management_page(
                    &state,
                    &session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    users,
                    AddUserFormValues::default(),
                    AddUserFieldErrors::default(),
                    Some("You cannot delete your own account.".to_string()),
                    None,
                )
                .await
            }
            Err(response) => response,
        };
    }

    if target_user.is_admin {
        match users::count_admin_users(state.db()).await {
            Ok(count) if count <= 1 => {
                return match fetch_user_rows(&state).await {
                    Ok(users) => {
                        render_user_management_page(
                            &state,
                            &session,
                            StatusCode::UNPROCESSABLE_ENTITY,
                            users,
                            AddUserFormValues::default(),
                            AddUserFieldErrors::default(),
                            Some("At least one administrator must remain.".to_string()),
                            None,
                        )
                        .await
                    }
                    Err(response) => response,
                };
            }
            Ok(_) => {}
            Err(err) => {
                error!(target: "users", %err, "failed to count admin users before deletion");
                return server_error_response();
            }
        }
    }

    match users::delete_user(state.db(), target_user.id).await {
        Ok(affected) if affected == 1 => {}
        Ok(_) => {
            return server_error_response();
        }
        Err(err) => {
            error!(target: "users", %err, user_id = target_user.id, "failed to delete user");
            return server_error_response();
        }
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after user deletion");
    }

    info!(
        target: "users",
        admin_id = admin.id,
        admin_username = %admin.username,
        target_id = target_user.id,
        target_username = %target_user.username,
        "administrator deleted user"
    );

    match fetch_user_rows(&state).await {
        Ok(users) => {
            render_user_management_page(
                &state,
                &session,
                StatusCode::OK,
                users,
                AddUserFormValues::default(),
                AddUserFieldErrors::default(),
                None,
                Some(format!("User '{}' deleted.", target_user.username)),
            )
            .await
        }
        Err(response) => response,
    }
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

async fn paste_form_handler(State(state): State<AppState>, session: Session) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => {}
        Ok(None) => return Redirect::to("/login").into_response(),
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

async fn paste_submit_handler(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<PasteForm>,
) -> Response {
    let session_user = match current_user(&session).await {
        Ok(Some(user)) => user,
        Ok(None) => return Redirect::to("/login").into_response(),
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

    let language_option = resolve_paste_language(form.language.trim());
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
            Err(err) if is_unique_violation(&err) && attempts < MAX_CODE_GENERATION_ATTEMPTS => {
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

fn map_user_summary_for_admin(record: users::UserSummary) -> Option<ManagedUserRow> {
    let created_display = match OffsetDateTime::from_unix_timestamp(record.created_at) {
        Ok(dt) => format_datetime_utc(dt),
        Err(err) => {
            debug!(
                target: "users",
                %err,
                created_at = record.created_at,
                user_id = record.id,
                "invalid created_at stored for user"
            );
            return None;
        }
    };

    let last_login_display = match record.last_login_at {
        Some(ts) => match OffsetDateTime::from_unix_timestamp(ts) {
            Ok(dt) => Some(format_datetime_utc(dt)),
            Err(err) => {
                debug!(
                    target: "users",
                    %err,
                    last_login_at = ts,
                    user_id = record.id,
                    "invalid last_login_at stored for user"
                );
                None
            }
        },
        None => None,
    };

    Some(ManagedUserRow {
        id: record.id,
        username: record.username,
        is_admin: record.is_admin,
        created_display,
        last_login_display,
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

fn resolve_paste_language(value: &str) -> &'static PasteLanguageOption {
    if PASTE_LANGUAGES.is_empty() {
        panic!("PASTE_LANGUAGES must contain at least one entry");
    }

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return &PASTE_LANGUAGES[0];
    }

    PASTE_LANGUAGES
        .iter()
        .find(|option| option.value.eq_ignore_ascii_case(trimmed))
        .unwrap_or(&PASTE_LANGUAGES[0])
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

async fn register_form_handler(State(state): State<AppState>, session: Session) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => return Redirect::to("/").into_response(),
        Ok(None) => {}
        Err(err) => {
            error!(
                target: "sessions",
                %err,
                "failed to read session while rendering registration form"
            );
            return server_error_response();
        }
    }

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    if !settings.allow_registration {
        return registration_closed_response(&state, &session).await;
    }

    render_registration_form(
        &state,
        &session,
        StatusCode::OK,
        RegistrationFormValues::default(),
        RegistrationFieldErrors::default(),
        None,
    )
    .await
}

async fn register_submit_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: Session,
    Form(form): Form<RegistrationForm>,
) -> Response {
    match current_user(&session).await {
        Ok(Some(_)) => return Redirect::to("/").into_response(),
        Ok(None) => {}
        Err(err) => {
            error!(
                target: "sessions",
                %err,
                "failed to read session while processing registration"
            );
            return server_error_response();
        }
    }

    let settings = match current_app_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };

    if !settings.allow_registration {
        return registration_closed_response(&state, &session).await;
    }

    let client_ip = addr.ip();
    if let Err(err) = state.registration_rate_limiter().check_ip(client_ip) {
        warn!(
            target: "auth",
            ip = %client_ip,
            %err,
            "registration request rate-limited"
        );
        let form_values = RegistrationFormValues {
            username: form.username.trim().to_string(),
        };
        return registration_rate_limited_response(&state, &session, form_values, &err).await;
    }

    let csrf_valid = match csrf::validate_csrf_token(&session, &form.csrf_token).await {
        Ok(valid) => valid,
        Err(err) => {
            error!(target: "csrf", %err, "failed to validate CSRF token on registration");
            return server_error_response();
        }
    };

    if !csrf_valid {
        warn!(target: "csrf", "registration form submitted with invalid CSRF token");
        if let Err(err) = csrf::rotate_csrf_token(&session).await {
            error!(target: "csrf", %err, "failed to rotate CSRF token after invalid registration");
        }
        let form_values = RegistrationFormValues {
            username: form.username.trim().to_string(),
        };
        return render_registration_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            form_values,
            RegistrationFieldErrors::default(),
            Some("Your session expired. Please try again.".to_string()),
        )
        .await;
    }

    let mut field_errors = RegistrationFieldErrors::default();
    let mut has_errors = false;
    let username_input = form.username.trim();
    let form_values = RegistrationFormValues {
        username: username_input.to_string(),
    };

    let normalized_username = match normalize_username(username_input) {
        Ok(username) => username,
        Err(_) => {
            field_errors.username =
                Some("Enter a username between 3 and 64 characters without spaces.".to_string());
            has_errors = true;
            String::new()
        }
    };

    if normalized_username.is_empty() {
        return render_registration_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            form_values,
            field_errors,
            Some("Please correct the highlighted fields.".to_string()),
        )
        .await;
    }

    if let Err(err) = validate_password_strength(&form.password) {
        match err {
            AuthError::InvalidPassword => {
                field_errors.password =
                    Some("Password must be at least 12 characters long.".to_string());
            }
            _ => {
                error!(target: "auth", %err, "unexpected validation error on password strength");
                return server_error_response();
            }
        }
        has_errors = true;
    }

    if form.password != form.password_confirm {
        field_errors.password_confirm = Some("Passwords do not match.".to_string());
        has_errors = true;
    }

    if has_errors {
        return render_registration_form(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            form_values,
            field_errors,
            Some("Please correct the highlighted fields.".to_string()),
        )
        .await;
    }

    match find_user_by_username(state.db(), &normalized_username).await {
        Ok(Some(_)) => {
            let mut field_errors = RegistrationFieldErrors::default();
            field_errors.username = Some("That username is already taken.".to_string());
            return render_registration_form(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                form_values,
                field_errors,
                Some("We couldn't create your account.".to_string()),
            )
            .await;
        }
        Ok(None) => {}
        Err(err) => {
            error!(target: "auth", %err, "failed to check username uniqueness during registration");
            return server_error_response();
        }
    }

    let password_hash = match hash_password(
        &form.password,
        state.config().security.password_pepper.as_deref(),
    )
    .await
    {
        Ok(hash) => hash,
        Err(err) => {
            error!(target: "auth", %err, "failed to hash password during registration");
            return server_error_response();
        }
    };

    if let Err(err) =
        users::create_user(state.db(), &normalized_username, &password_hash, false).await
    {
        if is_unique_violation(&err) {
            let mut field_errors = RegistrationFieldErrors::default();
            field_errors.username = Some("That username is already taken.".to_string());
            return render_registration_form(
                &state,
                &session,
                StatusCode::UNPROCESSABLE_ENTITY,
                form_values,
                field_errors,
                Some("We couldn't create your account.".to_string()),
            )
            .await;
        }

        error!(target: "auth", %err, "failed to create user during registration");
        return server_error_response();
    }

    let user = match find_user_by_username(state.db(), &normalized_username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            error!(
                target: "auth",
                username = %normalized_username,
                "newly created user missing during registration lookup"
            );
            return server_error_response();
        }
        Err(err) => {
            error!(target: "auth", %err, "failed to reload user after registration");
            return server_error_response();
        }
    };

    if let Err(err) = touch_user_login(state.db(), user.id).await {
        warn!(target: "auth", %err, user_id = user.id, "failed to update last login after registration");
    }

    if let Err(err) = session.cycle_id().await {
        error!(target: "auth", %err, "failed to cycle session ID after registration");
        return server_error_response();
    }

    let session_user = SessionUser::new(user.id, user.username.clone(), user.is_admin);
    if let Err(err) = store_user(&session, &session_user).await {
        error!(target: "auth", %err, "failed to store new user in session");
        return server_error_response();
    }

    if let Err(err) = csrf::rotate_csrf_token(&session).await {
        error!(target: "csrf", %err, "failed to rotate CSRF token after registration");
    }

    info!(target: "auth", user_id = user.id, username = %user.username, "user registered successfully");

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

async fn render_registration_form(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    form: RegistrationFormValues,
    field_errors: RegistrationFieldErrors,
    general_error: Option<String>,
) -> Response {
    let mut template = RegisterTemplate::new(layout_from_session(state, session, "Register").await)
        .with_form(form)
        .with_field_errors(field_errors);

    if let Some(message) = general_error {
        template = template.with_general_error(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}

async fn registration_closed_response(state: &AppState, session: &Session) -> Response {
    render_registration_form(
        state,
        session,
        StatusCode::FORBIDDEN,
        RegistrationFormValues::default(),
        RegistrationFieldErrors::default(),
        Some("Registration is currently disabled.".to_string()),
    )
    .await
}

async fn registration_rate_limited_response(
    state: &AppState,
    session: &Session,
    form: RegistrationFormValues,
    error: &RateLimitError,
) -> Response {
    let message = match error {
        RateLimitError::Registration(_) => {
            "Too many registration attempts from this IP. Please wait and try again.".to_string()
        }
        _ => "Too many requests right now. Please wait before trying again.".to_string(),
    };

    let mut response = render_registration_form(
        state,
        session,
        StatusCode::TOO_MANY_REQUESTS,
        form,
        RegistrationFieldErrors::default(),
        Some(message),
    )
    .await;

    let retry_after_secs = error.retry_after().as_secs().max(1);
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }

    response
}

async fn render_user_management_page(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    users: Vec<users::UserSummary>,
    add_form: AddUserFormValues,
    add_errors: AddUserFieldErrors,
    general_error: Option<String>,
    success_message: Option<String>,
) -> Response {
    let layout = layout_from_session(state, session, "User management").await;

    let mapped_users = users
        .into_iter()
        .filter_map(map_user_summary_for_admin)
        .collect::<Vec<_>>();

    let mut template = UserManagementTemplate::new(layout, mapped_users)
        .with_add_form(add_form)
        .with_add_errors(add_errors);

    if let Some(message) = general_error {
        template = template.with_general_error(message);
    }

    if let Some(message) = success_message {
        template = template.with_success_message(message);
    }

    (status, HtmlTemplate::new(template)).into_response()
}

async fn fetch_user_rows(state: &AppState) -> Result<Vec<users::UserSummary>, Response> {
    match users::list_users(state.db()).await {
        Ok(rows) => Ok(rows),
        Err(err) => {
            error!(target: "users", %err, "failed to load users for management page");
            Err(server_error_response())
        }
    }
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
        RateLimitError::Registration(_) => {
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
    let mut fallback = String::with_capacity(filename.len());
    let mut contains_non_ascii = false;

    for ch in filename.chars() {
        if matches!(ch, ' '..='~') && ch != '"' && ch != '\\' {
            fallback.push(ch);
        } else {
            contains_non_ascii |= !ch.is_ascii();
            fallback.push('_');
        }
    }

    if fallback.is_empty() {
        fallback.push_str("download.bin");
    }

    if fallback.len() > 255 {
        fallback.truncate(255);
    }

    let truncated_original: String = filename.chars().take(255).collect();
    let needs_extended = contains_non_ascii || truncated_original.len() != filename.len();

    let header_value = if needs_extended {
        let encoded = encode_filename_for_rfc5987(&truncated_original);
        format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
    } else {
        format!("attachment; filename=\"{fallback}\"")
    };

    HeaderValue::from_str(&header_value).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

fn encode_filename_for_rfc5987(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());

    for byte in input.as_bytes() {
        match *byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'&'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~' => encoded.push(*byte as char),
            _ => {
                encoded.push('%');
                encoded.push_str(&format!("{:02X}", byte));
            }
        }
    }

    encoded
}

#[derive(Debug, Default, Deserialize)]
struct HomeQueryParams {
    #[serde(default)]
    flash: Option<String>,
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
struct DeleteFileForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct PasteForm {
    csrf_token: String,
    title: String,
    language: String,
    expires_in: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct SettingsFormSubmission {
    csrf_token: String,
    ui_brand_name: String,
    max_file_size_bytes: String,
    default_expiration_hours: String,
    direct_link_ttl_minutes: String,
    allow_anonymous_download: Option<String>,
    allow_registration: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogoutForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct RegistrationForm {
    csrf_token: String,
    username: String,
    password: String,
    password_confirm: String,
}

#[derive(Debug, Deserialize)]
struct AddUserFormSubmission {
    csrf_token: String,
    username: String,
    password: String,
    password_confirm: String,
    is_admin: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResetUserPasswordForm {
    csrf_token: String,
    new_password: String,
    confirm_password: String,
}

#[derive(Debug, Deserialize)]
struct DeleteUserForm {
    csrf_token: String,
}
