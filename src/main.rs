mod app_state;
mod auth;
mod config;
mod csrf;
mod database;
mod logging;
mod rate_limit;
mod sessions;
mod templates;

use app_state::AppState;
use auth::{
    bootstrap_admin_user, find_user_by_username, hash_password, normalize_username,
    randomized_backoff, touch_user_login, update_password_hash, verify_password, AuthError,
};
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use config::AppConfig;
use database::initialize_database;
use logging::init_logging;
use rate_limit::RateLimitError;
use serde::Deserialize;
use sessions::{clear_user, current_user, store_user, SessionUser};
use std::net::SocketAddr;
use templates::{HomeTemplate, HtmlTemplate, LayoutContext, LoginTemplate};
use thiserror::Error;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tower_sessions::{cookie::SameSite, Session, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;
use tracing::{error, info, warn};

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
}

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
    let app_state = AppState::new(db_pool, config.clone());

    // Create router with middleware in correct order: Trace -> Sessions -> Routes
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_form_handler).post(login_submit_handler))
        .route("/logout", post(logout_handler))
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
    let layout = layout_from_session(&state, &session, "Home").await;
    HtmlTemplate::new(HomeTemplate::new(layout))
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
            let layout = LayoutContext::from_state(&state, "Sign in");
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
            LayoutContext::from_state(state, title)
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

#[derive(Debug, Deserialize)]
struct LoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LogoutForm {
    csrf_token: String,
}
