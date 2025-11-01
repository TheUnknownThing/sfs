mod app_state;
mod config;
mod database;
mod logging;
mod templates;

use app_state::AppState;
use axum::{extract::State, routing::get, Router};
use config::AppConfig;
use database::initialize_database;
use logging::init_logging;
use std::net::SocketAddr;
use templates::{HomeTemplate, HtmlTemplate, LayoutContext, LoginTemplate};
use thiserror::Error;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tower_sessions::{cookie::SameSite, Session, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;
use tracing::info;

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
        .route("/login", get(login_handler))
        .route("/test-session", get(test_session))
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
    axum::serve(listener, app).await?;

    Ok(())
}

/// Test endpoint to trigger session creation
async fn test_session(session: Session) -> &'static str {
    // Access the session to trigger session creation
    let _ = session.insert("test", "value").await;
    "Session created successfully"
}

async fn home_handler(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    let layout = LayoutContext::from_state(&state, "Home");
    HtmlTemplate::new(HomeTemplate::new(layout))
}

async fn login_handler(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    let layout = LayoutContext::from_state(&state, "Sign in");
    HtmlTemplate::new(LoginTemplate::new(layout))
}
