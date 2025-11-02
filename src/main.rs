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
mod server;
mod sessions;
mod settings;
mod templates;
mod users;

use std::net::SocketAddr;

use app_state::AppState;
use auth::{bootstrap_admin_user, AuthError};
use axum::Router;
use config::AppConfig;
use database::initialize_database;
use logging::init_logging;
use server::router::build_router;
use thiserror::Error;
use tokio::net::TcpListener;
use tower_sessions::{cookie::SameSite, SessionManagerLayer};
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
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),
    #[error("Application state error: {0}")]
    AppState(#[from] app_state::AppStateError),
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    init_logging().map_err(|e| AppError::Logging(e.to_string()))?;
    info!("Starting Simple File Server");

    let config = AppConfig::load()?;
    let db_pool = initialize_database(&config).await?;
    bootstrap_admin_user(&db_pool, &config).await?;

    let session_store = SqliteStore::new(db_pool.clone());
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(config.security.cookie_secure)
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_path("/")
        .with_name("__Host.sfs.sid");

    let app_state = AppState::new(db_pool, config.clone())?;
    cleanup::spawn_cleanup_job(app_state.clone());

    let app: Router = build_router(app_state, session_layer);

    let addr = SocketAddr::new(config.server.bind_addr.parse()?, config.server.port);
    info!("Starting server on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
