use crate::{config::AppConfig, rate_limit::LoginRateLimiter};
use sqlx::SqlitePool;
use std::sync::Arc;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: SqlitePool,
    /// Application configuration
    pub config: Arc<AppConfig>,
    /// Shared login rate limiter
    pub login_rate_limiter: Arc<LoginRateLimiter>,
}

impl AppState {
    /// Create a new AppState instance
    pub fn new(db: SqlitePool, config: AppConfig) -> Self {
        Self {
            db,
            config: Arc::new(config),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
        }
    }

    /// Get a reference to the database pool
    pub fn db(&self) -> &SqlitePool {
        &self.db
    }

    /// Get a reference to the application configuration
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Access the login rate limiter instance
    pub fn login_rate_limiter(&self) -> &LoginRateLimiter {
        &self.login_rate_limiter
    }
}
