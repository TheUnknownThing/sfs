use crate::config::AppConfig;
use sqlx::SqlitePool;
use std::sync::Arc;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: SqlitePool,
    /// Application configuration
    pub config: Arc<AppConfig>,
}

impl AppState {
    /// Create a new AppState instance
    pub fn new(db: SqlitePool, config: AppConfig) -> Self {
        Self {
            db,
            config: Arc::new(config),
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
}
