use crate::{
    config::AppConfig,
    direct_links::{DownloadTokenService, TokenError as DownloadTokenError},
    rate_limit::{
        DirectDownloadRateLimiter, DirectLinkRateLimiter, LoginRateLimiter, RegistrationRateLimiter,
    },
    settings::SettingsService,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use thiserror::Error;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: SqlitePool,
    /// Application configuration
    pub config: Arc<AppConfig>,
    /// Shared login rate limiter
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    /// Direct link generation rate limiter
    pub direct_link_rate_limiter: Arc<DirectLinkRateLimiter>,
    /// Direct download rate limiter
    pub direct_download_rate_limiter: Arc<DirectDownloadRateLimiter>,
    /// Registration rate limiter
    pub registration_rate_limiter: Arc<RegistrationRateLimiter>,
    /// Service responsible for issuing and validating download tokens
    pub download_tokens: Arc<DownloadTokenService>,
    /// Cached application settings loaded from the database
    pub settings: Arc<SettingsService>,
}

#[derive(Debug, Error)]
pub enum AppStateError {
    #[error("download token configuration error: {0}")]
    DownloadToken(#[from] DownloadTokenError),
}

impl AppState {
    /// Create a new AppState instance
    pub fn new(db: SqlitePool, config: AppConfig) -> Result<Self, AppStateError> {
        let download_tokens =
            DownloadTokenService::from_config(&config.security.download_token_secret)?;
        let settings_service = SettingsService::new(db.clone());

        Ok(Self {
            db,
            config: Arc::new(config),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            direct_link_rate_limiter: Arc::new(DirectLinkRateLimiter::new()),
            direct_download_rate_limiter: Arc::new(DirectDownloadRateLimiter::new()),
            registration_rate_limiter: Arc::new(RegistrationRateLimiter::new()),
            download_tokens: Arc::new(download_tokens),
            settings: Arc::new(settings_service),
        })
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

    /// Access the direct link rate limiter
    pub fn direct_link_rate_limiter(&self) -> &DirectLinkRateLimiter {
        &self.direct_link_rate_limiter
    }

    /// Access the direct download rate limiter
    pub fn direct_download_rate_limiter(&self) -> &DirectDownloadRateLimiter {
        &self.direct_download_rate_limiter
    }

    /// Access the registration rate limiter
    pub fn registration_rate_limiter(&self) -> &RegistrationRateLimiter {
        &self.registration_rate_limiter
    }

    /// Access the download token service
    pub fn download_tokens(&self) -> &DownloadTokenService {
        &self.download_tokens
    }

    /// Access the application settings service
    pub fn settings(&self) -> &SettingsService {
        self.settings.as_ref()
    }
}
