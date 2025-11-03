use base64::engine::general_purpose;
use base64::Engine;
use config::{Config, ConfigError as BaseConfigError, File};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct StorageConfig {
    pub root: PathBuf,
    pub max_file_size_bytes: u64,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct SecurityConfig {
    pub session_key: String,
    pub download_token_secret: String,
    pub cookie_secure: bool,
    pub trusted_proxies: Vec<String>,
    pub password_pepper: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct SessionConfig {
    pub cookie_name: String,
    pub max_age_hours: u64,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct DefaultsConfig {
    pub file_expiration_hours: u64,
    pub direct_link_ttl_minutes: u64,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct UiConfig {
    pub brand_name: String,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
    pub session: SessionConfig,
    pub defaults: DefaultsConfig,
    pub ui: UiConfig,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Configuration error: {0}")]
    Config(#[from] BaseConfigError),
    #[error("Storage directory error: {0}")]
    StorageDir(String),
    #[error("Invalid configuration: {0}")]
    Validation(String),
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        dotenvy::dotenv().ok();

        let mut settings = Config::builder();

        // Add default settings
        settings = settings.add_source(config::Config::try_from(&AppConfig::default())?);

        // Add config file if it exists
        settings = settings.add_source(File::with_name("config").required(false));

        // Add environment variables with explicit mapping for nested fields
        settings = settings
            // Server settings
            .set_override(
                "server.bind_addr",
                std::env::var("SERVER_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string()),
            )?
            .set_override(
                "server.port",
                std::env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse::<u16>()
                    .unwrap_or(8080),
            )?
            // Database settings
            .set_override(
                "database.url",
                std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                    "sqlite:///data/app.db?mode=rwc&cache=shared".to_string()
                }),
            )?
            .set_override(
                "database.max_connections",
                std::env::var("DATABASE_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse::<u32>()
                    .unwrap_or(10),
            )?
            // Storage settings
            .set_override(
                "storage.root",
                std::env::var("STORAGE_ROOT").unwrap_or_else(|_| "./data/storage".to_string()),
            )?
            .set_override(
                "storage.max_file_size_bytes",
                std::env::var("MAX_FILE_SIZE_BYTES")
                    .unwrap_or_else(|_| "52428800".to_string())
                    .parse::<u64>()
                    .unwrap_or(52428800),
            )?
            // Security settings
            .set_override(
                "security.session_key",
                std::env::var("SESSION_KEY").unwrap_or_else(|_| "".to_string()),
            )?
            .set_override(
                "security.download_token_secret",
                std::env::var("DOWNLOAD_TOKEN_SECRET").unwrap_or_else(|_| "".to_string()),
            )?
            .set_override(
                "security.cookie_secure",
                std::env::var("COOKIE_SECURE")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse::<bool>()
                    .unwrap_or(false),
            )?
            .set_override(
                "security.trusted_proxies",
                std::env::var("TRUSTED_PROXIES")
                    .unwrap_or_else(|_| "127.0.0.1/32".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<String>>(),
            )?
            .set_override(
                "security.password_pepper",
                std::env::var("PASSWORD_PEPPER").ok(),
            )?
            // Session settings
            .set_override(
                "session.cookie_name",
                std::env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "sfs_session".to_string()),
            )?
            .set_override(
                "session.max_age_hours",
                std::env::var("SESSION_MAX_AGE_HOURS")
                    .unwrap_or_else(|_| "24".to_string())
                    .parse::<u64>()
                    .unwrap_or(24),
            )?
            // Defaults settings
            .set_override(
                "defaults.file_expiration_hours",
                std::env::var("DEFAULT_EXPIRATION_HOURS")
                    .unwrap_or_else(|_| "168".to_string())
                    .parse::<u64>()
                    .unwrap_or(168),
            )?
            .set_override(
                "defaults.direct_link_ttl_minutes",
                std::env::var("DIRECT_LINK_TTL_MINUTES")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse::<u64>()
                    .unwrap_or(10),
            )?
            // UI settings
            .set_override(
                "ui.brand_name",
                std::env::var("UI_BRAND_NAME").unwrap_or_else(|_| "Simple File Server".to_string()),
            )?;

        let settings = settings.build()?;

        let mut config: AppConfig = settings.try_deserialize()?;

        // Validate and normalize configuration
        config.validate()?;

        Ok(config)
    }

    fn validate(&mut self) -> Result<(), ConfigError> {
        // Validate server configuration
        if self.server.port == 0 {
            return Err(ConfigError::Validation(
                "Server port cannot be 0".to_string(),
            ));
        }

        // Validate storage configuration
        if self.storage.max_file_size_bytes < 1024 * 1024 {
            return Err(ConfigError::Validation(
                "MAX_FILE_SIZE_BYTES must be at least 1MB".to_string(),
            ));
        }
        if self.storage.max_file_size_bytes > 5 * 1024 * 1024 * 1024 {
            return Err(ConfigError::Validation(
                "MAX_FILE_SIZE_BYTES cannot exceed 5GB".to_string(),
            ));
        }

        // Ensure storage directory exists or can be created
        if let Err(e) = fs::create_dir_all(&self.storage.root) {
            return Err(ConfigError::StorageDir(format!(
                "Cannot create storage directory {}: {}",
                self.storage.root.display(),
                e
            )));
        }

        // Validate security configuration
        // Handle base64: prefix by checking the actual decoded length
        let session_key_len = if self.security.session_key.starts_with("base64:") {
            general_purpose::STANDARD
                .decode(self.security.session_key.trim_start_matches("base64:"))
                .map_err(|e| {
                    ConfigError::Validation(format!("Invalid base64 for SESSION_KEY: {}", e))
                })?
                .len()
        } else {
            self.security.session_key.len()
        };

        let download_token_len = if self.security.download_token_secret.starts_with("base64:") {
            general_purpose::STANDARD
                .decode(
                    self.security
                        .download_token_secret
                        .trim_start_matches("base64:"),
                )
                .map_err(|e| {
                    ConfigError::Validation(format!(
                        "Invalid base64 for DOWNLOAD_TOKEN_SECRET: {}",
                        e
                    ))
                })?
                .len()
        } else {
            self.security.download_token_secret.len()
        };

        if session_key_len < 32 {
            return Err(ConfigError::Validation(
                "SESSION_KEY must be at least 32 bytes".to_string(),
            ));
        }
        if download_token_len < 32 {
            return Err(ConfigError::Validation(
                "DOWNLOAD_TOKEN_SECRET must be at least 32 bytes".to_string(),
            ));
        }

        // Validate defaults configuration
        if self.defaults.file_expiration_hours < 1 || self.defaults.file_expiration_hours > 2160 {
            return Err(ConfigError::Validation(
                "DEFAULT_EXPIRATION_HOURS must be between 1 and 2160 (90 days)".to_string(),
            ));
        }
        if self.defaults.direct_link_ttl_minutes < 1 || self.defaults.direct_link_ttl_minutes > 1440
        {
            return Err(ConfigError::Validation(
                "DIRECT_LINK_TTL_MINUTES must be between 1 and 1440 (24 hours)".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind_addr: "0.0.0.0".to_string(),
                port: 8080,
            },
            database: DatabaseConfig {
                url: "sqlite:///data/app.db?mode=rwc&cache=shared".to_string(),
                max_connections: 10,
            },
            storage: StorageConfig {
                root: PathBuf::from("./data/storage"),
                max_file_size_bytes: 50 * 1024 * 1024, // 50MB
            },
            security: SecurityConfig {
                session_key: "".to_string(),           // Must be provided by user
                download_token_secret: "".to_string(), // Must be provided by user
                cookie_secure: false,
                trusted_proxies: vec!["127.0.0.1/32".to_string()],
                password_pepper: None,
            },
            session: SessionConfig {
                cookie_name: "sfs_session".to_string(),
                max_age_hours: 24,
            },
            defaults: DefaultsConfig {
                file_expiration_hours: 168, // 7 days
                direct_link_ttl_minutes: 10,
            },
            ui: UiConfig {
                brand_name: "Simple File Server".to_string(),
            },
        }
    }
}
