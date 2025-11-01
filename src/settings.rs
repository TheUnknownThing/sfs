use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

const DEFAULT_CACHE_TTL_SECS: u64 = 10;

#[derive(Debug, Clone)]
pub struct AppSettings {
    pub max_file_size_bytes: u64,
    pub default_expiration_hours: u64,
    pub direct_link_ttl_minutes: u64,
    pub allow_anonymous_download: bool,
    pub ui_brand_name: String,
    #[allow(dead_code)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct SettingsUpdate {
    pub max_file_size_bytes: u64,
    pub default_expiration_hours: u64,
    pub direct_link_ttl_minutes: u64,
    pub allow_anonymous_download: bool,
    pub ui_brand_name: String,
}

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("settings record is missing")]
    Missing,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("settings data invalid: {0}")]
    InvalidData(&'static str),
}

struct CachedEntry {
    value: Arc<AppSettings>,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct SettingsService {
    pool: SqlitePool,
    cache: Arc<RwLock<Option<CachedEntry>>>,
    ttl: Duration,
}

impl SettingsService {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(None)),
            ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        }
    }

    pub async fn current(&self) -> Result<Arc<AppSettings>, SettingsError> {
        {
            let cache_guard = self.cache.read().await;
            if let Some(entry) = cache_guard.as_ref() {
                if entry.expires_at > Instant::now() {
                    return Ok(entry.value.clone());
                }
            }
        }

        self.refresh().await
    }

    pub async fn refresh(&self) -> Result<Arc<AppSettings>, SettingsError> {
        let mut cache_guard = self.cache.write().await;
        if let Some(entry) = cache_guard.as_ref() {
            if entry.expires_at > Instant::now() {
                return Ok(entry.value.clone());
            }
        }

        let fresh = self.load_from_db().await?;
        let shared = Arc::new(fresh);
        let expires_at = Instant::now() + self.ttl;
        *cache_guard = Some(CachedEntry {
            value: shared.clone(),
            expires_at,
        });

        Ok(shared)
    }

    pub async fn update(&self, update: SettingsUpdate) -> Result<Arc<AppSettings>, SettingsError> {
        let max_file_size = i64::try_from(update.max_file_size_bytes).map_err(|_| {
            SettingsError::InvalidData("max_file_size_bytes exceeds supported range")
        })?;
        let default_expiration = i64::try_from(update.default_expiration_hours).map_err(|_| {
            SettingsError::InvalidData("default_expiration_hours exceeds supported range")
        })?;
        let direct_ttl = i64::try_from(update.direct_link_ttl_minutes).map_err(|_| {
            SettingsError::InvalidData("direct_link_ttl_minutes exceeds supported range")
        })?;
        let allow_download = if update.allow_anonymous_download {
            1
        } else {
            0
        };

        sqlx::query!(
            r#"
            UPDATE settings
            SET
                max_file_size_bytes = ?,
                default_expiration_hours = ?,
                direct_link_ttl_minutes = ?,
                allow_anonymous_download = ?,
                ui_brand_name = ?,
                updated_at = strftime('%s', 'now')
            WHERE id = 1
            "#,
            max_file_size,
            default_expiration,
            direct_ttl,
            allow_download,
            update.ui_brand_name,
        )
        .execute(&self.pool)
        .await?;

        let fresh = self.load_from_db().await?;
        let shared = Arc::new(fresh);
        let expires_at = Instant::now() + self.ttl;

        let mut cache_guard = self.cache.write().await;
        *cache_guard = Some(CachedEntry {
            value: shared.clone(),
            expires_at,
        });

        Ok(shared)
    }

    async fn load_from_db(&self) -> Result<AppSettings, SettingsError> {
        let record = sqlx::query!(
            r#"
            SELECT
                max_file_size_bytes,
                default_expiration_hours,
                direct_link_ttl_minutes,
                allow_anonymous_download,
                ui_brand_name,
                updated_at
            FROM settings
            WHERE id = 1
            "#
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(record) = record else {
            return Err(SettingsError::Missing);
        };

        let max_file_size_bytes = u64::try_from(record.max_file_size_bytes).map_err(|_| {
            SettingsError::InvalidData("max_file_size_bytes stored value is negative")
        })?;
        let default_expiration_hours =
            u64::try_from(record.default_expiration_hours).map_err(|_| {
                SettingsError::InvalidData("default_expiration_hours stored value is negative")
            })?;
        let direct_link_ttl_minutes =
            u64::try_from(record.direct_link_ttl_minutes).map_err(|_| {
                SettingsError::InvalidData("direct_link_ttl_minutes stored value is negative")
            })?;

        Ok(AppSettings {
            max_file_size_bytes,
            default_expiration_hours,
            direct_link_ttl_minutes,
            allow_anonymous_download: record.allow_anonymous_download != 0,
            ui_brand_name: record.ui_brand_name,
            updated_at: record.updated_at,
        })
    }
}
