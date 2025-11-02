use crate::config::AppConfig;
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::str::FromStr;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Database connection error: {0}")]
    Connection(#[from] sqlx::Error),
    #[error("Database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("Invalid database URL: {0}")]
    InvalidUrl(String),
}

/// Initialize database connection pool with proper SQLite configuration
pub async fn create_pool(config: &AppConfig) -> Result<SqlitePool, DatabaseError> {
    info!("Initializing database connection pool");

    // Parse the database URL and configure SQLite options
    let mut connect_options = SqliteConnectOptions::from_str(&config.database.url)
        .map_err(|e| DatabaseError::InvalidUrl(format!("Invalid database URL: {}", e)))?;

    // Configure SQLite with WAL mode and busy timeout
    connect_options = connect_options
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5))
        .create_if_missing(true);

    // Create connection pool with configured size
    // Note: SQLite doesn't support max_connections in the same way as other databases
    // The connection pool will manage connections based on demand
    let pool = SqlitePool::connect_with(connect_options).await?;

    info!(
        "Database connection pool created with max connections: {}",
        config.database.max_connections
    );

    Ok(pool)
}

/// Bootstrap default settings if they don't exist
pub async fn bootstrap_settings(pool: &SqlitePool) -> Result<(), DatabaseError> {
    info!("Bootstrapping default settings");

    // Check if settings already exist
    let settings_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM settings WHERE id = 1")
        .fetch_one(pool)
        .await?;

    if settings_count == 0 {
        info!("Inserting default settings");
        sqlx::query!(
            r#"
            INSERT INTO settings (
                id, max_file_size_bytes, default_expiration_hours, 
                direct_link_ttl_minutes, allow_anonymous_download, 
                allow_registration,
                ui_brand_name, updated_at
            ) VALUES (
                1, 52428800, 168, 10, 1, 0, 'Simple File Server', 
                (strftime('%s', 'now'))
            )
            "#
        )
        .execute(pool)
        .await?;
    } else {
        info!("Settings already exist, skipping bootstrap");
    }

    Ok(())
}

/// Initialize database with connection pool, migrations, and settings
pub async fn initialize_database(config: &AppConfig) -> Result<SqlitePool, DatabaseError> {
    // Create connection pool
    let pool = create_pool(config).await?;

    // Create tables manually since we're not using migrations for now
    create_tables(&pool).await?;

    // Bootstrap settings
    bootstrap_settings(&pool).await?;

    info!("Database initialization completed successfully");

    Ok(pool)
}

/// Create all required tables manually
async fn create_tables(pool: &SqlitePool) -> Result<(), DatabaseError> {
    info!("Creating database tables");

    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            last_login_at INTEGER
        )
        "#,
    )
    .execute(pool)
    .await?;

    ensure_users_table_schema(pool).await?;

    // Create files table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            owner_user_id INTEGER,
            code TEXT UNIQUE NOT NULL,
            original_name TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            content_type TEXT,
            checksum TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            last_accessed_at INTEGER,
            FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create settings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            max_file_size_bytes INTEGER NOT NULL DEFAULT 52428800,
            default_expiration_hours INTEGER NOT NULL DEFAULT 168,
            direct_link_ttl_minutes INTEGER NOT NULL DEFAULT 10,
            allow_anonymous_download INTEGER NOT NULL DEFAULT 1,
            allow_registration INTEGER NOT NULL DEFAULT 0,
            ui_brand_name TEXT NOT NULL DEFAULT 'Simple File Server',
            updated_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    ensure_settings_table_schema(pool).await?;

    // Drop and recreate tower_sessions table for session store with correct schema
    sqlx::query("DROP TABLE IF EXISTS tower_sessions")
        .execute(pool)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE tower_sessions (
            id TEXT PRIMARY KEY,
            data BLOB NOT NULL,
            expiry_date INTEGER
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indices
    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_code ON files(code)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files(expires_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_owner_user_id ON files(owner_user_id)")
        .execute(pool)
        .await?;

    // Create index for tower_sessions
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_tower_sessions_expiry_date ON tower_sessions(expiry_date)",
    )
    .execute(pool)
    .await?;

    info!("Database tables created successfully");

    Ok(())
}

/// Ensure the users table has the expected columns when upgrading existing databases.
async fn ensure_users_table_schema(pool: &SqlitePool) -> Result<(), DatabaseError> {
    let has_is_admin_column: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM pragma_table_info('users') WHERE name = 'is_admin' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    if has_is_admin_column.is_none() {
        info!("Adding is_admin column to users table");
        sqlx::query("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await?;

        sqlx::query("UPDATE users SET is_admin = 1 WHERE username = 'admin'")
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Ensure the settings table has the expected columns when upgrading existing databases.
async fn ensure_settings_table_schema(pool: &SqlitePool) -> Result<(), DatabaseError> {
    let has_allow_registration: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM pragma_table_info('settings') WHERE name = 'allow_registration' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    if has_allow_registration.is_none() {
        info!("Adding allow_registration column to settings table");
        sqlx::query(
            "ALTER TABLE settings ADD COLUMN allow_registration INTEGER NOT NULL DEFAULT 0",
        )
        .execute(pool)
        .await?;
    }

    Ok(())
}
