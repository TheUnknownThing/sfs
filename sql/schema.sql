-- Schema for Simple File Server (used by sqlx compile-time checks and to create an initial DB)
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER
);

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
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_file_size_bytes INTEGER NOT NULL DEFAULT 52428800,
    default_expiration_hours INTEGER NOT NULL DEFAULT 168,
    direct_link_ttl_minutes INTEGER NOT NULL DEFAULT 10,
    allow_anonymous_download INTEGER NOT NULL DEFAULT 1,
    allow_registration INTEGER NOT NULL DEFAULT 0,
    ui_brand_name TEXT NOT NULL DEFAULT 'Simple File Server',
    preview_max_size_bytes INTEGER NOT NULL DEFAULT 1048576,
    updated_at INTEGER NOT NULL
);

DROP TABLE IF EXISTS tower_sessions;

CREATE TABLE IF NOT EXISTS tower_sessions (
    id TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    expiry_date INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE UNIQUE INDEX IF NOT EXISTS idx_files_code ON files(code);
CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files(expires_at);
CREATE INDEX IF NOT EXISTS idx_files_owner_user_id ON files(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_tower_sessions_expiry_date ON tower_sessions(expiry_date);
