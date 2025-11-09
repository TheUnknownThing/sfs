# Data model

SQLite with SQLx. Timestamps are stored as integer epoch seconds for speed/space efficiency.

## Tables

### users
- id INTEGER PRIMARY KEY AUTOINCREMENT
- username TEXT UNIQUE NOT NULL
- password_hash TEXT NOT NULL  -- argon2id encoded string with optional pepper
- is_admin INTEGER NOT NULL DEFAULT 0
- created_at INTEGER NOT NULL  -- epoch seconds
- last_login_at INTEGER        -- epoch seconds

Indexes:
- UNIQUE(username)

### files
- id TEXT PRIMARY KEY          -- ULID for sortable uniqueness
- owner_user_id INTEGER        -- nullable if uploaded by admin, else references users(id)
- code TEXT UNIQUE NOT NULL    -- human-friendly short code (XXXX-XXXX format)
- original_name TEXT NOT NULL
- stored_path TEXT NOT NULL    -- relative path under storage_root (YYYY/MM/DD/<file_id>)
- size_bytes INTEGER NOT NULL
- content_type TEXT            -- best-effort detection
- checksum TEXT                -- SHA-256 hex for integrity verification
- created_at INTEGER NOT NULL
- expires_at INTEGER           -- null means never expires (discouraged)
- last_accessed_at INTEGER

Foreign Keys:
- FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL

Indexes:
- UNIQUE(code)
- INDEX(expires_at)
- INDEX(owner_user_id)

### settings
- id INTEGER PRIMARY KEY CHECK (id = 1)  -- singleton row
- max_file_size_bytes INTEGER NOT NULL DEFAULT 52428800  -- 50MB
- default_expiration_hours INTEGER NOT NULL DEFAULT 168  -- 7 days
- direct_link_ttl_minutes INTEGER NOT NULL DEFAULT 10
- allow_anonymous_download INTEGER NOT NULL DEFAULT 1
- allow_registration INTEGER NOT NULL DEFAULT 0
- ui_brand_name TEXT NOT NULL DEFAULT 'Simple File Server'
- preview_max_size_bytes INTEGER NOT NULL DEFAULT 1048576  -- 1MB
- updated_at INTEGER NOT NULL

Seed a default row on startup if missing.

### tower_sessions (by tower-sessions-sqlx)
Managed by the library. Applied via tower-sessions-sqlx migration:
- id TEXT PRIMARY KEY
- data BLOB NOT NULL
- expiry_date INTEGER

Indexes:
- INDEX(expiry_date)

## Code generation strategy
- `files.code`: use `nanoid` with alphabet `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no O/0/I/1) in 4-4 format
- `files.id`: use `ulid` for sortable uniqueness and time-ordered IDs

## Storage paths
- Base: `storage_root`
- Partitioning: `storage_root/YYYY/MM/DD/<file_id>`
- `stored_path` records the relative path `YYYY/MM/DD/<file_id>`
- Both files and pastes use the same storage structure

## Paste support
Text pastes are stored as files with:
- Content type based on selected language (e.g., `text/x-rust` for Rust)
- File extension matching the language (e.g., `.rs` for Rust)
- Title used as filename with appropriate extension

## Migrations
Applied automatically via `sqlx::migrate!()` at startup:
1. Create users, files, settings tables
2. Create tower_sessions table via tower-sessions-sqlx migration
3. Create all necessary indexes
4. Set PRAGMA settings (WAL mode, foreign keys)

## Data integrity
- All files/pastes include SHA-256 checksums
- Foreign key constraints ensure referential integrity
- Unique constraints prevent duplicate codes and usernames