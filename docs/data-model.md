# Data model

SQLite with SQLx. Timestamps are UTC ISO-8601 or integer epoch seconds (use integer for speed/space). Use `INTEGER` for epochs.

## Tables

### users
- id INTEGER PRIMARY KEY AUTOINCREMENT
- username TEXT UNIQUE NOT NULL
- password_hash TEXT NOT NULL  -- argon2id encoded string
- is_admin INTEGER NOT NULL DEFAULT 0
- created_at INTEGER NOT NULL  -- epoch seconds
- last_login_at INTEGER        -- epoch seconds

Indexes:
- UNIQUE(username)

### files
- id TEXT PRIMARY KEY          -- e.g., ULID/cuid2
- owner_user_id INTEGER        -- nullable if uploaded by admin, else references users(id)
- code TEXT UNIQUE NOT NULL    -- human-friendly short code
- original_name TEXT NOT NULL
- stored_path TEXT NOT NULL    -- relative path under storage_root
- size_bytes INTEGER NOT NULL
- content_type TEXT            -- best-effort
- checksum TEXT                -- optional SHA-256 hex
- created_at INTEGER NOT NULL
- expires_at INTEGER           -- null means never expires (discouraged)
- last_accessed_at INTEGER

Indexes:
- UNIQUE(code)
- INDEX(expires_at)

### settings
- id INTEGER PRIMARY KEY CHECK (id = 1)  -- singleton row
- max_file_size_bytes INTEGER NOT NULL DEFAULT 52428800  -- 50MB
- default_expiration_hours INTEGER NOT NULL DEFAULT 168  -- 7 days
- direct_link_ttl_minutes INTEGER NOT NULL DEFAULT 10
- allow_anonymous_download INTEGER NOT NULL DEFAULT 1
- ui_brand_name TEXT NOT NULL DEFAULT 'Simple File Server'
- updated_at INTEGER NOT NULL

Seed a default row on startup if missing.

### sessions (by tower-sessions-sqlx)
Managed by the library. We'll apply the provided migration for SQLite:
- id TEXT PRIMARY KEY
- data BLOB NOT NULL
- expires_at INTEGER

## Code generation strategy
- `files.code`: use `nanoid` with an alphabet of uppercase letters and digits, grouped for readability (e.g., 4-4).
- `files.id`: use `ulid` or `cuid2` for sortable uniqueness.

## Storage paths
- Base: `storage_root`
- Partitioning: `storage_root/YYYY/MM/DD/<file_id>`
- `stored_path` records the relative path `YYYY/MM/DD/<file_id>`

## Migrations outline
1. Create users, files, settings
2. Create sessions via tower-sessions-sqlx migration
3. Indices (code unique, expires_at index)

We will use `sqlx::migrate!()` to apply migrations at startup.