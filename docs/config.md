# Configuration

Centralized configuration combines environment variables, a default config schema, and persisted settings in the DB. Precedence: env > DB settings > hard-coded defaults.

## Environment variables
- SERVER_BIND_ADDR: default `0.0.0.0`
- SERVER_PORT: default `8080`
- RUST_LOG: default `info,simple_file_server=info`
- DATABASE_URL: e.g. `sqlite:///data/app.db?mode=rwc&cache=shared`
- DATABASE_MAX_CONNECTIONS: default `10`
- STORAGE_ROOT: e.g. `/data/storage` (must be writable)
- MAX_FILE_SIZE_BYTES: default `52428800` (50 MB)
- SESSION_KEY: base64 or hex 32-byte secret for session encryption/signing (generated securely)
- DOWNLOAD_TOKEN_SECRET: 32+ random bytes, base64 or hex
- COOKIE_SECURE: `true`/`false` (force true in prod)
- TRUSTED_PROXIES: comma-separated CIDRs (e.g., `127.0.0.1/32,10.0.0.0/8`)
- PASSWORD_PEPPER: optional global pepper for hashing
- SESSION_COOKIE_NAME: default `sfs_session`
- SESSION_MAX_AGE_HOURS: default `24`
- DEFAULT_EXPIRATION_HOURS: default `168` (7 days)
- DIRECT_LINK_TTL_MINUTES: default `10`
- UI_BRAND_NAME: default `Simple File Server`
- BOOTSTRAP_ADMIN_USERNAME / BOOTSTRAP_ADMIN_PASSWORD: one-time bootstrap

## Database Settings (overridable in DB via `/settings`)
- max_file_size_bytes: default `52428800` (50 MB)
- default_expiration_hours: default `168` (7 days)
- direct_link_ttl_minutes: default `10`
- allow_anonymous_download: default `1` (true)
- allow_registration: default `0` (false)
- ui_brand_name: default `Simple File Server`
- preview_max_size_bytes: default `1048576` (1 MB)

## Validation rules
- STORAGE_ROOT must exist or be creatable; ensure sufficient disk space.
- MAX_FILE_SIZE_BYTES: 1 MB–5 GB (hard cap); enforce on server and reverse proxy.
- DEFAULT_EXPIRATION_HOURS: 1–2160 (90 days).
- DIRECT_LINK_TTL_MINUTES: 1–1440.
- SESSION_KEY and DOWNLOAD_TOKEN_SECRET must be 32+ random bytes.
- DATABASE_MAX_CONNECTIONS: 1–100.

## Example .env
```
SERVER_BIND_ADDR=0.0.0.0
SERVER_PORT=8080
RUST_LOG=info,simple_file_server=info
DATABASE_URL=sqlite:///data/app.db?mode=rwc&cache=shared
DATABASE_MAX_CONNECTIONS=10
STORAGE_ROOT=/data/storage
MAX_FILE_SIZE_BYTES=104857600
SESSION_KEY=base64:WmVkM0pYME1hZ0ZyQ29vbFNlY3JldEJpdGVzMTIzNA==
DOWNLOAD_TOKEN_SECRET=base64:bS9wS1l1d0pzcG1SSG9vQmFyU2VjcmV0S2V5LTIzNDU2
COOKIE_SECURE=true
TRUSTED_PROXIES=127.0.0.1/32
PASSWORD_PEPPER=
SESSION_COOKIE_NAME=sfs_session
SESSION_MAX_AGE_HOURS=24
DEFAULT_EXPIRATION_HOURS=168
DIRECT_LINK_TTL_MINUTES=10
UI_BRAND_NAME=Team Share
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=secure-password
```

## Library configuration
- `config` crate:
  - Sources: defaults -> environment variables -> `.env` via `dotenvy`.
  - Map to `AppConfig` struct; merge with `settings` row from DB during startup.
- `tracing` + `tracing-subscriber`:
  - Enable JSON logs in prod: env `LOG_JSON=true` optional.
- `sqlx` (SQLite):
  - Use `SqliteConnectOptions` with `journal_mode=WAL`, `busy_timeout=5s`.
  - Pool size: configurable via `DATABASE_MAX_CONNECTIONS`.
- Upload limits:
  - Apply Axum `RequestBodyLimitLayer` set to `MAX_FILE_SIZE_BYTES + overhead` on `/upload` and `/paste`.

## Runtime overrides in UI
- `/settings` updates `settings` table; changes take effect immediately for new requests.
- Settings are cached in `AppState` with automatic refresh to avoid constant DB hits.

## Forwarded headers
- TRUSTED_PROXIES is parsed but not yet implemented in middleware.

## Secrets management
- Prefer container secrets or platform-provided secret stores in prod.
- Rotate `DOWNLOAD_TOKEN_SECRET` with overlap: support verifying with current and previous secret for a short window.
- Base64-encoded secrets should be prefixed with `base64:`.

## Configuration structure
The application uses a nested configuration structure:
- `server`: bind address and port
- `database`: URL and connection pool settings
- `storage`: root directory and file size limits
- `security`: session keys, download token secret, trusted proxies, password pepper
- `session`: cookie name and max age
- `defaults`: file expiration and link TTL
- `ui`: brand name and display settings
