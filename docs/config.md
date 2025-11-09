# Configuration

Centralized configuration combines environment variables, a default config schema, and persisted settings in the DB. Precedence: env > DB settings > hard-coded defaults.

## Environment variables
- SERVER_BIND_ADDR: default `0.0.0.0`
- SERVER_PORT: default `8080`
- RUST_LOG: default `info,simple_file_server=info`
- DATABASE_URL: e.g. `sqlite:///data/app.db?mode=rwc&cache=shared`
- STORAGE_ROOT: e.g. `/data/storage` (must be writable)
- SESSION_KEY: base64 or hex 32-byte secret for session encryption/signing (generated securely)
- DOWNLOAD_TOKEN_SECRET: 32+ random bytes, base64 or hex
- COOKIE_SECURE: `true`/`false` (force true in prod)
- TRUSTED_PROXIES: comma-separated CIDRs (e.g., `127.0.0.1/32,10.0.0.0/8`)
- PASSWORD_PEPPER: optional global pepper for hashing
- BOOTSTRAP_ADMIN_USERNAME / BOOTSTRAP_ADMIN_PASSWORD: one-time bootstrap

Settings defaults (overridable in DB via `/settings`):
- MAX_FILE_SIZE_BYTES: default `52428800` (50 MB)
- DEFAULT_EXPIRATION_HOURS: default `168` (7 days)
- DIRECT_LINK_TTL_MINUTES: default `10`
- UI_BRAND_NAME: default `Simple File Server`

## Validation rules
- STORAGE_ROOT must exist or be creatable; ensure sufficient disk space.
- MAX_FILE_SIZE_BYTES: 1 MB–5 GB (hard cap); enforce on server and reverse proxy.
- DEFAULT_EXPIRATION_HOURS: 1–2160 (90 days).
- DIRECT_LINK_TTL_MINUTES: 1–1440.
- SESSION_KEY and DOWNLOAD_TOKEN_SECRET must be 32+ random bytes.

## Example .env
```
SERVER_BIND_ADDR=0.0.0.0
SERVER_PORT=8080
RUST_LOG=info,simple_file_server=info
DATABASE_URL=sqlite:///data/app.db?mode=rwc&cache=shared
STORAGE_ROOT=/data/storage
SESSION_KEY=base64:WmVkM0pYME1hZ0ZyQ29vbFNlY3JldEJpdGVzMTIzNA==
DOWNLOAD_TOKEN_SECRET=base64:bS9wS1l1d0pzcG1SSG9vQmFyU2VjcmV0S2V5LTIzNDU2
COOKIE_SECURE=true
TRUSTED_PROXIES=127.0.0.1/32
MAX_FILE_SIZE_BYTES=104857600
DEFAULT_EXPIRATION_HOURS=168
DIRECT_LINK_TTL_MINUTES=10
UI_BRAND_NAME=Team Share
```

## Library configuration
- `config` crate:
  - Sources: defaults -> environment (prefix `SFS_` optional) -> `.env` via `dotenvy`.
  - Map to `AppConfig` struct; merge with `settings` row from DB during startup.
- `tracing` + `tracing-subscriber`:
  - Enable JSON logs in prod: env `LOG_JSON=true` optional.
- `sqlx` (SQLite):
  - Use `SqliteConnectOptions` with `journal_mode=WAL`, `busy_timeout=5s`.
  - Pool size: 5–10.
- Upload limits:
  - Apply Axum `RequestBodyLimitLayer` set to `MAX_FILE_SIZE_BYTES + overhead` on `/upload`.

## Runtime overrides in UI
- `/settings` updates `settings` table; changes take effect immediately for new requests.
- Persisted values are read on every request or cached with small TTL (e.g., 10s) to avoid constant DB hits.

## Forwarded headers
- If behind proxies, enable `Forwarded`/`X-Forwarded-*` processing only from `TRUSTED_PROXIES`.

## Secrets management
- Prefer container secrets or platform-provided secret stores in prod.
- Rotate `DOWNLOAD_TOKEN_SECRET` with overlap: support verifying with current and previous secret for a short window.
