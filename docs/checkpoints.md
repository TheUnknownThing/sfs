# Implementation Checkpoints

A step-by-step plan to build, verify, and ship the server. Each checkpoint includes acceptance criteria and quick verification steps. Commands assume macOS + zsh.

## 0) Bootstrap project
- Initialize Rust project and scaffolding.
- Add dependencies: `axum`, `tokio`, `tracing`, `tracing-subscriber`, `askama`, `sqlx` (sqlite), `tower-sessions` + `tower-sessions-sqlx`, `argon2`, `time`, `serde`, `config`, `dotenvy`, `thiserror`, `nanoid` or `cuid2`, `tower-governor`, `mime_guess`/`tree_magic_mini`.
- Create `migrations/` folder; add initial SQL files per data model.
- Seed `settings` row (id=1) if missing at startup.

Acceptance:
- `cargo build` succeeds.
- App starts, applies migrations, logs startup URL.

## 1) Configuration & logging
- Implement `AppConfig` using `config` crate; layer defaults, `.env`, environment.
- Initialize `tracing` subscriber; pretty logs in dev, JSON in prod.
- Wire `DATABASE_URL`, `STORAGE_ROOT`, ports, secrets.

Acceptance:
- App reads `.env` values; invalid config is rejected with clear error.

## 2) Database & sessions
- Initialize SQLx pool with WAL and busy_timeout.
- Add migrations for `users`, `files`, `settings`, and `sessions` (tower-sessions provided schema).
- Configure `tower-sessions` store backed by SQLx; set cookie flags per security doc.

Acceptance:
- Session cookie is set on visit; session row stored in DB.

## 3) Templates & base UI
- Add Askama templates: layout, home, login, upload, file details, settings.
- Include Pico.css, htmx, and feather icons via CDN in base layout.
- Add brand name from settings to header.

Acceptance:
- Home and login pages render with Pico.css styling.

## 4) Auth: login/logout
- Add `/login` GET/POST with CSRF token; password hashing via Argon2id.
- Create initial admin via bootstrap env if users table empty.
- Add `/logout` POST that destroys session.

Acceptance:
- Valid login creates session; invalid shows error and rate-limit.

## 5) Upload (authenticated)
- GET `/upload` renders form; also show form on `/` when authed.
- POST `/upload` handles multipart streaming to temp file, enforces `MAX_FILE_SIZE_BYTES`.
- Generate `file_id` (ulid/cuid2) and `code` (nanoid with readable format `XXXX-XXXX`).
- Move to final storage path `YYYY/MM/DD/<file_id>`; insert `files` row.

Acceptance:
- Uploading a small file succeeds and redirects to `/f/<code>`.
- Oversized file returns `413` with friendly message.

## 6) File details & code lookup (public)
- GET `/f/:code` looks up file; handle not found/expired.
- Render name, size, expiration; show "Generate direct link" button.

Acceptance:
- Visiting a known code shows details; expired file shows 410/Gone page.

## 7) Temporary direct link
- POST `/f/:code/link` validates CSRF; generates HMAC-signed token with TTL from settings.
- Return HTML fragment with direct link in readonly input and Copy button.
- GET `/d/:token` validates token and streams file with `Content-Disposition: attachment`.

Acceptance:
- Direct link works before expiry; returns 401 after expiry or tampering.

## 8) Settings (admin)
- GET `/settings` renders form with current values.
- POST `/settings` validates and updates `settings` row.
- Make settings live immediately; optionally cache 10s.

Acceptance:
- Changing max file size alters upload limit behavior without restart.

## 9) Cleanup job
- Spawn background task to delete expired files and prune DB rows on interval (e.g., every 15 min).
- Ensure safe delete: ignore missing files; wrap IO errors with logging.

Acceptance:
- Expired files disappear and rows are removed; logs reflect deletions.

## 10) Rate limiting & hardening
- Add `tower-governor` policies to `/login`, `/upload`, `/f/:code`, and `/f/:code/link`.
- Add CSP and security headers; set HSTS in reverse proxy.
- Enforce timeouts for uploads/downloads.

Acceptance:
- Excess requests receive 429; headers present as configured.

## 11) Dockerization & deploy
- Create Dockerfile and optional Compose file per deployment doc.
- Verify env vars, volumes, and healthcheck.

Acceptance:
- Container starts, migrations run, pages render, uploads/downloads work.

## 12) QA & smoke tests
- Manual path tests:
  - Upload then download via code and via direct link.
  - Test invalid/expired token.
  - Test 413 with large file.
  - Test settings changes.
- Optional integration tests (Rust) using `reqwest` against a spawned server with temp SQLite and temp dir.

Acceptance:
- All critical flows verified; no panics; logs clean.

## Useful snippets (optional)

Generate secrets (macOS):
```
# 32 random bytes base64
openssl rand -base64 32
```

Example nanoid alphabet for codes:
- Alphabet: `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no O/0/I/1)
- Pattern: 8 chars with hyphen `XXXX-XXXX`

## Edge cases to test
- Duplicate code collision (extremely rare) -> retry generation.
- Storage disk-full during upload -> return 507 Insufficient Storage and rollback.
- DB busy/locked -> retry with backoff.
- Large files near limit -> ensure correct 413 and cleanup temp file.
- Token clock skew -> allow small ±60s grace window or document strictness.
