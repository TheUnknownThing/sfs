# Implementation Checkpoints

A step-by-step plan to build, verify, and ship the server. Each checkpoint includes acceptance criteria and quick verification steps. Commands assume macOS + zsh.

## 0) Bootstrap project
- Initialize Rust project and scaffolding.
- Add dependencies: `axum`, `tokio`, `tracing`, `tracing-subscriber`, `askama`, `sqlx` (sqlite), `tower-sessions` + `tower-sessions-sqlx`, `argon2`, `time`, `serde`, `config`, `dotenvy`, `thiserror`, `nanoid`, `ulid`, `tower-governor`, `mime_guess`, `sha2`, `base64`, `hmac`, `subtle`, `fastrand`, `tower`, `tower-http`, `tokio-util`.
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
- Add Askama templates: layout, home, login, register, upload, paste, file details, settings, users.
- Include Pico.css, htmx, and feather icons via CDN in base layout.
- Add brand name from settings to header.

Acceptance:
- Home and login pages render with Pico.css styling.

## 4) Auth: login/logout/register
- Add `/login` GET/POST with CSRF token; password hashing via Argon2id.
- Add `/register` GET/POST with CSRF token; controlled by `allow_registration` setting.
- Create initial admin via bootstrap env if users table empty.
- Add `/logout` POST that destroys session.

Acceptance:
- Valid login creates session; invalid shows error and rate-limit.
- Registration works when enabled; creates new user and signs them in.

## 5) Upload (authenticated)
- GET `/upload` renders form; also show form on `/` when authed.
- POST `/upload` handles multipart streaming to temp file, enforces `MAX_FILE_SIZE_BYTES`.
- Generate `file_id` (ULID) and `code` (nanoid with readable format `XXXX-XXXX`).
- Move to final storage path: `YYYY/MM/DD/<file_id>`; insert `files` row.

Acceptance:
- Uploading a small file succeeds and redirects to `/f/<code>`.
- Oversized file returns `413` with friendly message.

## 6) Paste creation (authenticated)
- GET `/paste` renders form with language selection and content area.
- POST `/paste` handles text content with size enforcement.
- Generate `file_id` (ULID) and `code` (nanoid with readable format `XXXX-XXXX`).
- Store with appropriate content type based on language selection.
- Apply file extension based on language for proper preview.

Acceptance:
- Creating a paste succeeds and redirects to `/f/<code>`.
- Oversized paste returns `413` with friendly message.

## 7) File/paste details & code lookup (public)
- GET `/f/:code` looks up file; handle not found/expired.
- Render name/title, size, expiration, content type, checksum.
- Show preview for text files under size limit with syntax highlighting.
- Show "Generate direct link" button.
- Show delete button for owners and admins.

Acceptance:
- Visiting a known code shows details; expired file shows 410/Gone page.
- Text pastes show inline preview when under size limit.

## 8) Temporary direct link
- POST `/f/:code/link` validates CSRF; generates HMAC-signed token with TTL from settings.
- Return HTML fragment with direct link in readonly input and Copy button.
- GET `/d/:token` validates token and streams file with `Content-Disposition: attachment`.

Acceptance:
- Direct link works before expiry; returns 401 after expiry or tampering.

## 9) Settings (admin)
- GET `/settings` renders form with current values including registration toggle and preview size.
- POST `/settings` validates and updates `settings` row.
- Make settings live immediately; cache in `AppState`.

Acceptance:
- Changing max file size alters upload limit behavior without restart.
- Registration toggle controls user signup availability.

## 10) User management (admin)
- GET `/admin/users` renders user list with management actions.
- POST `/admin/users` creates new users with password hashing.
- POST `/admin/users/:id/reset-password` resets user passwords.
- POST `/admin/users/:id/delete` deletes users with protection against deleting last admin.

Acceptance:
- Admin can create, manage, and delete users.
- Password reset functionality works correctly.
- Protection against deleting last admin or self.

## 11) Cleanup job
- Spawn background task to delete expired files/pastes and prune DB rows on interval (every 15 min).
- Prune expired sessions from `tower_sessions` table.
- Ensure safe delete: ignore missing files; wrap IO errors with logging.

Acceptance:
- Expired files/pastes disappear and rows are removed; logs reflect deletions.
- Expired sessions are cleaned up.

## 12) Rate limiting & hardening
- Add `tower-governor` policies to `/login`, `/register`, `/upload`, `/paste`, `/f/:code`, `/f/:code/link`, and `/d/:token`.
- Add CSRF protection to all state-changing forms.
- Add security headers in reverse proxy configuration.
- Enforce timeouts for uploads/downloads.

Acceptance:
- Excess requests receive 429; headers present as configured.
- CSRF validation prevents cross-site request forgery.

## 13) Dockerization & deploy
- Create Dockerfile and optional Compose file per deployment doc.
- Verify env vars, volumes, and healthcheck.
- Add proper user permissions and non-root execution.

Acceptance:
- Container starts, migrations run, pages render, uploads/downloads work.

## 14) QA & smoke tests
- Manual path tests:
  - Upload then download via code and via direct link.
  - Create and view paste with syntax highlighting.
  - Test invalid/expired token.
  - Test 413 with large file/paste.
  - Test settings changes.
  - Test user management functions.
  - Test registration flow.
  - Test delete functionality.
- Optional integration tests (Rust) using `reqwest` against a spawned server with temp SQLite and temp dir.

Acceptance:
- All critical flows verified; no panics; logs clean.