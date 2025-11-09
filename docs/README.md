# Simple File Server (Rust)

A pretty, team-friendly upload server with file-code sharing and paste functionality. Users can upload files or create text pastes (with login), share a short code, and anyone with the code can fetch a temporary direct download link and copy it. Includes comprehensive admin controls, user management, and configurable settings.

## Top features
- Upload files and create text pastes with login; download with file code (no login needed)
- Short file codes for sharing (e.g., `5G2X-9KQD`)
- Temporary signed direct download links with one click "Copy link"
- Text paste support with syntax highlighting for multiple languages
- Minimal, clean web UI (Pico.css) with server-rendered templates (Askama) and light htmx sprinkles
- User management with registration (admin-controlled) and admin panel
- Simple accounts (username + password), secure password hashing (Argon2id)
- Settings: default file expiration, max file size, direct-link TTL, registration toggle
- Persistent SQLite DB (SQLx) and durable server-side sessions (tower-sessions-sqlx)
- Background cleanup for expired files and sessions
- Comprehensive rate limiting and CSRF protection
- File preview for text files up to configurable size limit

## Tech choices (production-ready libs)
- Web: Axum 0.7 + Tokio 1.x
- Templates: Askama (static, fast, type-checked)
- DB: SQLx (SQLite) + migrations
- Sessions: tower-sessions + tower-sessions-sqlx (SQLite-backed)
- Passwords: argon2 (Argon2id)
- IDs: ULID for file IDs, nanoid for short codes
- UI: Pico.css (CDN) + htmx (CDN) + feather icons (CDN)
- Config: config crate + dotenvy
- Logging: tracing + tracing-subscriber
- Rate limit: tower-governor
- Time handling: time crate
- Crypto: HMAC-SHA256 for download tokens, base64 for encoding

## How it works (at a glance)
- Logged-in users get upload and paste forms (enforces max-size server-side). Files are streamed to disk and metadata is stored in SQLite.
- Each file/paste gets a human-friendly short code and a ULID for internal storage.
- Anyone (no login) can enter a file code to see details and get a temporary direct link. The link is an HMAC-signed token that expires quickly.
- Admin users can manage users, adjust settings, and control registration in the UI.
- Settings are configurable by env vars and can be overridden in the admin UI.
- A background task periodically deletes expired files/pastes and prunes DB rows.
- Rate limiting protects against abuse on login, registration, and download endpoints.

## NON-goals (for v1)
- Multi-tenant/org boundaries
- Third-party storage (S3)
- Complex RBAC — simple admin + user is enough

## Where to read next
- Overview and architecture: `architecture.md`
- Data model and schema: `data-model.md`
- API routes: `api.md`
- Security controls: `security.md`
- Configuration: `config.md`
- Deployment: `deployment.md`