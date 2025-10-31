# Simple File Server (Rust)

A pretty, team-friendly upload server with file-code sharing. Users can upload files (with login), share a short code, and anyone with the code can fetch a temporary direct download link and copy it. Includes basic settings (max file size, default expiration, etc.).

## Top features
- Upload with login; download with file code (no login needed)
- Short file codes for sharing (e.g., `5G2X-9KQD`)
- Temporary signed direct download links with one click "Copy link"
- Minimal, clean web UI (Pico.css) with server-rendered templates (Askama) and light htmx sprinkles
- Simple accounts (username + password), secure password hashing (Argon2id)
- Settings: default file expiration, max file size, direct-link TTL
- Persistent SQLite DB (SQLx) and durable server-side sessions (tower-sessions-sqlx)
- Background cleanup for expired files

## Tech choices (production-ready libs)
- Web: Axum 0.7 + Tokio 1.x
- Templates: Askama (static, fast, type-checked)
- DB: SQLx (SQLite) + migrations
- Sessions: tower-sessions + tower-sessions-sqlx (SQLite-backed)
- Passwords: argon2 (Argon2id)
- Short codes: nanoid or cuid2
- UI: Pico.css (CDN) + htmx (CDN) + feather icons (CDN)
- Config: config crate + dotenvy
- Logging: tracing + tracing-subscriber
- Rate limit: tower-governor (optional but recommended)

## How it works (at a glance)
- Logged-in users get an upload form (enforces max-size server-side). Files are streamed to disk and metadata is stored in SQLite.
- Each file gets a human-friendly short code.
- Anyone (no login) can enter a file code to see details and get a temporary direct link. The link is an HMAC-signed token that expires quickly.
- Settings can be adjusted by an admin user in the UI (and are also configurable by env vars).
- A small background task periodically deletes expired files and prunes DB rows.

## Non-goals (for v1)
- Multi-tenant/org boundaries
- Third-party storage (S3) — can be added later
- Complex RBAC — simple admin + user is enough

## Where to read next
- Overview and architecture: `architecture.md`
- Data model and schema: `data-model.md`
- API routes: `api.md`
- UI design: `ui.md`
- Security controls: `security.md`
- Configuration: `config.md`
- Deployment: `deployment.md`
- Implementation plan (summary): `checkpoints.md`
- Detailed step-by-step guides: `checkpoints/README.md` (then open the numbered files)