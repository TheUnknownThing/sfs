# Architecture

## Components
- HTTP server (Axum): routing, middleware, request limits, error handling
- Templates (Askama): server-rendered pages; minimal JS via htmx for niceties
- SQLite (SQLx): durable metadata (users, files, settings); connection pool
- Sessions (tower-sessions with SQLx store): login persistence via signed+encrypted cookie referencing a server-side session stored in DB
- Storage (FS): uploaded file bytes live on disk under a configured directory, organized by hashed subfolders
- Background worker: periodic cleanup of expired files and stale sessions
- Config: environment-driven (config + dotenvy) with overrides from a Settings table (for admin UI)

## Data flow
1. Login
   - POST /login with username + password
   - Verify against `users` (argon2id hashes)
   - Create session, set secure cookie (HttpOnly, SameSite=Lax; Secure in prod)

2. Upload (auth required)
   - GET / (upload form visible when logged in)
   - POST /upload multipart form
   - Stream to a temp file with size enforcement; compute checksum (optional) and mime sniffing
   - Move to final path: `<storage_root>/<yy>/<mm>/<dd>/<file_id>`
   - Record `files` row: id, owner, original_name, size, content_type, code, created_at, expires_at

3. Download by code (no auth required)
   - GET /f/:code renders file details and a button to generate a temporary direct link
   - POST /f/:code/link creates a signed token with expiry (e.g. 10 minutes from Settings)
   - Frontend displays copyable direct link: `/d/<token>`

4. Direct download
   - GET /d/:token validates HMAC signature and expiry
   - Streams file with `Content-Disposition: attachment; filename="original.ext"`

## Signed URL (token) format
- Contents: `base64url(file_id).base64url(exp_epoch).base64url(hmac_sha256(secret, file_id||exp))`
- Secret: `DOWNLOAD_TOKEN_SECRET` (32+ bytes), loaded from env
- Validation: constant-time compare; reject if `now > exp`

## Middleware and layers
- Request size limit: set per-route for uploads
- Rate-limit: tower-governor on code lookup and token generation
- Session layer: tower-sessions with SQLx store; cookie: `__Host.sfs.sid`
- Tracing: request spans, structured logs
- CSRF: double-submit tokens for form posts (login, upload, settings)

## Error handling
- Map known errors to friendly pages (404 for missing/expired code, 413 for too large, 401/403 for auth)
- Log errors with context; avoid leaking secrets

## Extensibility
- Swap FS storage with S3-compatible via a `Storage` trait
- Add email notifications for expiring files
- Add per-file password protection (optional)
