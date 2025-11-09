# Architecture

## Components
- HTTP server (Axum 0.7): routing, middleware, request limits, error handling
- Templates (Askama): server-rendered pages; minimal JS via htmx for niceties
- SQLite (SQLx): durable metadata (users, files, settings, sessions); connection pool
- Sessions (tower-sessions with SQLx store): login persistence via signed+encrypted cookie referencing a server-side session stored in DB
- Storage (FS): uploaded file and paste bytes live on disk under a configured directory, organized by date subfolders
- Background worker: periodic cleanup of expired files/pastes and stale sessions
- Config: environment-driven (config + dotenvy) with overrides from a Settings table (for admin UI)
- Rate limiting: tower-governor for protecting against abuse
- CSRF protection: double-submit tokens for all state-changing forms
- Download tokens: HMAC-SHA256 signed URLs for temporary access

## Data flow
1. Login/Registration
   - POST /login or POST /register with username + password
   - Verify against `users` (argon2id hashes with optional pepper)
   - Create session, set secure cookie (HttpOnly, SameSite=Lax; Secure in prod)
   - Rate limiting applies to prevent brute force attacks

2. Upload (auth required)
   - GET /upload (upload form visible when logged in)
   - POST /upload multipart form
   - Stream to a temp file with size enforcement; compute SHA-256 checksum and MIME type detection
   - Move to final path: `<storage_root>/<yy>/<mm>/<dd>/<file_id>` (ULID)
   - Record `files` row: id (ULID), owner, original_name, size, content_type, code, created_at, expires_at, checksum

3. Paste creation (auth required)
   - GET /paste (paste form with language selection)
   - POST /paste with title, language, content, expiration
   - Stream to temp file with size enforcement
   - Move to final path: `<storage_root>/<yy>/<mm>/<dd>/<file_id>` (ULID)
   - Record `files` row with appropriate content_type based on language

4. Download by code (no auth required)
   - GET /f/:code renders file/paste details and a button to generate a temporary direct link
   - Shows preview for text files under size limit
   - POST /f/:code/link creates a signed token with expiry (from Settings)
   - Frontend displays copyable direct link: `/d/<token>`

5. Direct download
   - GET /d/:token validates HMAC signature and expiry
   - Streams file with `Content-Disposition: attachment; filename="original.ext"`
   - Rate limited to prevent abuse

6. Admin operations
   - User management via /admin/users routes
   - Settings updates via /settings routes
   - All admin operations require admin privilege and CSRF token

## Signed URL (token) format
- Contents: `base64url(file_id).base64url(exp_epoch).base64url(hmac_sha256(secret, file_id||exp))`
- Secret: `DOWNLOAD_TOKEN_SECRET` (32+ bytes), loaded from env
- Validation: constant-time compare; reject if `now > exp`
- Maximum token length: 512 characters

## Middleware and layers
- Request size limit: set per-route for uploads and pastes
- Rate-limit: tower-governor on login, registration, code lookup, token generation, and downloads
- Session layer: tower-sessions with SQLx store; cookie: `__Host.sfs.sid`
- Tracing: request spans, structured logs with JSON option
- CSRF: double-submit tokens for all form posts (login, register, upload, paste, settings, admin)
- Body limiting: tower-http RequestBodyLimitLayer for upload protection

## Error handling
- Map known errors to friendly pages (404 for missing/expired code, 413 for too large, 401/403 for auth)
- Log errors with context; avoid leaking secrets
- Graceful degradation for template rendering errors
- Proper HTTP status codes for all error conditions

## Extensibility
- Swap FS storage with S3-compatible via a `Storage` trait
- Add email notifications for expiring files
- Add per-file password protection (optional)
- Add more paste language support
- Add file preview for more formats (PDF, images)
