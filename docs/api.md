# HTTP API and Routes

All pages are server-rendered HTML unless stated. JSON endpoints are limited to htmx interactions.

## Public
- GET /
  - If logged out: landing with file-code form and login link
  - If logged in: upload form + recent uploads

- GET /login
  - Render login form

- POST /login
  - Form: username, password, csrf_token
  - 302 -> / on success; show error on failure

- POST /logout
  - Clears session, 302 -> /

- GET /f/:code
  - Render file details if exists and not expired; otherwise 404/410
  - Shows: name, size, expires, Generate Link button

- POST /f/:code/link
  - Auth: none required
  - Body: csrf_token (via htmx fetch or form submit)
  - Action: issues a temporary signed token (TTL from settings)
  - Response: HTML fragment with the direct link and Copy button

- GET /d/:token
  - Validates HMAC signature and expiry; 401 on invalid/expired
  - Streams file bytes with `Content-Disposition: attachment`

## Auth-only
- GET /upload
  - Upload page (also accessible from / when logged in)

- POST /upload
  - Multipart form: file, expires_in (hours), optional notes
  - Limits: enforces max_file_size_bytes from settings
  - On success: redirect to `/f/<code>`

- GET /settings
  - Admin only; render settings form

- POST /settings
  - Admin only; update: max_file_size_bytes, default_expiration_hours, direct_link_ttl_minutes, ui_brand_name

## Errors
- 400 Bad Request: malformed token, invalid form
- 401 Unauthorized: invalid token (download), or auth-required endpoints
- 403 Forbidden: non-admin to admin endpoint
- 404 Not Found: unknown file code
- 410 Gone: file expired
- 413 Payload Too Large: file exceeds max size

## JSON fragments (htmx)
- POST /f/:code/link
  - Returns small HTML snippet with the link and copy button. Keep it server-rendered to avoid frontend framework.