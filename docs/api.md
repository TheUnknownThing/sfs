# HTTP API and Routes

All pages are server-rendered HTML unless stated. JSON endpoints are limited to htmx interactions.

## Public
- GET /
  - If logged out: landing with file-code form and login/register links
  - If logged in: upload form + recent uploads

- GET /login
  - Render login form

- POST /login
  - Form: username, password, csrf_token
  - 302 -> / on success; show error on failure

- GET /register
  - Render registration form (if registration is enabled in settings)

- POST /register
  - Form: username, password, password_confirm, csrf_token
  - Creates new user account if registration is enabled
  - 302 -> / on success; show error on failure

- POST /logout
  - Clears session, 302 -> /

- GET /f/:code
  - Render file/paste details if exists and not expired; otherwise 404/410
  - Shows: name, size, expires, content preview (for text files), Generate Link button
  - Shows delete button for owners or admins

- POST /f/:code/link
  - Auth: none required
  - Body: csrf_token (via htmx fetch or form submit)
  - Action: issues a temporary signed token (TTL from settings)
  - Response: HTML fragment with the direct link and Copy button

- POST /f/:code/delete
  - Auth: owner or admin required
  - Body: csrf_token
  - Action: deletes file/paste and associated storage
  - 302 -> / on success

- GET /d/:token
  - Validates HMAC signature and expiry; 401 on invalid/expired
  - Streams file bytes with `Content-Disposition: attachment`

## Auth-only
- GET /upload
  - Upload page (also accessible from / when logged in)

- POST /upload
  - Multipart form: file, expires_in (hours)
  - Limits: enforces max_file_size_bytes from settings
  - On success: redirect to `/f/<code>`

- GET /paste
  - Paste creation page with syntax highlighting options

- POST /paste
  - Form: title, language, expires_in (hours), content, csrf_token
  - Limits: enforces max_file_size_bytes from settings
  - On success: redirect to `/f/<code>`

## Admin-only
- GET /settings
  - Admin only; render settings form

- POST /settings
  - Admin only; update: max_file_size_bytes, default_expiration_hours, direct_link_ttl_minutes, ui_brand_name, allow_registration, allow_anonymous_download, preview_max_size_bytes

- GET /admin/users
  - Admin only; render user management page with list of all users

- POST /admin/users
  - Admin only; create new user
  - Form: username, password, password_confirm, is_admin, csrf_token

- POST /admin/users/:id/reset-password
  - Admin only; reset password for specific user
  - Form: new_password, confirm_password, csrf_token

- POST /admin/users/:id/delete
  - Admin only; delete specific user (cannot delete self or last admin)
  - Form: csrf_token

## Errors
- 400 Bad Request: malformed token, invalid form
- 401 Unauthorized: invalid token (download), or auth-required endpoints
- 403 Forbidden: non-admin to admin endpoint, or CSRF token invalid
- 404 Not Found: unknown file code or user
- 410 Gone: file/paste expired
- 413 Payload Too Large: file/paste exceeds max size
- 422 Unprocessable Entity: validation errors in forms

## JSON fragments (htmx)
- POST /f/:code/link
  - Returns small HTML snippet with the link and copy button. Keep it server-rendered to avoid frontend framework.

## Rate Limits
- Login: 5 attempts per minute per IP and per username
- Registration: 1 attempt per minute per IP
- Direct link generation: 5 attempts per minute per IP
- Direct downloads: 30 attempts per minute per IP