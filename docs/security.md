# Security

This document describes the security controls that exist in the Simple File Server codebase and the operational steps required to keep them effective.

## Authentication & Accounts
- Password hashing uses Argon2id (`argon2` crate) with the parameters hard-coded in `src/auth.rs`: memory cost 19_456 KiB (about 19 MiB), time cost 2, parallelism 1, 32-byte output. Password hashes are stored in PHC format and are only recomputed when parameters drift (`verify_password` sets `needs_rehash`).
- Optional pepper support: if `PASSWORD_PEPPER` is set the server prepends it to the supplied password before hashing or verification. Remove or rotate the pepper carefully because existing hashes embed the peppered password material.
- Username policy is enforced by `normalize_username`: trimmed, lowercase, length 3-64, no whitespace. Password strength enforcement requires at least 12 characters.
- Login flow (`server/handlers/auth.rs`):
  - Rate limits by IP and by normalized username to 5 attempts per minute each.
  - Invalid attempts incur a randomized 150-300 ms backoff (`randomized_backoff`) to slow brute force attacks.
  - CSRF token validation happens before any credential checks. On success the session ID is rotated to prevent fixation, the last-login timestamp is updated, and passwords are rehashed if necessary.
- Registration mirrors the same CSRF handling and password policy, is disabled by default via the settings table, and is rate limited to 1 request per IP per minute. Newly registered users are signed in immediately with a rotated session ID.
- Administrative access is guarded in `server/handlers/shared.rs::require_admin`. Only accounts with `is_admin = 1` may hit `/settings` and `/admin/*` routes.
- On first boot the application calls `bootstrap_admin_user`. If the `users` table is empty and both `BOOTSTRAP_ADMIN_USERNAME` and `BOOTSTRAP_ADMIN_PASSWORD` are set, a single admin is created with full validation and hashing.

## Session Management
- Sessions are provided by `tower-sessions` backed by the SQLite store in the `tower_sessions` table. Each record contains opaque serialized state plus `expiry_date` managed by the library.
- Cookies are issued under the host-only name `__Host.sfs.sid` with `Path=/`, `HttpOnly`, and `SameSite=Lax`. The `Secure` flag is controlled by `COOKIE_SECURE`; set it to `true` in production so browsers refuse plaintext transport.
- The configuration layer will not start unless `SESSION_KEY` is at least 32 bytes (base64 accepted). This guard ensures we always have high-entropy material available for key management.
- Session IDs are rotated on login, registration, and logout. Logout also clears the stored user and rotates the CSRF token to invalidate existing forms.
- Tower Sessions v0.11 applies its default TTL to all sessions (24 hours at the time of writing). The background cleanup job removes expired rows so abandoned sessions cannot be reused. The `SESSION_MAX_AGE_HOURS` field in `AppConfig` is present for future tuning but is not yet wired into the session layer.

## CSRF Protection
- `csrf.rs` issues a 64-character nanoid per session and stores it server-side. Tokens are generated lazily via `ensure_csrf_token` and rotated after login, logout, successful uploads, registration, settings saves, and any validation failure.
- All forms that mutate state must include `<input name="csrf_token">`. Handlers call `validate_csrf_token`, which compares the provided token with constant-time equality and rejects missing or mismatched tokens.
- The base layout exposes the token in a `<meta>` tag for JavaScript clients. HTMX requests automatically add an `X-CSRF-Token` header, and the file preview scripts read the hidden field before making `fetch` requests.

## Rate Limiting & Abuse Prevention
- `src/rate_limit.rs` implements keyed token buckets (governor crate):
  - Login attempts: 5/minute per client IP and 5/minute per normalized username.
  - Registration: 1/minute per IP.
  - Direct-link generation (`POST /f/:code/link`): 5/minute per IP.
  - Direct downloads (`GET /d/:token`): 30/minute per IP.
- When a limiter triggers the response includes `Retry-After` and an explanatory message. Rate limits are enforced before hitting expensive workloads such as password hashing or disk IO.

## Direct Download Tokens
- `DownloadTokenService` signs tokens as `base64url(file_id).base64url(expiry_epoch).base64url(HMAC_SHA256(secret, file_id || expiry_epoch))` using `DOWNLOAD_TOKEN_SECRET` (validated to be >= 32 bytes, base64 supported).
- Token lifetimes come from the settings table (`direct_link_ttl_minutes`, accepted range 1-1440). At issuance the effective expiry is the earlier of the configured TTL and the underlying file's own expiration.
- Validation performs constant-time signature comparison, enforces token length (<=512 characters), rejects malformed Base64 components, and ensures the token has not expired.
- Issuance and redemption are rate limited (see above). `download_handler` canonicalizes the resolved storage path and refuses to serve files that escape the configured `storage.root`, blocking path traversal attempts.
- Tokens are not yet bound to client IPs or marked single-use; if you need those properties add them to `DownloadTokenClaims` and the backing cache.

## File & Paste Handling
- Uploads (`server/handlers/uploads.rs`) and pastes (`server/handlers/paste.rs`) require an authenticated session. Both stream multipart content directly to disk using a temporary `.uploading` file, enforce the current `max_file_size_bytes`, and remove any partially written blobs if limits are exceeded or IO fails.
- Stored files live under `storage/<YYYY>/<MM>/<DD>/<ULID>`; the ULID is generated server-side and recorded in the database. User-supplied filenames are kept only as metadata. `sanitize_filename` strips dangerous characters, truncates to 255 bytes, and falls back to a safe name when needed.
- Each record includes a SHA-256 checksum for later integrity checks. For pastes we also normalize the extension based on the selected language to keep previews coherent.
- Download responses set `Content-Type` using the stored value (falling back to `mime_guess`), emit `Content-Disposition` with proper ASCII fallback and RFC 5987 encoding, and always include `X-Content-Type-Options: nosniff`. Text files up to 1 MiB are rendered inline to support the preview tooling; larger or non-text files are forced to download.
- Deletions require ownership or admin privileges, run within a `BEGIN IMMEDIATE` transaction, and remove the on-disk blob after the database commit. Missing blobs are logged but not treated as fatal.

## Transport & Deployment Expectations
- The application assumes TLS termination happens at a reverse proxy. The provided `deploy/Caddyfile` already applies `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` headers and redirects HTTP to HTTPS.
- The example `deploy/nginx.conf` handles HTTPS redirection and size limits but does not yet add the hardened headers. Mirror the Caddy configuration if you deploy with Nginx or another proxy.
- The code currently ignores the `TRUSTED_PROXIES` list. Until proxy awareness is added, expose the service only behind infrastructure you fully control and strip spoofed headers at the edge.

## Input Validation & Sanitisation
- Public download codes are normalised by `normalize_lookup_code`, which enforces the 4-4 pattern (A-Z, 2-9, without ambiguous letters) and uppercases input.
- Tokens and IDs are parsed with explicit Base64 and UTF-8 checks (`direct_links.rs`). Any decoding failure results in a rejected request.
- Settings, upload, and paste forms validate numeric ranges against the constants in `server/constants.rs`. Attempting to exceed configured bounds yields helpful form errors.
- Usernames are stored lowercase to prevent impersonation via case differences.

## Background Cleanup & Data Lifecycle
- `cleanup::spawn_cleanup_job` runs every 15 minutes. It removes expired file records in batches of 100, deletes the associated blobs, and logs any missing files for investigation.
- The same task also prunes expired sessions from `tower_sessions`, ensuring abandoned cookies cannot be replayed after expiry.
- File expirations are derived from per-upload selections or the application defaults (configurable via the settings UI or `DEFAULT_EXPIRATION_HOURS`).

## Logging & Auditability
- Structured logging is powered by `tracing`. Events record user IDs, usernames, IP addresses, and file codes where needed, but never include passwords, raw tokens, or file contents.
- Setting `LOG_JSON=true` switches to JSON output suitable for centralised log aggregation.
- Failed security checks (rate limits, invalid CSRF, token validation errors, path traversal attempts) are logged with appropriate severity so they can feed alerting.

## Secrets & Configuration
- `SESSION_KEY` and `DOWNLOAD_TOKEN_SECRET` must each be at least 32 bytes (plain or `base64:` prefixed). The server refuses to boot if either secret is missing or too short.
- `PASSWORD_PEPPER` is optional; when set it must be kept secret and rotated carefully because removing it invalidates existing hashes.
- `COOKIE_SECURE` should be `true` in every HTTPS environment so the session cookie is never transmitted over HTTP.
- `MAX_FILE_SIZE_BYTES` is re-validated at startup to fall between 1 MiB and 5 GiB. Values outside that band cause the application to abort, preventing accidental misconfiguration.

## Backup & Recovery
- Persist and back up both the SQLite database (`data/app.db` plus WAL/SHM files) and the storage root (`storage/`). Use SQLite's `VACUUM INTO` or filesystem snapshots to take consistent backups while the service is online.
- The `tower_sessions` table contains transient session data and can be excluded from backups if desired. Users will simply sign in again after a restore.

## Known Gaps / Next Hardening Steps
- Upload requests are currently limited only by authentication and file-size checks; there is no dedicated upload rate limiter yet.
- Global HTTP timeouts (header read, whole-body, idle) rely on the reverse proxy. Add per-route timeouts at the Axum layer if clients connect directly.
- `TRUSTED_PROXIES` is parsed but unused. Introduce middleware to enforce it before trusting forwarded headers.
- A global Content-Security-Policy is not emitted by the application. Configure one at the proxy or contribute server support.
- Session lifetime is controlled by the library default. Wire `SESSION_MAX_AGE_HOURS` through `tower-sessions` if you need explicit control.
