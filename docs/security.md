# Security

This document lists concrete, implementable security controls for the file server.

## Authentication & authorization
- Password hashing: Argon2id via `argon2` crate.
  - Parameters (baseline): memory_cost=19456 KiB (19 MB), time_cost=2, parallelism=1.
  - Store PHC-formatted hash; never store plaintext.
  - Allow rehash-on-login when parameters increase (detect with `needs_rehash`).
  - Optional pepper: `PASSWORD_PEPPER` env var concatenated with password before hashing.
- Account policy:
  - Username unique, 3–64 chars; password min 12 chars.
  - Lockout/backoff after repeated failures: rate-limit per IP and per username (see Rate limiting).
  - Admin flag on user; only admins can access `/settings`.
- Session management:
  - Use `tower-sessions` with SQLx-backed store (SQLite).
  - Cookie name: `__Host.sfs.sid` (Host-only prefix requires Secure + Path=/ + no Domain).
  - Cookie flags: `Secure` (prod), `HttpOnly`, `SameSite=Lax`, `Path=/`.
  - Rotate session ID on login to prevent fixation; revoke on logout.
  - Server-side session expiry (e.g., 14 days idle) with rolling refresh.

## CSRF protection
- Use double-submit cookie or `tower-csrf` pattern:
  - Generate CSRF token per session; embed as hidden `<input name="csrf_token">`.
  - Validate on every state-changing POST (login, upload, settings, generate-link).
  - For htmx requests, send token via `HX-Request` header `X-CSRF-Token`.

## Rate limiting & abuse controls
- Apply `tower-governor` or similar token-bucket limits:
  - `/login`: 5 req/min per IP and per username key.
  - `/f/:code`, `/f/:code/link`: 60 req/min per IP.
  - `/upload`: 10 req/min per authenticated user.
- Add small random delay on auth failures to reduce brute force effectiveness.

## Transport security
- Enforce HTTPS in production via reverse proxy (Caddy/Nginx).
- Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` when behind TLS.
- Trust proxy headers only from configured `TRUSTED_PROXIES` CIDRs.

## Download token (signed URL)
- Token contents: `base64url(file_id).base64url(exp_epoch).base64url(hmac_sha256(secret, file_id||exp))`.
- Secret: `DOWNLOAD_TOKEN_SECRET` (>=32 random bytes).
- Validation: constant-time compare; reject if `now > exp`.
- TTL: from settings (`direct_link_ttl_minutes`, default 10 min).
- Optional hardening (v2): bind token to IP or user-agent; add single-use nonce with server cache.

## File upload safety
- Enforce server-side size limit: `max_file_size_bytes` from settings.
- Stream uploads to temp file; reject early when over limit.
- Store files outside any static web root; serve bytes only via handler that always sets:
  - `Content-Disposition: attachment; filename="original.ext"`
  - `X-Content-Type-Options: nosniff`
- Content-type: sniff best effort (e.g., `tree_magic_mini`) but never trust client value.
- Filenames: store original name as metadata; never use it for path construction.
- Paths: construct storage path from server-generated `file_id` only; prohibit user-controlled paths.
- Optional malware scan: integrate `clamd` (network daemon) and quarantine/block on detection.

## Input validation
- File code: restrict to `[A-Z0-9-]`, fixed length (e.g., 4-4 pattern).
- Token: strict base64url parsing; length caps; handle decode errors safely.
- Settings form: validate ranges (see Configuration).

## Headers & browser hardening
- `Content-Security-Policy: default-src 'self'; style-src 'self' https://unpkg.com 'unsafe-inline'; script-src 'self' https://unpkg.com; img-src 'self' data:; object-src 'none'`
- `Referrer-Policy: no-referrer`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`

## Logging & privacy
- Log structured events with request IDs; exclude passwords, tokens, cookies.
- Redact IP if required by policy. Avoid logging file contents or secrets.

## Timeouts & resource limits
- Read header timeout: 10s; full body timeout: 5 min for large uploads.
- Concurrent upload limit per process (semaphore) to prevent memory pressure.
- SQLite pragmas: enable `busy_timeout` and WAL mode; avoid long write locks.

## Backups & recovery
- Backup `storage_root` and SQLite DB (`.db` and WAL/SHM) consistently (use `VACUUM INTO` for snapshot).
- Exclude `sessions` table from backups for privacy; session restore is not required.

## Initial admin bootstrap
- On first run, if no users present, create admin via CLI flag or env pair `BOOTSTRAP_ADMIN_USERNAME`/`BOOTSTRAP_ADMIN_PASSWORD` read once.
- Disable bootstrap after success.
