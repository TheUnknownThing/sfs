# 07) Temporary direct link

## Objectives
- Provide short-lived signed download links; validate tokens and stream files.

## Steps
1. Token structure:
   - `base64url(file_id).base64url(exp_epoch).base64url(hmac_sha256(secret, file_id||exp))`
2. Generation:
   - POST `/f/:code/link` (no auth); validate CSRF; read TTL from settings; return HTML snippet with link `/d/<token>`
3. Validation & streaming:
   - GET `/d/:token`: parse, verify HMAC and expiry, fetch file by id, stream with `Content-Disposition: attachment; filename="..."` and `X-Content-Type-Options: nosniff`
4. Rate limiting:
   - Limit link generation and downloads per IP.

## Acceptance criteria
- Fresh token downloads file; expired or tampered token returns 401.
