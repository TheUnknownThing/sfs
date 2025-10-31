# 10) Rate limiting & hardening

## Objectives
- Guard critical endpoints and add security headers and timeouts.

## Steps
1. Add `tower-governor` policies for:
   - `/login` (per IP + username key), `/upload`, `/f/:code`, `/f/:code/link`
2. Security headers via `tower-http::set_header`, including CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
3. Timeouts and limits:
   - Read header timeout 10s; body timeout 5m; limit concurrent uploads with semaphore.
4. Proxy/body size:
   - Document reverse proxy `client_max_body_size` in deployment.

## Acceptance criteria
- Surges produce 429; headers present; long uploads/downloads succeed within timeouts.
