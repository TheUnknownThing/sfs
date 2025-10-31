# 04) Auth: login/logout

## Objectives
- Implement secure password login with Argon2id and CSRF; add logout.

## Steps
1. Users table seed:
   - On startup, if no users exist and `BOOTSTRAP_ADMIN_*` set, create admin user (argon2id).
2. Password hashing:
   - Use `argon2` crate with Argon2id and strong params; store PHC string.
3. CSRF:
   - Generate per-session token; embed in login form; validate on POST.
4. Routes:
   - GET `/login`: render form
   - POST `/login`: verify creds; rotate session ID; redirect `/`
   - POST `/logout`: revoke session; redirect `/`
5. Rate limiting:
   - 5 req/min per IP and per username.

## Acceptance criteria
- Valid login creates session; invalid attempts show error and are rate limited.
- Logout clears cookie and session.
