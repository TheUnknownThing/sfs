# 02) Database & sessions

## Objectives
- Initialize SQLx (SQLite) with WAL, busy_timeout; set up sessions backed by DB.

## Steps
1. SQLx setup:
   - Use `SqliteConnectOptions::from_str(database_url)` with `journal_mode=WAL`, `busy_timeout(5s)`.
   - Create pool with size 5–10.
2. Run migrations at startup: `sqlx::migrate!().run(&pool).await?`.
3. Settings bootstrap:
   - If `settings` row absent, insert defaults.
4. tower-sessions:
   - Use `tower_sessions::SessionManagerLayer::new(SqlxStore::new(pool.clone()))`.
   - Cookie: name `__Host.sfs.sid`, `Secure` (prod), `HttpOnly`, `SameSite=Lax`, `Path=/`.
   - Idle timeout 14 days; rolling.
5. Middleware ordering:
   - Trace -> Sessions -> CSRF -> Routes.

## Migrations content
- Create `users`, `files`, `settings` per data-model.
- Apply sessions schema from tower-sessions-sqlx (copy vendor SQL).
- Indices: UNIQUE(username), UNIQUE(code), INDEX(expires_at).

## Acceptance criteria
- Visiting `/` creates a session entry in DB.
- Migrations re-run idempotently with no errors.
