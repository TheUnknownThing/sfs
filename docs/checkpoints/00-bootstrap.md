# 00) Bootstrap project

## Objectives
- Initialize a Rust binary project with a production-ready dependency set and migrations folder.

## Steps
1. Initialize project:
   - Create `Cargo.toml` (bin) and `src/main.rs` skeleton.
2. Add dependencies (latest compatible):
   - Runtime: `axum`, `tokio`, `tracing`, `tracing-subscriber`, `serde`, `serde_json`, `thiserror`.
   - Templates: `askama` (+ `askama_axum`).
   - DB: `sqlx` with features `runtime-tokio-rustls, macros, sqlite`.
   - Sessions: `tower-sessions`, `tower-sessions-sqlx-store` (or `tower-sessions-sqlx`).
   - Auth: `argon2`.
   - Config: `config`, `dotenvy`.
   - IDs: `ulid` or `cuid2`, codes: `nanoid`.
   - Misc: `time`, `mime_guess` or `tree_magic_mini`, `tower`, `tower-http`, `tower-governor`.
3. Create `migrations/` with initial SQL files from data model:
   - `0001_init_users_files_settings.sql`
   - `0002_sessions.sql` (from tower-sessions-sqlx)
   - `0003_indices.sql`
4. Add `.env.example` from `docs/config.md`.

## Files to create
- `Cargo.toml` with features set
- `src/main.rs` minimal server start stub
- `migrations/` scripts as above

## Acceptance criteria
- `cargo build` succeeds.
- Running the binary logs startup and exits with helpful error if DB or config missing.

## Notes
- Pin minor versions for stability; enable `resolver = "2"` in Cargo.
- Consider creating `sqlx-data.json` via `cargo sqlx prepare` for offline checks (optional).
