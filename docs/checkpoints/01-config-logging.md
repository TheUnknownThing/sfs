# 01) Configuration & logging

## Objectives
- Centralize configuration with defaults, `.env`, and environment. Initialize structured logging.

## Contract
- Inputs: env + `.env`; outputs: `AppConfig` struct and initialized tracer.
- Error modes: missing secrets -> startup error; invalid numeric ranges -> explicit error.

## Steps
1. Define `AppConfig` struct:
   - server: bind, port
   - database_url, storage_root
   - session_key, download_token_secret
   - cookie_secure, trusted_proxies
   - defaults for settings (max size, default expiration, link TTL, brand)
2. Load config:
   - `dotenvy::dotenv().ok();`
   - `config::Config::builder()` with defaults -> env (`SFS_` prefix optional).
3. Initialize `tracing_subscriber`:
   - Dev: pretty formatter
   - Prod: JSON if `LOG_JSON=true`
4. Validate config (lengths, ranges, directories writable/creatable).

## Snippets
- Ensure storage dir exists: create if not exists with `std::fs::create_dir_all`.
- Log fields: request_id, method, path, status, elapsed_ms.

## Acceptance criteria
- App reads config and starts with logs at `info`.
- Invalid config leads to descriptive error and non-zero exit.
