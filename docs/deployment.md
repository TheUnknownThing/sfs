# Deployment

This guide covers containerized and bare-metal/systemd deployments with reverse proxy and TLS.

## Container image (Dockerfile)
The root `Dockerfile` builds a musl-linked binary in a multi-stage pipeline and ships a minimal Alpine runtime. It configures sane defaults for running inside the container, drops privileges via `su-exec`, and exposes a health check using `wget`.

Highlights:
- Builder stage installs only the toolchains required to compile the release artifact with `SQLX_OFFLINE=true`.
- Runtime stage adds `wget`, `sqlite-libs`, and `su-exec`, creates the `/data` hierarchy, and declares volumes for both the SQLite database and uploaded files.
- Health checks probe `http://127.0.0.1:8080/` every 30 seconds.
- Uses non-root user with proper permissions.

See `Dockerfile` for the exact implementation.

## Docker Compose

The repository ships with `docker-compose.yml` which:
- Builds (or pulls) the production image for the `app` service.
- Mounts two named volumes: `sfs-db` for the SQLite database at `/data/app.db` and `sfs-storage` for user uploads under `/data/storage`.
- Exposes port `8080` and wires a `CMD-SHELL` health check hitting `/`.
- Environment variables for cryptographic secrets (`SESSION_KEY`, `DOWNLOAD_TOKEN_SECRET`) are surfaced as required placeholders so the stack refuses to start without them. Attach your own reverse proxy or load balancer as needed (examples below).

## Reverse proxy

### Caddy (recommended)
`deploy/Caddyfile` mirrors the example below with minor tweaks so you can parameterise the domain and ACME behaviour via environment variables (`SFS_DOMAIN`, `SFS_TLS_EMAIL`). By default it uses Caddy's internal CA; set `SFS_TLS_EMAIL` to a real address when you are ready to request public certificates. Mount this file into your own Caddy container if you want automatic TLS.

```
{$SFS_DOMAIN:files.local} {
  encode zstd gzip
  tls {$SFS_TLS_EMAIL:internal}
  @static path /static/*
  handle @static {
    respond 404
  }
  handle {
    header {
      Strict-Transport-Security "max-age=31536000; includeSubDomains"
      X-Content-Type-Options "nosniff"
      X-Frame-Options "DENY"
      Referrer-Policy "no-referrer"
    }
    reverse_proxy app:8080
  }
}

:80 {
  redir https://{$SFS_DOMAIN:files.local}{uri}
}
```

### Nginx
`deploy/nginx.conf` is a drop-in configuration that aligns with the guidance below and expects certificates issued by Let's Encrypt (or equivalent) in `/etc/letsencrypt`). Run it alongside the app if you prefer Nginx over Caddy.

```
server {
  listen 80;
  server_name ${SFS_DOMAIN};
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl http2;
  server_name ${SFS_DOMAIN};
  ssl_certificate /etc/letsencrypt/live/${SFS_DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${SFS_DOMAIN}/privkey.pem;

  client_max_body_size 200m;  # set >= MAX_FILE_SIZE_BYTES

  location / {
    proxy_pass http://app:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 600s;  # large downloads/uploads
    proxy_send_timeout 600s;
  }
}
```

## Bare metal (systemd)
```
[Unit]
Description=Simple File Server
After=network.target

[Service]
User=sfs
Group=sfs
Environment=RUST_LOG=info
Environment=SERVER_PORT=8080
Environment=DATABASE_URL=sqlite:///var/lib/sfs/app.db?mode=rwc&cache=shared
Environment=STORAGE_ROOT=/var/lib/sfs/storage
Environment=SESSION_KEY=base64:...
Environment=DOWNLOAD_TOKEN_SECRET=base64:...
Environment=COOKIE_SECURE=true
ExecStart=/usr/local/bin/simple_file_server
Restart=always
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sfs

[Install]
WantedBy=multi-user.target
```

Create directories and permissions:
- Create `/var/lib/sfs` and `/var/lib/sfs/storage` owned by `sfs:sfs`.

## Database migrations
- Executed at startup via `sqlx::migrate!()`; ensure app has write permission to DB path.
- Automatic schema updates on application restart.

## Backups
- Quiesce DB with `sqlite3 /path/app.db ".backup /backup/app-$(date +%F).db"` or `VACUUM INTO`.
- Snapshot the storage directory concurrently.
- Consider excluding `tower_sessions` table from backups as it contains transient data.

## Observability
- Logs: stdout; use JSON in prod if desired (`LOG_JSON=true`).
- Structured logging with tracing for better observability.
- Metrics (optional): expose Prometheus via `metrics` + `axum-prometheus`.

## Sizing & limits
- Ensure reverse proxy `client_max_body_size` >= MAX_FILE_SIZE_BYTES.
- Tune read/write timeouts for large uploads/downloads.
- Disk capacity monitoring for STORAGE_ROOT.
- Memory usage monitoring for paste preview functionality.

## Production considerations
- Set `COOKIE_SECURE=true` when using HTTPS.
- Use strong secrets for `SESSION_KEY` and `DOWNLOAD_TOKEN_SECRET`.
- Configure proper backup retention policies.
- Monitor disk space and cleanup job effectiveness.
- Consider log rotation for long-running deployments.
- Set up monitoring for application health and performance.
