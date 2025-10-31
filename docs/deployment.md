# Deployment

This guide covers containerized and bare-metal/systemd deployments with reverse proxy and TLS.

## Container image (Dockerfile outline)
Use a small, static binary for reliability. Example multi-stage:

```
# Build stage
FROM rust:1.81-bullseye AS builder
WORKDIR /app
# Install SQLx CLI offline cache optionally if needed for compile-time checks
# COPY sqlx-data.json ./sqlx-data.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release

# Runtime stage
FROM gcr.io/distroless/cc-debian12
USER 10001:10001
WORKDIR /app
COPY --from=builder /app/target/release/simple_file_server /app/simple_file_server
# Create writable dirs via volumes (storage, db)
VOLUME ["/data/storage", "/data"]
ENV RUST_LOG=info \
    SERVER_BIND_ADDR=0.0.0.0 \
    SERVER_PORT=8080 \
    DATABASE_URL=sqlite:////data/app.db?mode=rwc&cache=shared&busy_timeout=5000 \
    STORAGE_ROOT=/data/storage \
    COOKIE_SECURE=true
EXPOSE 8080
ENTRYPOINT ["/app/simple_file_server"]
```

Notes:
- Use `distroless` or `alpine:3` if you need a shell (distroless has no shell).
- Ensure `STORAGE_ROOT` and DB path are persistent volumes.

## Docker Compose

```
services:
  app:
    image: ghcr.io/yourorg/simple-file-server:latest
    environment:
      - RUST_LOG=info
      - SERVER_PORT=8080
      - DATABASE_URL=sqlite:////data/app.db?mode=rwc&cache=shared&busy_timeout=5000
      - STORAGE_ROOT=/data/storage
      - SESSION_KEY=${SESSION_KEY}
      - DOWNLOAD_TOKEN_SECRET=${DOWNLOAD_TOKEN_SECRET}
      - COOKIE_SECURE=true
    volumes:
      - sfs-db:/data
      - sfs-storage:/data/storage
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "/bin/sh", "-c", "wget -qO- http://localhost:8080/ | head -n1 >/dev/null"]
      interval: 30s
      timeout: 5s
      retries: 3
volumes:
  sfs-db: {}
  sfs-storage: {}
```

## Reverse proxy

### Caddy (recommended)
```
:80 {
  redir https://{host}{uri}
}

:443 {
  encode zstd gzip
  tls you@example.com
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
```

### Nginx
```
server {
  listen 80;
  server_name files.example.com;
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl http2;
  server_name files.example.com;
  ssl_certificate /etc/letsencrypt/live/files.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/files.example.com/privkey.pem;

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
Environment=DATABASE_URL=sqlite:////var/lib/sfs/app.db?mode=rwc&cache=shared&busy_timeout=5000
Environment=STORAGE_ROOT=/var/lib/sfs/storage
Environment=SESSION_KEY=base64:...
Environment=DOWNLOAD_TOKEN_SECRET=base64:...
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

## Backups
- Quiesce DB with `sqlite3 /path/app.db ".backup /backup/app-$(date +%F).db"` or `VACUUM INTO`.
- Snapshot the storage directory concurrently.

## Observability
- Logs: stdout; use JSON in prod if desired.
- Metrics (optional): expose Prometheus via `metrics` + `axum-prometheus`.

## Sizing & limits
- Ensure reverse proxy `client_max_body_size` >= MAX_FILE_SIZE_BYTES.
- Tune read/write timeouts for large uploads/downloads.
- Disk capacity monitoring for STORAGE_ROOT.
