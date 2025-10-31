# 11) Dockerization & deployment

## Objectives
- Containerize the app and run with persistent volumes and health checks.

## Steps
1. Dockerfile: multi-stage build to a small runtime (distroless or alpine).
2. Compose file: mount volumes for `/data` and `/data/storage`, expose port 8080.
3. Healthcheck: simple HTTP GET of `/`.
4. Reverse proxy: configure Caddy/Nginx from deployment doc.

## Acceptance criteria
- Container starts and serves pages; uploads and downloads work; data persists across restarts.
