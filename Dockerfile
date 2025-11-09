# syntax=docker/dockerfile:1.6

########################################
# Builder                                                               #
########################################
FROM rust:1.88-alpine3.20 AS builder

# Allow incremental builds to reuse dependencies
RUN apk add --no-cache \
        build-base \
        openssl-dev \
        sqlite-dev \
        sqlite \
        pkgconfig

WORKDIR /app

# Build for musl so the resulting binary works on Alpine
RUN rustup target add x86_64-unknown-linux-musl

# Pre-fetch dependencies to maximise layer caching
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf "fn main() {}\n" > src/main.rs \
    && cargo fetch --target x86_64-unknown-linux-musl \
    && rm -rf src

# Copy the remainder of the source code
COPY . .

# Create a temporary database for the build
RUN mkdir -p /tmp/sqlx-tmp && \
    sqlite3 /tmp/sqlx-tmp/temp.db < sql/schema.sql

ENV DATABASE_URL=sqlite:///tmp/sqlx-tmp/temp.db

# Compile the application
RUN cargo build --locked --release --target x86_64-unknown-linux-musl

########################################
# Runtime                                                               #
########################################
FROM alpine:3.20 AS runtime

# Packages needed at runtime: CA bundle for outbound TLS, sqlite libs, wget for healthchecks,
# and su-exec for privilege drop.
RUN apk add --no-cache \
        ca-certificates \
        sqlite-libs \
        wget \
        su-exec

# Non-root user to run the server
RUN addgroup -S sfs && adduser -S sfs -G sfs

WORKDIR /app

# Default runtime configuration geared towards container deployments
ENV RUST_LOG=info \
    SERVER_BIND_ADDR=0.0.0.0 \
    SERVER_PORT=8080 \
    DATABASE_URL=sqlite:////data/app.db?mode=rwc&cache=shared \
    STORAGE_ROOT=/data/storage \
    COOKIE_SECURE=true

# Copy the release binary from the builder stage
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/simple_file_server /app/simple_file_server

# Copy entrypoint (added separately) to drop privileges after ensuring writable volumes
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /data/storage \
    && chown -R sfs:sfs /data /app

# Declare persistent volumes for database and file storage
VOLUME ["/data", "/data/storage"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/simple_file_server"]
