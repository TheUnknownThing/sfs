# Simple File Server

Welcome! This repository contains a Rust-based file sharing server with a clean web UI, short file codes, and temporary direct download links.

## What is this?
- Upload files (login required), share a short code, and anyone can fetch a temporary direct link to download.
- Built with Axum, SQLx (SQLite), Askama, Pico.css, and secure defaults.

## Quick Start (Local Development)

1.  **Clone the repository.**

2.  **Set up configuration:**
    Copy the example `.env` file. You must generate secure random keys for `SESSION_KEY` and `DOWNLOAD_TOKEN_SECRET`.
    ```bash
    cp .env.example .env
    # Generate secrets
    echo "SESSION_KEY=base64:$(openssl rand -base64 32)" >> .env
    echo "DOWNLOAD_TOKEN_SECRET=base64:$(openssl rand -base64 32)" >> .env
    ```

    **Remember:**
    - Keep these keys secret.
    - **Remove the existing** `SESSION_KEY` and `DOWNLOAD_TOKEN_SECRET` lines from `.env` after adding the new ones.

3. **Initialize the database:**
    You can use the provided script or manually create the database.
    ```bash
    mkdir -p data
    sqlite3 data/app.db < sql/schema.sql
    ```

    If you prefer using a different database location, adjust the `DATABASE_URL` in your `.env` file accordingly.

4. **Modify the env accordingly**
   Update the `DATABASE_URL` in your `.env` file to point to the new database location:
   ```bash
   DATABASE_URL=sqlite:data/app.db?mode=rwc&cache=shared
   ```

   This assumes you are using the above `data/app.db` path. Adjust as necessary. It is also worth noting that you may want need to change the `STORAGE_ROOT` variable to point to a valid directory for uploaded file storage.

5.  **Run the application:**
    ```bash
    cargo run
    ```

## Quick Start (Docker)

1. **Set secrets:** Create a `.env` file (or export the variables in your shell) with values for `SESSION_KEY` and `DOWNLOAD_TOKEN_SECRET`. Example:
    ```bash
    export SESSION_KEY="base64:$(openssl rand -base64 32)"
    export DOWNLOAD_TOKEN_SECRET="base64:$(openssl rand -base64 32)"
    ```

2. **Build and start the container:** The repository ships with a production-focused image that exposes port 8080.
    ```bash
    docker compose up --build
    ```

    The application listens on `http://localhost:8080`. Named volumes store the SQLite database and uploaded files so restarts retain data.

    Looking for TLS termination? Sample `deploy/Caddyfile` and `deploy/nginx.conf` configs are included, but you decide if and how to run a reverse proxy.

3. **Use the published image:** Once a GitHub release is published, an image is pushed to `ghcr.io/theunknownthing/sfs`. Pull it directly:
    ```bash
    docker pull ghcr.io/theunknownthing/sfs:latest
    ```
    You can swap the `build` section in `docker-compose.yml` with that image for faster deployments.

## Deployment (Production)

1.  **Build the release binary:**
    ```bash
    cargo build --release
    ```
    The binary will be located at `target/release/simple_file_server`.

2.  **Prepare the environment:**
    On your server, create a directory for the application. Copy the `simple_file_server` binary to this directory.

3.  **Configure the application:**
    Create a `.env` file in the same directory as the binary. Start by copying the contents of `.env.example`.

    **Important:**
    - Set `SERVER_BIND_ADDR` to `0.0.0.0` to listen on all network interfaces.
    - Set `COOKIE_SECURE=true` if you are running behind a TLS proxy (which is highly recommended).
    - Generate strong, unique values for `SESSION_KEY` and `DOWNLOAD_TOKEN_SECRET` as shown in the "Quick Start" section.
    - Set `BOOTSTRAP_ADMIN_USERNAME` and `BOOTSTRAP_ADMIN_PASSWORD` on the first run to create an initial admin account. **Remove these from the `.env` file after the first run.**
    - Adjust `DATABASE_URL` and `STORAGE_ROOT` as needed for your production environment.

4.  **Create data directories:**
    The application needs directories for the database and file storage. By default, it uses `data/` and `data/storage/`.
    ```bash
    mkdir -p data/storage
    ```
    Ensure the user running the application has write permissions to these directories.

5.  **Run the server:**
    ```bash
    ./simple_file_server
    ```

## Licensing
This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.