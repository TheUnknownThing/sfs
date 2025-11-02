# Simple File Server

Welcome! This repository contains a Rust-based file sharing server with a clean web UI, short file codes, and temporary direct download links.

## What is this?
- Upload files (login required), share a short code, and anyone can fetch a temporary direct link to download.
- Built with Axum, SQLx (SQLite), Askama, Pico.css, and secure defaults.

## Contributing
- Propose changes via PR.
- Keep docs updated when behavior changes.
- Follow the implementation checkpoints to add features iteratively.

## Quick Start (Local Development)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/simple_file_server.git
    cd simple_file_server
    ```

2.  **Set up configuration:**
    Copy the example `.env` file:
    ```bash
    cp .env.example .env
    ```
    You must generate secure random keys for `SESSION_KEY` and `DOWNLOAD_TOKEN_SECRET`. You can use `openssl` to do this:
    ```bash
    # Generate SESSION_KEY
    echo "SESSION_KEY=base64:$(openssl rand -base64 32)" >> .env
    # Generate DOWNLOAD_TOKEN_SECRET
    echo "DOWNLOAD_TOKEN_SECRET=base64:$(openssl rand -base64 32)" >> .env
    ```

3.  **Run the application:**
    ```bash
    cargo run
    ```
    The server will be running at `http://127.0.0.1:8080`.

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

4.  **Create data directories:**
    The application needs directories for the database and file storage. By default, it uses `data/` and `storage/`.
    ```bash
    mkdir -p data storage
    ```
    Ensure the user running the application has write permissions to these directories.

5.  **Run the server:**
    ```bash
    ./simple_file_server
    ```
    It is recommended to run the application as a systemd service or using another process manager to ensure it restarts automatically.

