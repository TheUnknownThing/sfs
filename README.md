# Simple File Server

Welcome! This repository contains a Rust-based file sharing server with a clean web UI, short file codes, and temporary direct download links.

## Start here
- Project docs live in `docs/`
  - Overview: `docs/README.md`
  - Architecture: `docs/architecture.md`
  - Data model: `docs/data-model.md`
  - API: `docs/api.md`
  - UI: `docs/ui.md`
  - Security: `docs/security.md`
  - Configuration: `docs/config.md`
  - Deployment: `docs/deployment.md`
  - Implementation plan (summary): `docs/checkpoints.md`
  - Detailed implementation guides: `docs/checkpoints/` (open files 00–12)

## What is this?
- Upload files (login required), share a short code, and anyone can fetch a temporary direct link to download.
- Built with Axum, SQLx (SQLite), Askama, Pico.css, and secure defaults.

## Contributing
- Propose changes via PR.
- Keep docs updated when behavior changes.
- Follow the implementation checkpoints to add features iteratively.
