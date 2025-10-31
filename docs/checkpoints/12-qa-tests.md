# 12) QA & tests

## Objectives
- Verify critical paths manually and optionally via integration tests.

## Steps
1. Manual tests:
   - Upload small file; copy direct link; download via token.
   - Enter wrong code; see 404/410.
   - Oversize upload; see 413.
   - Change settings; see behavior change.
2. Integration tests (optional):
   - Spawn server on random port against temp dirs and temp SQLite.
   - Use `reqwest` to simulate login, upload, link gen, and download.
3. Non-functional:
   - Restart app and verify persistence; check logs for errors.

## Acceptance criteria
- All core flows succeed; errors handled gracefully; no panics.
