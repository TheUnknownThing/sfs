# 09) Cleanup job

## Objectives
- Periodically delete expired files and prune database rows.

## Steps
1. Spawn background task on startup with interval (e.g., 15 min).
2. Query expired files: `expires_at <= now`.
3. Delete file from disk (ignore missing) and remove DB row in a transaction.
4. Log actions; keep metrics counters (optional).

## Acceptance criteria
- Expired files are removed on schedule; system remains responsive during cleanup.
