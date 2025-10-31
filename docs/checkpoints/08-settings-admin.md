# 08) Settings (admin)

## Objectives
- Admin-editable settings persisted in DB with live effect.

## Steps
1. Route: GET `/settings` (admin only); render form with current values.
2. Route: POST `/settings` (admin only); validate ranges and update row.
3. Cache strategy: read-through cache with small TTL (e.g., 10s) or always read DB.
4. Reflect changes immediately for new requests and link generation.

## Acceptance criteria
- Changing max file size alters upload behavior without restart.
- Brand name updates UI header after refresh.
