# 05) Upload (authenticated)

## Objectives
- Stream file uploads with enforced max size; persist metadata and bytes.

## Steps
1. Routes:
   - GET `/upload` (or show on `/` when authed)
   - POST `/upload` multipart
2. Limits:
   - Apply `RequestBodyLimitLayer` set to `MAX_FILE_SIZE_BYTES + overhead`.
3. Streaming:
   - Write to temp file; track byte count; abort on overflow with 413.
4. IDs & codes:
   - `file_id`: ulid/cuid2
   - `code`: nanoid with alphabet excluding ambiguous chars; format `XXXX-XXXX`
5. Storage path:
   - `storage_root/YYYY/MM/DD/<file_id>`; move temp file atomically.
6. DB insert:
   - `files` row with owner_user_id, original_name, size_bytes, content_type, checksum(optional), created_at, expires_at
7. Redirect:
   - On success, `302 -> /f/<code>`

## Acceptance criteria
- Upload small file succeeds and is listed with a code.
- Oversized upload returns 413 without leaving temp file behind.
