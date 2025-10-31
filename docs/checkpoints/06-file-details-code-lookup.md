# 06) File details & code lookup

## Objectives
- Allow anyone to look up a file by code and view details if not expired.

## Steps
1. Route: GET `/f/:code`
   - Validate code pattern; query DB; check `expires_at`.
2. Template `file.html` shows:
   - name, size, created_at, expires_at
   - button to generate direct link (POST `/f/:code/link`)
3. Error handling:
   - 404 if not found; 410 if expired

## Acceptance criteria
- Visiting known code shows details; expired returns a friendly 410.
