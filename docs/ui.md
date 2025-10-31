# Web UI

Minimal server-rendered UI using Pico.css and htmx.

## Style & assets
- Pico.css (CDN): https://unpkg.com/@picocss/pico@latest/css/pico.min.css
- htmx (CDN): https://unpkg.com/htmx.org@1.9.12
- Feather icons (CDN): https://unpkg.com/feather-icons
- Base template includes header with brand name from settings

## Pages

### Layout
- Top nav: brand (settings.ui_brand_name), Login/Logout, Upload (if authed)
- Footer: small note with version and links

### Home (/)
- Logged out:
  - Card with "Enter file code" form
  - On submit: GET /f/:code
  - Link to Login
- Logged in:
  - Upload form (multipart). Fields:
    - File input
    - Expiration (select: 1 day, 3 days, 7 days, custom hours)
    - Submit
  - Recent uploads list

### File details (/f/:code)
- Show filename, size, expires_at
- Button: "Generate direct link" (POST /f/:code/link)
- Response snippet shows:
  - Direct link in a readonly input
  - Button: Copy (uses clipboard API)

### Settings (/settings, admin)
- Fields:
  - Max file size (MB)
  - Default expiration (hours)
  - Direct link TTL (minutes)
  - Brand name
- Save -> POST /settings

## Behavior
- Copy button: `navigator.clipboard.writeText(link)` and toast message
- Use htmx to inject the direct-link snippet without reloading the page
- CSRF: include hidden input token in all forms

## Accessibility & i18n
- Use semantic HTML, labels tied to inputs
- Provide aria-live region for copy success feedback
- Keep strings centralized server-side for easy translation later

## Error states
- File not found/expired: friendly page with hint to check code
- Oversized upload: clear message shows current max size
- Auth errors: redirect to login with next param
