# 03) Templates & base UI

## Objectives
- Establish base HTML templates with Pico.css and htmx; render home and login.

## Steps
1. Add Askama templates:
   - `base.html`: includes Pico.css, htmx, feather icons; header/footer; CSRF meta tag
   - `home.html`, `login.html`, `upload.html`, `file.html`, `settings.html`
2. Inject `ui_brand_name` into layout from settings.
3. Add routes that render templates with minimal context structs.
4. Add copy-to-clipboard helper JS for later.

## Snippets
- Pico.css CDN: `https://unpkg.com/@picocss/pico@latest/css/pico.min.css`
- htmx CDN: `https://unpkg.com/htmx.org@1.9.12`

## Acceptance criteria
- GET `/` and `/login` return styled pages with base layout applied.
