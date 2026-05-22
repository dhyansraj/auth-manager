# Tenant Theme Starter

This is a starter pack for customising your Keycloak login + account pages.
Edit the files, zip the contents (NOT a wrapper folder — the `login/` and
`account/` directories must be at the zip root), and upload back to the
Branding tab.

## Layout

Keycloak themes are structured as `<type>/...` subdirectories. The starter
ships with two types:

- `login/` — sign-in, registration, password reset pages
- `account/` — the user's self-service account console

You can add or remove types (`email/`, `admin/`, `welcome/`) as needed; at
least one `<type>/theme.properties` is required.

## What you can change

- `<type>/theme.properties` — must declare `parent=keycloak.v2` for `login/`
  and `parent=keycloak.v2.account` for `account/`. Add message-bundle includes
  here.
- `<type>/resources/css/custom.css` — your CSS overrides. CSS variables
  stubbed at the top are pre-wired by the parent theme; override them and
  you're done.
- `<type>/resources/img/*` — logos and icons. Allowed: `.png`, `.jpg`,
  `.webp`, `.ico`, `.svg`.
- `<type>/resources/fonts/*` — custom fonts. Allowed: `.woff`, `.woff2`,
  `.ttf`, `.otf`.
- `<type>/messages/messages_*.properties` — i18n overrides per locale.

## What is forbidden

The auth-manager prescans every uploaded file:

- **No executable content.** `.html`, `.htm`, `.ftl`, `.js`, `.mjs`, `.ts`,
  and anything else outside the allow-list is rejected outright.
- **No external network access in CSS.** No `@import`, no `url(http://...)`,
  no `url(https://...)`, no `url(//...)`. Relative paths only.
- **No CSS exploits.** `expression(...)`, `behavior:`, and `javascript:` URLs
  are rejected.
- **SVGs are sanitized.** `<script>`, `on*=` event handlers, `<foreignObject>`,
  and remote `href` / `xlink:href` values are stripped. The sanitized SVG is
  what gets stored — so test your SVG renders as you expect after upload.
- **Properties files cannot contain HTML/JS.** Lines containing `<script>`,
  `<iframe>`, `javascript:`, or `on*=` event handlers are rejected.
- **Magic bytes must match the extension.** A `.png` that isn't really a PNG
  (polyglot detection) is rejected.

## Size limits

- Total zip (compressed): 800 KB
- Total uncompressed: 5 MB
- Max files: 200
- Per-file: 2 MB
