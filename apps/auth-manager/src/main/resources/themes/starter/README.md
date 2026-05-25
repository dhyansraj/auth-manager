# Tenant Theme Starter

This is a starter pack for customising your Keycloak sign-in, account, and
email screens. The theme applies to every login screen users hit while
signing into the tenant -- including the BFF + PKCE flow served at the
tenant hostname -- plus the password-reset / verify-email mails KC sends
on behalf of the tenant.

This starter targets **Keycloak 26.3.3** and uses **PatternFly v5**
selectors (`.pf-v5-c-*`), which is what the `keycloak.v2` parent theme
emits. Earlier PatternFly-v4 selectors (`.pf-c-*`, `.card-pf`) are NOT
emitted and will silently no-op.

## Quickstart

1. Edit `login/resources/img/logo.svg` -- drop in your real logo (see
   "Layout constraints" below for sizing).
2. Edit `login/resources/css/custom.css` -- at minimum, change `--kc-primary`
   to your brand colour. The file is organised by visual area, with
   comments at each section explaining what it styles.
3. (Optional) Uncomment + customise message strings in
   `login/messages/messages_en.properties` and
   `email/messages/messages_en.properties`.
4. Re-zip the contents (NOT a wrapper folder -- the `login/`, `account/`,
   and `email/` directories must sit at the zip root).
5. Upload via the admin-ui Branding tab.
6. Open an incognito window on your tenant hostname and confirm the
   sign-in page looks right.

The change is live on the **next page load**. Server-side theme caching
and the browser-side `max-age` are both disabled at the KC level, so you
no longer need a hard-reload after upload.

## Where it uploads

The admin-ui Branding tab handles the upload. Behind the scenes
auth-manager validates the zip (see "Forbidden content" below), stores
the bytes, and materialises them onto Keycloak's filesystem under
`/opt/keycloak/themes/t-<tenant-slug>/`. The realm is already configured
to point its login + account + email theme at `t-<tenant-slug>`, so the
upload "just works" on the next page load.

## Layout

Keycloak themes are structured as `<type>/...` subdirectories. The
starter ships with three types:

- `login/` -- sign-in, registration, password reset pages (the screens
  users see during the BFF/PKCE flow)
- `account/` -- the user's self-service account console
- `email/` -- subject lines + bodies for password-reset / verify-email
  mails. Only the message bundle is customised by default; KC's stock
  FTL templates are inherited from the parent `keycloak` theme.

You can add or remove types (`admin/`, `welcome/`) as needed; at least
one `<type>/theme.properties` is required.

## Layout constraints (logo sizing)

The `keycloak.v2` parent theme places branding (logo /
`.pf-v5-c-login__header`) in a **narrow right-hand column** on wider
viewports. CSS alone cannot widen that column -- doing so requires
overriding the parent FTL template, which the upload validator blocks
(no `.ftl` files allowed).

Practical implications for your logo:

- Keep it **square or vertical**. A 120x120 square (or up to ~160px
  wide) renders well in the reserved column.
- **Avoid wide landscape wordmarks** -- they'll be scaled down to fit
  the column and the text becomes illegible.
- The starter's placeholder is a 120x120 circle with the letter "B" --
  same aspect ratio as what works in production. Use it as a sizing
  reference.

If you absolutely need a wider logo, your options are:

1. Build a different parent theme (out of scope for tenants; requires
   a custom KC image).
2. Use a tall, narrow vertical logo and accept the column constraint.

## What you can change

- `<type>/theme.properties` -- declares `parent=`. Use `keycloak.v2`
  for `login/`, `keycloak.v2.account` for `account/`, `keycloak` for
  `email/`. Add message-bundle includes here.
- `<type>/resources/css/custom.css` -- your CSS overrides. The `:root`
  block at the top of the starter's login CSS exposes `--kc-*` tokens
  read by the selectors *in that same file* -- they are not consumed
  by the parent theme, just by the rules below them.
- `<type>/resources/img/*` -- logos and icons. Allowed: `.png`, `.jpg`,
  `.webp`, `.ico`, `.svg`.
- `<type>/resources/fonts/*` -- custom fonts. Allowed: `.woff`,
  `.woff2`, `.ttf`, `.otf`.
- `<type>/messages/messages_*.properties` -- i18n overrides per locale.
  Only override the keys you want to change; everything else inherits
  from the parent theme's catalog (so an empty file is a valid no-op).

## Selector cheat sheet

The most-likely-to-customise selectors in `login/resources/css/custom.css`,
with their visible effect:

| Selector | Visible effect |
| --- | --- |
| `html, body, .login-pf` | Page background outside the card |
| `.pf-v5-c-login__main` | Card padding / border / shadow |
| `.pf-v5-c-login__header::before` | Logo image (background-image) |
| `.pf-v5-c-title.pf-m-3xl` | Big "Sign in to <realm>" title |
| `.pf-v5-c-form-control` | Email / password input shells |
| `.pf-v5-c-form-control:focus` | Focus ring colour + width |
| `.pf-v5-c-button.pf-m-primary` | Submit button (Continue / Sign in) |
| `.pf-v5-c-button.pf-m-secondary` | Social IdP buttons (Google, GitHub) |
| `.pf-v5-c-brand` + `.pf-v5-c-button img` | IdP icon sizing (MUST cap to ~20px) |
| `.pf-v5-c-login a` | "Forgot password?" + other links |
| `.pf-v5-c-form__helper-text .pf-m-error` | Inline validation error text |
| `.pf-v5-c-login__main-footer-band` | "Or continue with" divider band below the primary submit; defaults to a 1px grey `border-top` (visible as a thin line under the button — override `border-top: 0 !important` to remove, or set a brand colour) |

## Custom fonts

External font CDNs (Google Fonts, Adobe Fonts, etc.) are **not allowed**.
Both `@import` and any absolute `url(...)` in CSS are rejected by the
upload validator (`css_import_forbidden` / `css_external_url`). The
reasons are privacy (the user's browser would hit the CDN's IP on every
sign-in — a GDPR concern in some jurisdictions), tighter CSP
(`font-src 'self'` everywhere), and removing a third-party availability
dependency from the critical-path sign-in screen.

To use a custom font, **bundle the font files in the zip** and reference
them with a relative path. Example using Inter:

1. Download the woff2 files from the foundry or Google Fonts download.
2. Drop them under `login/resources/fonts/` (and `account/resources/fonts/`
   if you want the same font in the account console). The whitelist
   accepts `.woff`, `.woff2`, `.ttf`, `.otf`.
3. Add an `@font-face` block at the top of `login/resources/css/custom.css`,
   above the `:root` block:

   ```css
   @font-face {
     font-family: "Inter";
     font-style: normal;
     font-weight: 400;
     font-display: swap;
     src: url("../fonts/Inter-Regular.woff2") format("woff2");
   }
   @font-face {
     font-family: "Inter";
     font-style: normal;
     font-weight: 700;
     font-display: swap;
     src: url("../fonts/Inter-Bold.woff2") format("woff2");
   }
   ```

4. Update `--kc-font-family` in `:root` to put your font first, then keep
   the system stack as fallback:

   ```css
   --kc-font-family: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
   ```

The `url(...)` paths are relative to the CSS file (`login/resources/css/`),
which is why `../fonts/` resolves to `login/resources/fonts/`. Keep an eye
on the 800 KB total-zip budget if you ship multiple weights — woff2 files
typically run 30-80 KB each.

## Common PF v5 quirks to watch for

Visual artefacts that show up out-of-the-box from PatternFly v5's defaults
and aren't obvious from the live DOM. Override in `custom.css` as needed:

- **Thin line under the primary submit button.** PF v5's
  `.pf-v5-c-login__main-footer-band` (the "Or continue with" / locale strip)
  ships with a 1px grey `border-top`. Renders as a hairline directly below
  your styled Continue button, slightly wider than the pill. Fix:
  ```css
  .pf-v5-c-login__main-footer-band {
    border-top: 0 !important;
  }
  ```
  Keep the verbal "Or continue with" text as the section divider if your
  layout still benefits from it.

- **Native button bevel on macOS Chrome.** `.pf-v5-c-button` should ship
  with `appearance: none`, but some builds leave `appearance: auto`. If
  your primary button shows a faint OS-native bevel/shadow, force it:
  ```css
  .pf-v5-c-button.pf-m-primary { appearance: none !important; }
  ```

- **IdP icons rendered at natural size.** PF v5 doesn't constrain the
  `<svg>` inside social IdP buttons. Without an explicit cap, icons render
  at intrinsic size and push the button to full card width. The starter
  CSS already handles this (`pf-v5-c-brand` + `svg` selectors); keep that
  block if you replace the rest of the file.

These are the artefacts that have bitten existing tenants. Surface
additional quirks here as they're found.

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
  what gets stored -- so test your SVG renders as you expect after upload.
- **Properties files cannot contain HTML/JS.** Lines containing `<script>`,
  `<iframe>`, `javascript:`, or `on*=` event handlers are rejected.
- **Magic bytes must match the extension.** A `.png` that isn't really a PNG
  (polyglot detection) is rejected.

## Size limits

- Total zip (compressed): 800 KB
- Total uncompressed: 5 MB
- Max files: 200
- Per-file: 2 MB

## Notes on KC v2 CSS variables

The `--kc-*` custom properties at the top of `login/resources/css/custom.css`
are scoped **to that file**. The selectors below read them via `var()`;
the parent theme does NOT read them. Treat them as a local brand-token
convenience. If you want to recolour something the starter doesn't already
cover, inspect the rendered page with browser devtools and add a selector
(or use one from the cheat sheet above).

The account console additionally honours a small set of PatternFly v5
design tokens (`--pf-v5-global-*`) directly; those overrides live in
`account/resources/css/custom.css`.
