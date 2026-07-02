<#-- mcpmesh-flexible login/template.ftl
     Wraps keycloak.v2's standard login layout in a CSS Grid with named slots.
     Slots are sourced from messages_en.properties (mcpmeshSlot<Name>Html keys).
     Layout variant is set via a body class controlled by the mcpLayoutVariant
     message key. When a slot's message is empty the corresponding <div> is
     omitted so the grid template's named area collapses cleanly.
-->
<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false displayWide=false showAnotherWayIfPresent=true>
<!DOCTYPE html>
<html class="${properties.kcHtmlClass!}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=yes">
  <meta name="robots" content="noindex, nofollow">
  <title>${msg("loginTitle",(realm.displayName!''))}</title>
  <link rel="icon" href="${url.resourcesPath}/img/favicon.ico" />
  <#if properties.stylesCommon?has_content>
    <#list properties.stylesCommon?split(' ') as style>
      <link href="${url.resourcesCommonPath}/${style}" rel="stylesheet" />
    </#list>
  </#if>
  <#if properties.styles?has_content>
    <#list properties.styles?split(' ') as style>
      <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
    </#list>
  </#if>
  <#if scripts??>
    <#list scripts as script>
      <script src="${script}" type="text/javascript"></script>
    </#list>
  </#if>
  <#-- Layout grid CSS is INLINED here because KC theme inheritance resolves
       properties.styles to the CHILD theme's value only — the parent's
       styles= setting is shadowed. Inlining keeps the grid layout always
       loaded regardless of what the child theme sets. -->
  <style>
    body.mcp-layout-centered {
      display: grid;
      grid-template-areas: "above-form" "form-area" "below-form" "footer";
      grid-template-columns: minmax(320px, 480px);
      justify-content: center;
      align-content: start;
      min-height: 100vh;
      padding: 2rem 1rem;
      gap: 1rem;
    }
    body.mcp-layout-centered .mcp-slot-marketing-left,
    body.mcp-layout-centered .mcp-slot-marketing-right { display: none; }
    body.mcp-layout-centered .mcp-slot-above-form { grid-area: above-form; }
    body.mcp-layout-centered .mcp-slot-form-area  { grid-area: form-area; }
    body.mcp-layout-centered .mcp-slot-below-form { grid-area: below-form; }
    body.mcp-layout-centered .mcp-slot-footer     { grid-area: footer; }

    body.mcp-layout-split-left {
      display: grid;
      grid-template-areas: "marketing-left form-area" "footer footer";
      grid-template-columns: 1fr 1fr;
      grid-template-rows: 1fr auto;
      min-height: 100vh;
      gap: 2rem;
    }
    body.mcp-layout-split-left .mcp-slot-marketing-left { grid-area: marketing-left; padding: 3rem; display: flex; flex-direction: column; justify-content: center; }
    body.mcp-layout-split-left .mcp-slot-marketing-right { display: none; }
    body.mcp-layout-split-left .mcp-slot-form-area { grid-area: form-area; display: flex; flex-direction: column; justify-content: center; padding: 2rem; max-width: 480px; }
    body.mcp-layout-split-left .mcp-slot-footer { grid-area: footer; }
    @media (max-width: 768px) {
      body.mcp-layout-split-left {
        grid-template-areas: "form-area" "marketing-left" "footer";
        grid-template-columns: 1fr;
      }
    }

    body.mcp-layout-split-right {
      display: grid;
      grid-template-areas: "form-area marketing-right" "footer footer";
      grid-template-columns: 1fr 1fr;
      grid-template-rows: 1fr auto;
      min-height: 100vh;
      gap: 2rem;
    }
    body.mcp-layout-split-right .mcp-slot-marketing-right { grid-area: marketing-right; padding: 3rem; display: flex; flex-direction: column; justify-content: center; }
    body.mcp-layout-split-right .mcp-slot-marketing-left { display: none; }
    body.mcp-layout-split-right .mcp-slot-form-area { grid-area: form-area; display: flex; flex-direction: column; justify-content: center; padding: 2rem; max-width: 480px; margin-left: auto; }
    body.mcp-layout-split-right .mcp-slot-footer { grid-area: footer; }
    @media (max-width: 768px) {
      body.mcp-layout-split-right {
        grid-template-areas: "form-area" "marketing-right" "footer";
        grid-template-columns: 1fr;
      }
    }

    body.mcp-layout-bleed {
      display: grid;
      place-items: center;
      min-height: 100vh;
      padding: 2rem 1rem;
    }
    body.mcp-layout-bleed .mcp-slot-marketing-left,
    body.mcp-layout-bleed .mcp-slot-marketing-right,
    body.mcp-layout-bleed .mcp-slot-above-form,
    body.mcp-layout-bleed .mcp-slot-below-form { display: none; }
    body.mcp-layout-bleed .mcp-slot-form-area { max-width: 480px; width: 100%; }
    body.mcp-layout-bleed .mcp-slot-footer { position: fixed; bottom: 1rem; left: 50%; transform: translateX(-50%); }

    .mcp-slot { box-sizing: border-box; }
    .mcp-slot-form-area .pf-v5-c-login { width: 100%; }

    /* ===== Social-only login (mcp-no-password) ========================
     * Hide username/password form when realm attribute
     * mcpmesh.passwordLoginEnabled=false. Inlined here (not in
     * mcp-layout.css) because tenant child themes typically override
     * `styles=` to point at their own custom.css, which excludes parent
     * CSS files. Inline rules always apply. UX-only gating: KC's flow
     * still accepts credentials POSTed directly to /login-actions. */
    body.mcp-no-password #kc-form-login,
    body.mcp-no-password #kc-form-forgot-password,
    body.mcp-no-password .pf-v5-c-form__helper-text,
    body.mcp-no-password #kc-registration-container,
    body.mcp-no-password .pf-v5-c-login__main-footer-band {
      display: none !important;
    }
    body.mcp-no-password #kc-social-providers { padding-top: 1rem; }

    /* ===== Social-button border + focus =============================
     * The stray border on "Continue with X" is PatternFly v5 drawing a
     * SECOND border via ::after (default blue #0066CC, and at the PF
     * border-radius ~3px, so it shows as a rectangle behind the button's
     * own rounded <a> border). Tenant themes style the <a> border but never
     * ::after, so PF's competing rectangle leaks through. Remove it entirely
     * — the tenant's <a> border is the intended one — and kill the UA blue
     * :focus-visible outline. Inlined (not mcp-layout.css) so it survives
     * the child `styles=` override and reaches every tenant theme;
     * structural selector, not the PF class which shifts between KC
     * versions. Tenants can add their own ::after border in custom.css. */
    #kc-social-providers a::after {
      border-color: transparent !important;
    }
    #kc-social-providers a:focus,
    #kc-social-providers a:focus-visible {
      outline: none !important;
      box-shadow: none !important;
    }

    /* ===== Apple social-button logo ================================
     * The klausbetz Apple SPI sets the button's iconClasses to the
     * FontAwesome class `fa fa-apple`, but keycloak.v2 is PatternFly and
     * ships no FontAwesome font, so the glyph renders blank — the "Sign in
     * with Apple" button shows text only while Google shows its logo. Draw
     * the official Apple logo with a CSS mask, using `background-color:
     * currentColor` + mask so it inherits the button's text color and adapts
     * per tenant (white on dark buttons, dark on light) with no hardcoded
     * fill. Inlined here (not in mcp-layout.css) so it survives child themes'
     * `styles=` override and reaches every tenant, matching the ::after
     * border fix above.
     *
     * Layout mirrors Google: that button is a space-between flex row with two
     * children — a leading <svg> logo (pinned far-left) and a
     * <span class="pf-v5-u-m-auto"> label (margin:auto centers it). Apple's
     * label arrives as the <a>'s only child <span class="fa fa-apple">, so we
     * add the logo as a flex child via the anchor's ::before (pinned left) and
     * center the label span with margin:auto. */
    #kc-social-providers #social-apple::before {
      content: "";
      flex: 0 0 auto;
      width: 1.15em;
      height: 1.5em;
      background-color: currentColor;
      -webkit-mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 384 512'%3E%3Cpath d='M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z'/%3E%3C/svg%3E") center / contain no-repeat;
      mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 384 512'%3E%3Cpath d='M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z'/%3E%3C/svg%3E") center / contain no-repeat;
    }
    /* center the label in the remaining space, mirroring Google's
     * pf-v5-u-m-auto text span */
    #kc-social-providers #social-apple .fa-apple {
      margin: auto;
    }
    /* ===== Input legibility — foreground follows the theme =============
     * PatternFly wraps inputs in a .pf-v5-c-form-control span that resets
     * text color to PF's light-theme default (#151515), which is invisible on
     * a tenant's dark input. The themed text color lives on .mcp-slot-form-area
     * (this template's form container). Force BOTH the PF span AND the input to
     * `color: inherit` so the chain flows from .mcp-slot-form-area down — text
     * then follows the theme automatically (dark theme → light text, light
     * theme → dark text) with no dependency on which token a tenant set.
     * Verified against the live rendered login (computed color 245,240,242).
     * Inlined here so it survives the child `styles=` override, like the rules
     * above. */
    .mcp-slot-form-area .pf-v5-c-form-control,
    .mcp-slot-form-area .pf-v5-c-form-control > input,
    .mcp-slot-form-area input {
      color: inherit !important;
    }
    .mcp-slot-form-area input::placeholder {
      color: inherit !important;
      opacity: 0.6;
    }
    /* Browser autofill forces its own light bg + dark text, ignoring the theme.
     * Suppress the autofill background repaint with the long transition (so the
     * input keeps its themed/transparent background) and fill the autofilled
     * text with the input's now-inherited color. */
    .mcp-slot-form-area input:-webkit-autofill,
    .mcp-slot-form-area input:-webkit-autofill:hover,
    .mcp-slot-form-area input:-webkit-autofill:focus,
    .mcp-slot-form-area input:-webkit-autofill:active {
      -webkit-text-fill-color: currentColor !important;
      caret-color: currentColor;
      transition: background-color 600000s 0s, color 600000s 0s;
    }
  </style>
</head>
<#-- Read the per-realm password-login flag set by auth-manager's
     LoginMethodService. Absence → "true" → password ON (default). Compared
     against the literal "false" so any other value also reads as ON. -->
<#assign mcpPasswordDisabled = (realm.attributes["mcpmesh.passwordLoginEnabled"]!"true") == "false">
<body class="${properties.kcBodyClass!} mcp-layout-${msg('mcpLayoutVariant','centered')}${mcpPasswordDisabled?then(' mcp-no-password', '')}">
  <#if msg("mcpmeshSlotMarketingLeftHtml","")?length gt 0>
    <aside class="mcp-slot mcp-slot-marketing-left">${msg("mcpmeshSlotMarketingLeftHtml")?no_esc}</aside>
  </#if>

  <div class="mcp-slot mcp-slot-form-area">
    <#if msg("mcpmeshSlotAboveFormHtml","")?length gt 0>
      <div class="mcp-slot mcp-slot-above-form">${msg("mcpmeshSlotAboveFormHtml")?no_esc}</div>
    </#if>

    <#-- kc.v2 login card scaffolding. We replicate the DOM that the kc.v2
         template uses for the page header + main + content so the CSS classes
         (kcLoginClass, kcContainerClass, kcMainClass, kcContentClass) still
         apply. The <#nested> sections are populated by the page-specific
         templates (login.ftl, register.ftl, etc.). -->
    <div class="${properties.kcLoginClass!}">
      <div class="${properties.kcContainerClass!}">
        <header class="${properties.kcHeaderClass!}">
          <#-- Nest login.ftl's "header" section inside <h1>. Mirrors
               keycloak.v2 and avoids the duplicate-title bug from
               rendering loginTitleHtml here AND letting login.ftl's
               header section render as separate text below. -->
          <h1 id="kc-page-title"><#nested "header"></h1>
        </header>
        <main class="${properties.kcMainClass!}">
          <div class="${properties.kcContentClass!}">
            <#nested "form">
            <#nested "info">
            <#nested "socialProviders">
          </div>
        </main>
      </div>
    </div>

    <#if msg("mcpmeshSlotBelowFormHtml","")?length gt 0>
      <div class="mcp-slot mcp-slot-below-form">${msg("mcpmeshSlotBelowFormHtml")?no_esc}</div>
    </#if>
  </div>

  <#if msg("mcpmeshSlotMarketingRightHtml","")?length gt 0>
    <aside class="mcp-slot mcp-slot-marketing-right">${msg("mcpmeshSlotMarketingRightHtml")?no_esc}</aside>
  </#if>

  <#if msg("mcpmeshSlotFooterHtml","")?length gt 0>
    <footer class="mcp-slot mcp-slot-footer">${msg("mcpmeshSlotFooterHtml")?no_esc}</footer>
  </#if>
</body>
</html>
</#macro>
