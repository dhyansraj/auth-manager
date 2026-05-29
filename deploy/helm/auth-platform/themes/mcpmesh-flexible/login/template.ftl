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
