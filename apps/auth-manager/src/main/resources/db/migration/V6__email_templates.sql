-- ============================================================================
-- V6: Per-tenant transactional email templates + inline assets
--
-- Slice 1 of the email-templates feature. A tenant may store a Mustache HTML
-- body (+ optional subject) per reserved type_key (e.g. "invitation"), plus a
-- bag of inline image assets referenced from the body via {{asset:name}} /
-- cid:name. When no row exists for (tenant, type_key) the render pipeline falls
-- back to the phase-1 classpath default (invitation only).
--
-- ddl-auto=validate: the EmailTemplate / EmailTemplateAsset JPA entities must
-- match this schema exactly.
-- ============================================================================
SET search_path = auth_manager, public;

CREATE TABLE email_templates (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type_key          VARCHAR(64) NOT NULL,
    subject_template  TEXT,
    html_template     TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, type_key)
);

CREATE INDEX idx_email_templates_tenant ON email_templates(tenant_id);

CREATE TABLE email_template_assets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    type_key      VARCHAR(64) NOT NULL,
    name          VARCHAR(128) NOT NULL,
    content_type  VARCHAR(128) NOT NULL,
    bytes         BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, type_key, name),
    CONSTRAINT fk_email_template_assets_template
        FOREIGN KEY (tenant_id, type_key)
        REFERENCES email_templates(tenant_id, type_key)
        ON DELETE CASCADE
);

CREATE INDEX idx_email_template_assets_template
    ON email_template_assets(tenant_id, type_key);

COMMENT ON TABLE email_templates IS
  'Per-tenant Mustache email body+subject keyed by reserved type_key (slice 1).';
COMMENT ON TABLE email_template_assets IS
  'Inline image assets for a tenant email template, referenced via {{asset:name}} / cid:name.';
