-- ============================================================================
-- auth_manager schema
-- ============================================================================
CREATE SCHEMA IF NOT EXISTS auth_manager;
SET search_path = auth_manager, public;

-- ---------- tenants ---------------------------------------------------------
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    realm_name      TEXT,                              -- null until Keycloak provisioned
    status          TEXT NOT NULL CHECK (status IN
                      ('PENDING','ACTIVE','SUSPENDED','FAILED','DELETED')),
    settings        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);
CREATE INDEX idx_tenants_status ON tenants(status) WHERE deleted_at IS NULL;

-- ---------- tenant hostnames (host -> tenant routing intent) ----------------
CREATE TABLE tenant_hostnames (
    hostname        TEXT PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    backend_url     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_hostnames_tenant ON tenant_hostnames(tenant_id);

-- ---------- apps ------------------------------------------------------------
CREATE TABLE apps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    client_id       TEXT NOT NULL,                    -- Keycloak client id
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

-- ---------- app manifests (idempotency + versioning) ------------------------
CREATE TABLE app_manifests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id          UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    manifest_yaml   TEXT NOT NULL,
    manifest_json   JSONB NOT NULL,
    hash            CHAR(64) NOT NULL,                -- sha256 of canonicalized manifest
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_by      TEXT NOT NULL,
    UNIQUE (app_id, version),
    UNIQUE (app_id, hash)                              -- idempotency: same hash never re-applied
);

-- ---------- onboarding jobs (long-running state) ----------------------------
CREATE TABLE onboarding_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id),
    app_id          UUID REFERENCES apps(id),
    kind            TEXT NOT NULL CHECK (kind IN ('TENANT_CREATE','TENANT_DELETE','APP_APPLY')),
    state           TEXT NOT NULL CHECK (state IN ('QUEUED','RUNNING','SUCCEEDED','FAILED')),
    payload         JSONB NOT NULL,
    result          JSONB,
    error           TEXT,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_jobs_state ON onboarding_jobs(state) WHERE state IN ('QUEUED','RUNNING');

-- ---------- audit events ----------------------------------------------------
CREATE TABLE audit_events (
    id              BIGSERIAL PRIMARY KEY,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor           TEXT NOT NULL,            -- sub of caller, or "system", or "keycloak"
    actor_kind      TEXT NOT NULL CHECK (actor_kind IN ('USER','SERVICE','SYSTEM','IDP_EVENT')),
    tenant_id       UUID REFERENCES tenants(id),
    action          TEXT NOT NULL,            -- e.g. 'tenant.create', 'app.apply', 'LOGIN'
    target_kind     TEXT,                     -- 'tenant','app','user',...
    target_id       TEXT,
    request_hash    CHAR(64),                 -- sha256 of payload (for replay correlation)
    result          TEXT NOT NULL CHECK (result IN ('SUCCESS','FAILURE')),
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip              INET,
    user_agent      TEXT
);
CREATE INDEX idx_audit_tenant_time ON audit_events(tenant_id, occurred_at DESC);
CREATE INDEX idx_audit_actor_time  ON audit_events(actor, occurred_at DESC);
CREATE INDEX idx_audit_action_time ON audit_events(action, occurred_at DESC);

-- ---------- user cache (for fast list/search in UI) -------------------------
CREATE TABLE user_cache (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    keycloak_user_id UUID NOT NULL,
    username        TEXT NOT NULL,
    email           TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_login_at   TIMESTAMPTZ,
    refreshed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, keycloak_user_id)
);
CREATE INDEX idx_user_cache_username ON user_cache(tenant_id, lower(username));
CREATE INDEX idx_user_cache_email    ON user_cache(tenant_id, lower(email));
