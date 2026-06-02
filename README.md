# auth-manager

Multi-tenant authentication & authorization platform — "auth-as-a-service" — built on Keycloak, an OpenResty/Lua edge, and a Spring Boot control plane. Self-hosted on Kubernetes (beelink k3s).

Each tenant gets its own Keycloak realm: users, identity providers, client apps, custom theme, and SMTP config. Operators manage tenants through **auth-manager** via the admin UI; tenant teams integrate their apps using the published auth libraries.

**Status:** Live in production. Two fully-isolated environments run side-by-side on the same cluster — **prod** (`auth-platform` namespace, HA) and **dev** (`auth-platform-dev`, single-replica throwaway tenants). They share the same Helm chart and image registry; only sizing and infra targets differ.

## What is this?

A control plane that:

- Provisions Keycloak realms, clients, roles, resources, and policies per tenant — declaratively or via UI.
- Federates external identity providers (Google, GitHub, SAML) per tenant realm. One shared OAuth client serves many tenants instead of one per app.
- Routes traffic at the edge (OpenResty + Lua + Redis) based on hostname, with dynamic tenant onboarding (no kubectl-apply per new tenant).
- Ships consumer libraries (Java, Python, React) that any app can drop in for JWT validation, permission caching, and `@Secured("PERMISSION_*")`-style authorization.
- Optionally watches `Tenant`/`App` CRDs for GitOps-style declarative tenancy.

## Documentation

| Doc | What it covers |
| --- | --- |
| **[`OPERATOR-GUIDE.org`](./OPERATOR-GUIDE.org)** | Operate the live platform — architecture, URLs, deployment, operator workflows, gotchas, daily checklist. |
| **[`PLAN.org`](./PLAN.org)** | Design doc + rationale — component design with code, and the *why* behind decisions (search for `~WHY:~`). |
| **[`BACKLOG.org`](./BACKLOG.org)** | Prioritized open work. |

## Repo layout

```
apps/
  auth-manager/         Spring Boot control-plane backend (Java 21, Spring Boot 4.0.6)
  admin-ui/             React + Vite admin SPA
  app1-backend/         Sample tenant backend (auth-lib integration reference)
  app1-ui/              Sample tenant React SPA
  auth-client-sample/   Minimal OIDC client example
  tenant-operator/      java-operator-sdk reconciler for Tenant/App CRDs (scaffolded)
  keycloak-event-spi/   Keycloak event listener SPI (scaffolded)
libs/
  auth-lib/             Java consumer library — JWT validation + permission cache (Maven Central: mcp-mesh-auth-lib)
  auth-lib-react/       React hooks/components for BFF auth (npm: @mcpmesh/auth-lib-react)
  auth-lib-python/      Python/FastAPI consumer library (PyPI: mcp-mesh-auth-lib)
deploy/
  helm/auth-platform/   Umbrella Helm chart (auth-manager, admin-ui, platform-edge, cloudflared, smtp-relay)
  cnpg/                 CloudNativePG manifests
  k3d/                  Local cluster bootstrap
dev/
  compose.yaml          Layer-1 local dev stack (Postgres, Redis, Keycloak, OpenResty, Mailhog)
  openresty/            platform-edge: OpenResty + Lua BFF (sessions, CSRF, routing, token refresh)
  smtp-relay/           Go SMTP relay → SendGrid
scripts/                Deploy, Cloudflare tunnel, provisioning, seed helpers
```

## Published libraries

| Library | Registry | Version |
| --- | --- | --- |
| `mcp-mesh-auth-lib` (Java) | Maven Central | 0.3.1 |
| `mcp-mesh-auth-lib` (Python) | PyPI | 0.1.0 |
| `@mcpmesh/auth-lib-react` | npm | 0.3.0 |

## Getting started

To operate the live platform, see **[`OPERATOR-GUIDE.org`](./OPERATOR-GUIDE.org)**.

For the local dev loop:

```bash
make dev    # Layer 1: Docker Compose deps (Postgres, Redis, Keycloak, OpenResty, Mailhog)
cd apps/auth-manager && mvn spring-boot:run -Dspring-boot.run.profiles=local
cd apps/admin-ui     && npm run dev
```

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).
