# auth-manager

Multi-tenant authentication & authorization platform built on Keycloak, OpenResty, and a Spring Boot control plane. Designed for self-hosted Kubernetes (currently targeting k3s).

**Status:** Pre-Phase 0 (planning complete, scaffold not yet built).

## What is this?

A control plane that:

- Provisions Keycloak realms, clients, roles, resources, and policies per tenant — declaratively or via UI.
- Federates external identity providers (Google, Microsoft, GitHub, SAML) per tenant realm. One Google OAuth client serves many tenants instead of one per app.
- Routes traffic at the edge (OpenResty + Lua + Redis) based on hostname, with dynamic tenant onboarding (no kubectl-apply per new tenant).
- Ships a Spring Boot consumer library (`auth-lib`) that any app can drop in to get JWT validation, permission caching, and `@Secured("PERMISSION_*")`-style authorization with one `pom.xml` dependency.
- Optionally watches `Tenant`/`App` CRDs for GitOps-style declarative tenancy.

## Where the design lives

**[`PLAN.org`](./PLAN.org)** — single canonical design document. Read this first. It covers architecture, component-by-component design (with real code), Helm chart layout, IdP brokering strategy, security model, data model, REST API, UI design, naming conventions, version pinning, local-first dev loop, k3d setup, brownfield migration from existing per-app Cloudflare Tunnels, and a six-phase roadmap.

If you want to know *why* a decision was made, search PLAN.org for the relevant `~WHY:~` paragraph.

## Repo layout (target — built out across Phase 0)

```
apps/
  auth-manager/         Spring Boot control-plane backend
  admin-ui/             React + Vite admin SPA
  tenant-operator/      java-operator-sdk reconciler for Tenant/App CRDs
  keycloak-event-spi/   Keycloak event listener → auth-manager
libs/
  auth-lib/             Consumer library (JWT validation + permission cache)
deploy/
  helm/auth-platform/   Umbrella Helm chart + per-component subcharts
  k3d/                  Local cluster bootstrap
dev/                    Layer-1 local dev stack (Docker Compose)
scripts/                Bootstrap, seed, mkcert helpers
.github/workflows/      CI pipelines
```

## Getting started

Phase 0 (scaffolding) hasn't been built yet. Once it's in place, the dev loop will be:

```bash
make dev                                    # Layer 1: Docker Compose deps
cd apps/auth-manager && mvn spring-boot:run -Dspring-boot.run.profiles=local
cd apps/admin-ui     && npm run dev
```

See [`PLAN.org` → Local-First Development Loop](./PLAN.org) for details.

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).
