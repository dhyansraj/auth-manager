# Build context MUST be the repo root, not apps/app1-ui/:
#   docker build -f apps/app1-ui/Dockerfile -t app1-ui:tag .
#
# Workspace-aware: pulls in root package.json, libs/auth-lib-react, and
# apps/app1-ui. Single `npm install` at root wires symlinks across workspaces;
# we build the shared lib first so its dist/ exists, then build the SPA.

# ───── Stage 1: build ─────
FROM node:20-alpine AS build
WORKDIR /src

# 1. workspace manifests first (better layer caching when source changes)
COPY package.json package-lock.json* ./
COPY libs/auth-lib-react/package.json ./libs/auth-lib-react/
COPY apps/app1-ui/package.json ./apps/app1-ui/

# package-lock.json may not exist on fresh repos — fall back to install.
RUN if [ -f package-lock.json ]; then npm ci; else npm install --no-audit --no-fund; fi

# 2. source for the lib and the SPA
COPY libs/auth-lib-react/ ./libs/auth-lib-react/
COPY apps/app1-ui/ ./apps/app1-ui/

# 3. build the lib (produces libs/auth-lib-react/dist), then the SPA
RUN npm --workspace=@mcpmesh/auth-lib-react run build \
 && npm --workspace=app1-ui run build

# ───── Stage 2: runtime ─────
FROM nginx:1.27-alpine AS runtime

# SPA fallback nginx config -- any unknown path serves index.html so React Router works.
RUN cat > /etc/nginx/conf.d/default.conf <<'EOF'
server {
    listen 80 default_server;
    server_name _;

    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /healthz {
        access_log off;
        return 200 "ok\n";
        add_header Content-Type text/plain;
    }
}
EOF

COPY --from=build /src/apps/app1-ui/dist /usr/share/nginx/html
EXPOSE 80
