# Build context MUST be the repo root, not apps/admin-ui/:
#   docker build -f apps/admin-ui/Dockerfile -t admin-ui:tag .

# ───── Stage 1: build ─────
FROM node:20-alpine AS build
WORKDIR /src
COPY apps/admin-ui/package.json apps/admin-ui/package-lock.json ./
RUN npm ci
COPY apps/admin-ui/ ./
RUN npm run build

# ───── Stage 2: runtime ─────
FROM nginx:1.27-alpine AS runtime

# SPA fallback nginx config -- any unknown path serves index.html so React Router works
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

COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 80
