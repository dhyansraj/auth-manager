FROM openresty/openresty:1.27.1.1-alpine

RUN apk add --no-cache curl bash

WORKDIR /usr/local/openresty/nginx

# lua-resty-redis ships with openresty image; no extra rocks needed for the
# basic single-instance use case. Re-add lua-resty-redis-cluster only if/when
# we move to Redis Cluster in production.
#
# Build context is the repo root (so this image can be built the same way
# from docker-compose AND from CI/k8s pipelines). See dev/compose.yaml and
# scripts/deploy-beelink.sh.
COPY dev/openresty/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY dev/openresty/lua/       /usr/local/openresty/nginx/lua/

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost/health || exit 1
