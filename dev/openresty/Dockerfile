FROM openresty/openresty:1.27.1.1-alpine

RUN apk add --no-cache curl bash gettext

WORKDIR /usr/local/openresty/nginx

# lua-resty-redis ships with openresty image; no extra rocks needed for the
# basic single-instance use case. Re-add lua-resty-redis-cluster only if/when
# we move to Redis Cluster in production.
#
# Build context is the repo root (so this image can be built the same way
# from docker-compose AND from CI/k8s pipelines). See dev/compose.yaml and
# scripts/deploy-beelink.sh.
#
# nginx.conf is shipped as a template; docker-entrypoint.sh runs envsubst at
# container start to inject $NGINX_RESOLVER (different per environment:
# 127.0.0.11 for compose, 10.43.0.10 for k3s).
COPY dev/openresty/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf.template
COPY dev/openresty/lua/       /usr/local/openresty/nginx/lua/
COPY dev/openresty/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
# Normalise file perms — mutagen-synced source on the build host strips
# group/other perms to 0600, but the openresty worker runs as 'nobody' and
# can't read 0600 root-owned files. Force world-readable.
RUN chmod -R a+rX /usr/local/openresty/nginx/lua /usr/local/openresty/nginx/conf/nginx.conf.template

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["openresty", "-g", "daemon off;"]
