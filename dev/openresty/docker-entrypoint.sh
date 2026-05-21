#!/bin/sh
set -e
: "${NGINX_RESOLVER:?NGINX_RESOLVER must be set (e.g. 10.43.0.10 for k3s, 127.0.0.11 for docker-compose)}"
envsubst '$NGINX_RESOLVER' \
  < /usr/local/openresty/nginx/conf/nginx.conf.template \
  > /usr/local/openresty/nginx/conf/nginx.conf
exec "$@"
