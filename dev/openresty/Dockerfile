FROM openresty/openresty:alpine

RUN apk add --no-cache curl bash

# lua-resty-redis ships with openresty image; no extra rocks needed for the
# basic single-instance use case. Re-add lua-resty-redis-cluster only if/when
# we move to Redis Cluster in production.

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/       /usr/local/openresty/nginx/lua/

EXPOSE 80
