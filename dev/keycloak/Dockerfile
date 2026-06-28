# Custom Keycloak image = Bitnami KC 26.3.3 + the klausbetz Apple Identity
# Provider SPI (v1.15.0, built against KC 26.3.0).
#
# Why: Sign in with Apple requires response_mode=form_post when the email/name
# scope is requested, which makes Apple POST the authorization code back. KC's
# stock GENERIC-OIDC broker endpoint has no @POST handler and returns 405 on
# that callback. This SPI registers providerId="apple" with a proper form_post
# POST handler, mints the ES256 client-secret JWT internally from the .p8, and
# maps email/name. It also renders the real Apple logo on the social button.
#
# Bitnami's KC entrypoint runs the Quarkus augmentation ("installing your
# custom providers, if any") at container start, which registers any JAR in
# the providers dir — so a plain COPY is enough, no explicit `kc build`.
# The JAR MUST be world-readable AND owned by 1001. Bitnami's chart mounts an
# emptyDir over /opt/bitnami/keycloak/providers and a `prepare-write-dirs` init
# container (running as uid 1001, non-root) copies the image's providers dir
# into it with `cp -r --preserve=mode,timestamps`. A plain COPY lands the JAR as
# root:root mode 600 — unreadable by uid 1001 — so the cp silently skips it, the
# emptyDir ends up without the JAR, KC never registers providerId=apple, and the
# IdP create returns HTTP 400. Setting owner 1001 + mode 0644 lets the init copy
# survive into the running container.
FROM docker.io/bitnamilegacy/keycloak:26.3.3-debian-12-r0
USER root
COPY providers/apple-identity-provider-1.15.0.jar /opt/bitnami/keycloak/providers/
RUN chown 1001:1001 /opt/bitnami/keycloak/providers/apple-identity-provider-1.15.0.jar \
 && chmod 0644 /opt/bitnami/keycloak/providers/apple-identity-provider-1.15.0.jar
USER 1001
