-- Native-app (NATIVE_PKCE) profile support: persist app profile + native identifiers.
-- All nullable, only populated for NATIVE_PKCE apps. No backfill.
ALTER TABLE apps
    ADD COLUMN profile             VARCHAR(40),
    ADD COLUMN ios_team_id         VARCHAR(40),
    ADD COLUMN ios_bundle_id       VARCHAR(255),
    ADD COLUMN android_package     VARCHAR(255),
    ADD COLUMN android_cert_sha256 TEXT;
