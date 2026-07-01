-- Persist an app's requested audience (comma-separated client slugs) so the
-- startup reconcile runner can re-apply audience mappers after a realm rebuild.
-- Nullable; no backfill (existing rows keep NULL).
ALTER TABLE apps ADD COLUMN audience TEXT;
