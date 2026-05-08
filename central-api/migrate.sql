-- bf-central database migrations
-- These ALTER TABLE statements are safe to re-run (IF NOT EXISTS / idempotent).
-- A fresh install does NOT need this file — db.create_all() builds the correct
-- schema from models.py.  Run this file only when upgrading an existing deploy.

-- v1 → v2: push delivery support
ALTER TABLE sites         ADD COLUMN IF NOT EXISTS push_secret VARCHAR(256);
ALTER TABLE central_users ADD COLUMN IF NOT EXISTS network_password_hash TEXT;

-- v2 → v3: is_wired on central_devices
ALTER TABLE central_devices ADD COLUMN IF NOT EXISTS is_wired BOOLEAN NOT NULL DEFAULT FALSE;
