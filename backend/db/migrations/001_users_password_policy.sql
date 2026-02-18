-- Add first-login password policy columns (idempotent-ish).
-- MySQL doesn't support IF NOT EXISTS for ADD COLUMN in older versions, so run manually if needed.

ALTER TABLE users
  ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 1,
  ADD COLUMN password_changed_at DATETIME NULL;

