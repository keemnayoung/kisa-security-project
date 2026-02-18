-- Store one previous password hash to prevent immediate reuse.
ALTER TABLE users
  ADD COLUMN prev_user_passwd VARCHAR(255) NULL;

