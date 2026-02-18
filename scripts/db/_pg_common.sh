#!/bin/bash
# Common helpers for PostgreSQL check/fix scripts.
# This file is sourced by scripts under scripts/db/postgres/**.
#
# Design goal:
# - Work when scripts are executed as root via Ansible (become: yes).
# - Prefer local peer auth via `sudo -u postgres psql` (no password required).
# - Fall back to TCP auth if PGUSER/PGPASSWORD are provided.

set -o nounset

load_pg_env() {
  # Caller may override with env vars.
  export PGHOST="${PGHOST:-127.0.0.1}"
  export PGPORT="${PGPORT:-5432}"
  export PGDATABASE="${PGDATABASE:-postgres}"

  # Prefer local peer auth as the postgres OS user.
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n -u postgres psql -AtX -c "SELECT 1;" >/dev/null 2>&1; then
      PG_USE_SUDO=1
      return 0
    fi
  fi

  PG_USE_SUDO=0
  return 0
}

run_psql() {
  local sql="$1"

  if [[ "${PG_USE_SUDO:-0}" == "1" ]]; then
    sudo -n -u postgres psql -AtX -v ON_ERROR_STOP=1 -c "$sql" 2>/dev/null || true
    return 0
  fi

  # Fallback: TCP connection using provided credentials.
  # Note: If PGUSER/PGPASSWORD are not set and server requires auth, this will return empty.
  local user="${PGUSER:-}"
  if [[ -z "$user" ]]; then
    user="postgres"
  fi

  # PGPASSWORD can be exported by caller/env.
  psql -AtX -v ON_ERROR_STOP=1 \
    -h "${PGHOST}" -p "${PGPORT}" -U "${user}" -d "${PGDATABASE}" \
    -c "$sql" 2>/dev/null || true
}

escape_json_str() {
  # Escapes string for JSON embedding.
  # - Converts newlines to \n
  # - Escapes backslashes and quotes
  local s="$1"
  printf '%s' "$s" \
    | sed ':a;N;$!ba;s/\n/\\n/g' \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g'
}

