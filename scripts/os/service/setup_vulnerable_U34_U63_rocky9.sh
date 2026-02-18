#!/bin/bash
# Thin wrapper to keep a single source of truth for vulnerable-environment setup.
# Canonical script lives in repo root: 3_service/setup_vulnerable_U34_U63_rocky9.sh

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"
CANON="${REPO_ROOT}/3_service/setup_vulnerable_U34_U63_rocky9.sh"

if [ ! -f "$CANON" ]; then
  echo "[오류] canonical 스크립트를 찾을 수 없습니다: $CANON"
  exit 2
fi

exec bash "$CANON" "$@"

