#!/bin/bash
# Compatibility wrapper.
# Many postgres scripts expect _pg_common.sh to exist under scripts/db/postgres/.
# Keep the implementation centralized at scripts/db/_pg_common.sh.

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"

