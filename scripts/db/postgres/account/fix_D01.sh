#!/bin/bash
export POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
export POSTGRES_PORT="${POSTGRES_PORT:-5432}"
export POSTGRES_DB="${POSTGRES_DB:-postgres}"
export POSTGRES_USER="${POSTGRES_USER:-postgres}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
export PG_SUPERUSER="${PG_SUPERUSER:-postgres}"
# 기본 변수
ID="D-01"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="pg_shadow"
CHECK_COMMAND="psql -h <POSTGRES_HOST> -p <POSTGRES_PORT> -U <POSTGRES_USER> -d <POSTGRES_DB> -t -A -q -c \"SELECT s.usename FROM pg_shadow s JOIN pg_roles r ON r.rolname = s.usename WHERE r.rolsuper = true AND (s.passwd IS NULL OR s.passwd = '');\""

NEW_PASS="${NEW_SUPERUSER_PASSWORD:-}"

run_psql() {
  local sql="$1"
  local timeout_cmd=""

  if command -v timeout >/dev/null 2>&1; then
    timeout_cmd="timeout 10s"
  fi

  if PGPASSWORD="${POSTGRES_PASSWORD:-}" $timeout_cmd psql -w -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    $timeout_cmd sudo -n -u "$PG_SUPERUSER" psql -w -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null
    return $?
  fi
  return 1
}

sql_quote() {
  printf '%s' "$1" | sed "s/'/''/g"
}

# 1) 비밀번호 미설정 SUPERUSER 조회
VULN_USERS=$(run_psql "
SELECT s.usename
FROM pg_shadow s
JOIN pg_roles r ON r.rolname = s.usename
WHERE r.rolsuper = true
  AND (s.passwd IS NULL OR s.passwd = '');
")

if [ $? -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="SUPERUSER 비밀번호 설정 상태 조회에 실패하여 조치가 완료되지 않았습니다."
  DETAIL_CONTENT=""
else
  if [ -z "$VULN_USERS" ]; then
    IS_SUCCESS=1
    REASON_LINE="SUPERUSER 계정의 비밀번호가 설정되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT=""
  else
    if [ -z "$NEW_PASS" ]; then
      IS_SUCCESS=0
      REASON_LINE="비밀번호가 설정되지 않은 SUPERUSER 계정이 존재하나 NEW_SUPERUSER_PASSWORD가 설정되지 않아 조치가 완료되지 않았습니다."
      DETAIL_CONTENT="$(echo "$VULN_USERS" | sed '/^[[:space:]]*$/d')"
    else
      FAIL_COUNT=0
      OK_USERS=""
      FAIL_USERS=""

      ESC_PASS=$(sql_quote "$NEW_PASS")

      while IFS= read -r user; do
        [ -z "$user" ] && continue
        ESC_USER=$(sql_quote "$user")

        if run_psql "ALTER ROLE \"$ESC_USER\" WITH PASSWORD '$ESC_PASS';" >/dev/null 2>&1; then
          OK_USERS="${OK_USERS}${user}
"
        else
          FAIL_COUNT=$((FAIL_COUNT + 1))
          FAIL_USERS="${FAIL_USERS}${user}
"
        fi
      done <<< "$VULN_USERS"

      if [ "$FAIL_COUNT" -eq 0 ]; then
        IS_SUCCESS=1
        REASON_LINE="비밀번호가 설정되지 않은 SUPERUSER 계정의 비밀번호가 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="$(echo "$OK_USERS" | sed '/^[[:space:]]*$/d')"
      else
        IS_SUCCESS=0
        REASON_LINE="SUPERUSER 계정 비밀번호 변경을 수행했으나 일부 계정의 변경이 실패하여 조치가 완료되지 않았습니다."
        DETAIL_CONTENT="$(echo "$FAIL_USERS" | sed '/^[[:space:]]*$/d')"
      fi
    fi
  fi
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

FAILURE_REASON=""
if [ "$IS_SUCCESS" -eq 0 ]; then
  FAILURE_REASON="$REASON_LINE"
fi
FAILURE_REASON_ESCAPED=$(echo "$FAILURE_REASON" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# DB 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "failure_reason": "$FAILURE_REASON_ESCAPED",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF
