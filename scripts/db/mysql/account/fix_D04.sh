#!/bin/bash

# 기본 변수
ID="D-04"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="INFORMATION_SCHEMA.USER_PRIVILEGES"

MYSQL_TIMEOUT=8
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
ALLOWED_USERS_CSV="${ALLOWED_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

CHECK_COMMAND="mysql --protocol=TCP -u<MYSQL_USER> -e \"SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='SUPER';\" 2>/dev/null"

run_mysql() {
  local sql="$1"
  if [ -n "$TIMEOUT_BIN" ]; then
    $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
  return $?
}

in_csv() {
  local needle="$1" csv="$2"
  IFS=',' read -r -a arr <<< "$csv"
  for x in "${arr[@]}"; do
    [ "$needle" = "$x" ] && return 0
  done
  return 1
}

# 1) SUPER 권한 보유 계정 조회
LIST="$(run_mysql "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='SUPER';")"
RC=$?

if [ $RC -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="SUPER 권한 보유 계정 조회에 실패하여 조치가 완료되지 않았습니다."
  DETAIL_CONTENT=""
else
  FAIL=0
  CNT=0

  # 2) 허용 목록 외 SUPER 권한 회수
  while IFS= read -r grantee; do
    [ -z "$grantee" ] && continue
    user="$(echo "$grantee" | sed -E "s/^'([^']+)'.*$/\1/")"

    if in_csv "$user" "$ALLOWED_USERS_CSV"; then
      continue
    fi

    if run_mysql "REVOKE SUPER ON *.* FROM ${grantee};" >/dev/null 2>&1; then
      CNT=$((CNT + 1))
    else
      FAIL=1
    fi
  done <<< "$LIST"

  run_mysql "FLUSH PRIVILEGES;" >/dev/null 2>&1 || FAIL=1

  # 3) 조치 후 상태 수집(조치 후 상태만 detail에 표시)
  REMAIN="$(run_mysql "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='SUPER';")"
  RC2=$?

  BAD=0
  BAD_LIST=""
  REMAIN_LIST=""

  if [ $RC2 -eq 0 ]; then
    while IFS= read -r grantee; do
      [ -z "$grantee" ] && continue
      user="$(echo "$grantee" | sed -E "s/^'([^']+)'.*$/\1/")"
      REMAIN_LIST="${REMAIN_LIST}${grantee}
"
      if ! in_csv "$user" "$ALLOWED_USERS_CSV"; then
        BAD=1
        BAD_LIST="${BAD_LIST}${grantee}
"
      fi
    done <<< "$REMAIN"
  else
    BAD=1
  fi

  REMAIN_LIST="$(echo "$REMAIN_LIST" | sed '/^[[:space:]]*$/d')"
  BAD_LIST="$(echo "$BAD_LIST" | sed '/^[[:space:]]*$/d')"

  if [ $FAIL -eq 0 ] && [ $BAD -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$CNT" -gt 0 ]; then
      REASON_LINE="허용 목록 외 계정의 SUPER 권한이 회수되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="허용 목록 외 계정의 SUPER 권한이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
    DETAIL_CONTENT="$REMAIN_LIST"
  else
    IS_SUCCESS=0
    REASON_LINE="SUPER 권한 회수를 수행했으나 일부 권한 회수가 실패하거나 허용되지 않은 SUPER 권한이 남아 있어 조치가 완료되지 않았습니다."
    if [ -n "$BAD_LIST" ]; then
      DETAIL_CONTENT="$BAD_LIST"
    else
      DETAIL_CONTENT="$REMAIN_LIST"
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
