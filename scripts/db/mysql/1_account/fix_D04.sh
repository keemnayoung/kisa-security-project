#!/bin/bash
# @Author: 한은결
# D-04: 불필요 SUPER 권한 회수
ID="D-04"
CATEGORY="계정 관리"
TITLE="관리자 권한 최소 부여"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_TIMEOUT=8
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
ALLOWED_USERS_CSV="${ALLOWED_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
  return $?
}

in_csv() {
  local needle="$1" csv="$2"
  IFS=',' read -r -a arr <<< "$csv"
  for x in "${arr[@]}"; do [[ "$needle" == "$x" ]] && return 0; done
  return 1
}

LIST="$(run_mysql "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='SUPER';")"
RC=$?
if [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: SUPER 권한 조회 실패"
  EVIDENCE="INFORMATION_SCHEMA.USER_PRIVILEGES 조회 실패"
else
  FAIL=0
  CNT=0
  while IFS= read -r grantee; do
    [[ -z "$grantee" ]] && continue
    user="$(echo "$grantee" | sed -E "s/^'([^']+)'.*$/\1/")"
    if in_csv "$user" "$ALLOWED_USERS_CSV"; then
      continue
    fi
    run_mysql "REVOKE SUPER ON *.* FROM ${grantee};" >/dev/null || FAIL=1
    CNT=$((CNT+1))
  done <<< "$LIST"

  run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1
  REMAIN="$(run_mysql "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='SUPER';")"
  RC2=$?
  BAD=0
  if [[ $RC2 -eq 0 ]]; then
    while IFS= read -r grantee; do
      [[ -z "$grantee" ]] && continue
      user="$(echo "$grantee" | sed -E "s/^'([^']+)'.*$/\1/")"
      in_csv "$user" "$ALLOWED_USERS_CSV" || BAD=1
    done <<< "$REMAIN"
  else
    BAD=1
  fi

  if [[ $FAIL -eq 0 && $BAD -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="불필요 SUPER 권한 ${CNT}건을 회수했습니다."
    EVIDENCE="D-04 조치 후 비인가 SUPER 권한 미검출"
  else
    ACTION_LOG="조치 일부 실패: 일부 SUPER 권한이 남아 있을 수 있습니다."
    EVIDENCE="D-04 자동 조치를 완료하지 못했습니다."
  fi
fi

echo ""
cat <<JSON
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide":"불필요한 SUPER 권한을 회수하였으며, 최소 권한 원칙(Least Privilege)에 따라 필요한 권한만 부여하여 운영하시기 바랍니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
