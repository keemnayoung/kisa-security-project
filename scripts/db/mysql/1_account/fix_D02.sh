#!/bin/bash
# @Author: 한은결
# D-02: 불필요 계정 제거
ID="D-02"
CATEGORY="계정 관리"
TITLE="데이터베이스의 불필요 계정을 제거하거나 잠금설정 후 사용"
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

# 자동 조치 정책: 불필요 계정은 삭제(DROP)로 고정
ACTION_MODE="DROP"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
  return $?
}

sql_escape() {
  local s="$1"
  s="${s//\'/\'\'}"
  printf "%s" "$s"
}

DEMO_LIST="'scott','pm','adams','clark','test','guest','demo','sample'"
Q="SELECT user,host FROM mysql.user WHERE user='' OR LOWER(user) IN (${DEMO_LIST});"

ROWS="$(run_mysql "$Q")"
RC=$?

if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 계정 조회 시간 초과"
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: 계정 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-02 조치를 수행할 수 없습니다."
elif [[ -z "$ROWS" ]]; then
  STATUS="PASS"
  ACTION_RESULT="NOT_REQUIRED"
  ACTION_LOG="불필요 계정(익명/데모)이 확인되지 않았습니다."
  EVIDENCE="D-02 기준 추가 조치 불필요"
else
  FAIL=0
  COUNT=0

  while IFS=$'\t' read -r user host; do
    [[ -z "$host" ]] && continue
    esc_user="$(sql_escape "$user")"
    esc_host="$(sql_escape "$host")"

    # 삭제(DROP) 고정
    run_mysql "DROP USER IF EXISTS '${esc_user}'@'${esc_host}';" >/dev/null || FAIL=1
    COUNT=$((COUNT+1))
  done <<< "$ROWS"

  run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1

  AFTER="$(run_mysql "$Q")"
  RC2=$?

  if [[ $FAIL -eq 0 && $RC2 -eq 0 && -z "$AFTER" ]]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="불필요 계정 ${COUNT}건을 삭제(DROP) 처리했습니다. (필요 시 계정을 재생성하여 복구하십시오.)"
    EVIDENCE="D-02 조치 후 불필요 계정 미검출 (삭제 처리 완료)"
  else
    ACTION_LOG="조치 일부 실패: 불필요 계정 삭제 후 잔여 계정이 남아 있을 수 있습니다."
    EVIDENCE="D-02 자동 조치를 완료하지 못했습니다."
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
  "guide":"불필요한 계정은 삭제 조치하였으며, 업무상 필요한 경우에는 계정을 재생성하여 최소 권한으로 운영하시기 바랍니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
