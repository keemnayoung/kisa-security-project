#!/bin/bash
# ============================================================================ 
# @Project: 시스템 보안 자동화 프로젝트 
# @Version: 2.1.0 
# @Author: 한은결 
# @Last Updated: 2026-02-16 
# ============================================================================ 
# [점검 항목 상세] 
# @ID          : D-02 
# @Category    : 계정 관리 
# @Platform    : MySQL 
# @Severity    : 상 
# @Title       : 데이터베이스의 불필요 계정 제거 또는 잠금 설정 
# @Description : DB 운용에 사용하지 않는 불필요 계정 존재 여부 점검 
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드 
# ============================================================================

ID="D-02"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user(table)"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

SYSTEM_USERS_CSV="'root','mysql.sys','mysql.session','mysql.infoschema','mysqlxsys','mariadb.sys'"

AUTHORIZED_USERS_CSV="${AUTHORIZED_USERS_CSV:-}"
DEMO_USERS_CSV="${DEMO_USERS_CSV:-scott,pm,adams,clark,test,guest,demo,sample}"

# SQL 비시스템 계정(user not in SYSTEM_USERS)과 host/잠금 여부 조회
QUERY_PRIMARY="SELECT user, host, IFNULL(account_locked,'N') AS account_locked FROM mysql.user WHERE user NOT IN (${SYSTEM_USERS_CSV});"
QUERY_FALLBACK="SELECT user, host, 'N' AS account_locked FROM mysql.user WHERE user NOT IN (${SYSTEM_USERS_CSV});"

run_mysql_query() {
  local query="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
  else
    $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR"
  fi
}

in_csv() {
  local needle="$1"
  local csv="$2"
  IFS=',' read -r -a arr <<< "$csv"
  for item in "${arr[@]}"; do
    [[ "$needle" == "$item" ]] && return 0
  done
  return 1
}

RESULT="$(run_mysql_query "$QUERY_PRIMARY")"
QUERY_MODE="PRIMARY"
if [[ "$RESULT" == "ERROR" ]]; then
  RESULT="$(run_mysql_query "$QUERY_FALLBACK")"
  QUERY_MODE="FALLBACK"
fi

DETAIL_CONTENT=""
VULNERABLE_ACCOUNTS=""
GUIDE_LINE="자동 조치로 불필요한 계정을 삭제하거나 잠글 경우, 기존 시스템 설정에 의도치 않은 영향이 발생할 수 있어 수동 조치가 필요합니다. 
잘못된 계정 삭제로 인해 일부 사용자가 정상적으로 접근할 수 없거나 서비스도 중단될 수 있습니다. 
관리자가 직접 불필요 계정을 삭제하거나 잠금 설정을 확인하고 조치하시기 바랍니다."

# 2) 실행 실패 분기(타임아웃/접속 오류)
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 계정 목록 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 점검을 완료하지 못했습니다."
  DETAIL_CONTENT="result=ERROR_TIMEOUT"
elif [[ "$RESULT" == "ERROR" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 접속 실패 또는 mysql.user 조회 권한 부족으로 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="result=ERROR"
else
  VULN_COUNT=0

  while IFS=$'\t' read -r user host locked; do
    [[ -z "$user" && -z "$host" ]] && continue
    [[ "$locked" == "Y" ]] && continue

    # 익명 계정 활성
    if [[ -z "$user" ]]; then
      VULN_COUNT=$((VULN_COUNT + 1))
      VULNERABLE_ACCOUNTS="${VULNERABLE_ACCOUNTS}[익명 계정 활성] anonymous@${host}\n "
      continue
    fi

    # 데모/테스트 계정명 탐지
    if in_csv "$user" "$DEMO_USERS_CSV"; then
      VULN_COUNT=$((VULN_COUNT + 1))
      VULNERABLE_ACCOUNTS="${VULNERABLE_ACCOUNTS}[데모/테스트 계정]${user}@${host}\n "
      continue
    fi

    # 기관 허용 목록 사용 시, 목록 외 계정은 취약 후보
    if [[ -n "$AUTHORIZED_USERS_CSV" ]] && ! in_csv "$user" "$AUTHORIZED_USERS_CSV"; then
      VULN_COUNT=$((VULN_COUNT + 1))
      VULNERABLE_ACCOUNTS="${VULNERABLE_ACCOUNTS}[목록 외 계정] ${user}@${host}\n "
      continue
    fi
  done <<< "$RESULT"

  # 판정 분기(PASS/FAIL)
  if [[ "$VULN_COUNT" -eq 0 ]]; then
    STATUS="PASS"
    REASON_LINE="불필요 계정이 활성화되지 않았기 때문에 이 항목에 대하여 양호합니다."
    DETAIL_CONTENT="vuln_count=0"
  else
    STATUS="FAIL"
    REASON_LINE="불필요 계정이 활성화되었기 때문에 이 항목에 대하여 취약합니다."
    DETAIL_CONTENT="vuln_count=${VULN_COUNT}; vulnerable_accounts=\n${VULNERABLE_ACCOUNTS}"
  fi
fi

CHECK_COMMAND="$MYSQL_CMD \"$QUERY_PRIMARY\" (fallback: \"$QUERY_FALLBACK\")"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
  $DETAIL_CONTENT",
  "target_file": "$TARGET_FILE",
  "guide": "$GUIDE_LINE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
