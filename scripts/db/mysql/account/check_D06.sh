#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-06"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

COMMON_USERS_CSV="${COMMON_USERS_CSV:-guest,test,demo,shared,common,public,user}"
EXEMPT_USERS_CSV="${EXEMPT_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

# 활성 계정의 호스트 접근 설정 및 패턴을 확인하기 위한 쿼리
QUERY="
SELECT user,
       SUM(CASE WHEN host NOT IN ('localhost','127.0.0.1','::1') THEN 1 ELSE 0 END) AS non_local_host_count,
       SUM(CASE WHEN host='%' THEN 1 ELSE 0 END) AS wildcard_count,
       GROUP_CONCAT(host ORDER BY host SEPARATOR ',') AS hosts
FROM mysql.user
WHERE IFNULL(account_locked,'N') != 'Y'
GROUP BY user;
"

in_csv() {
  local needle="$1"
  local csv="$2"
  IFS=',' read -r -a arr <<< "$csv"
  for item in "${arr[@]}"; do
    [[ "$needle" == "$item" ]] && return 0
  done
  return 1
}

run_mysql_query() {
  local q="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$q" 2>/dev/null || echo "ERROR_TIMEOUT"
  else
    $MYSQL_CMD "$q" 2>/dev/null || echo "ERROR"
  fi
}

RESULT="$(run_mysql_query "$QUERY")"

REASON_LINE=""
DETAIL_CONTENT=""
# 수동 조치 필요성 및 자동 조치 시의 위험성 정의
GUIDE_LINE="이 항목에 대해서 현재 애플리케이션이 공용 계정으로 연결되어 있는 경우, 자동 삭제 시 서비스 접속 불가 및 데이터베이스 연동 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 불필요한 공용/테스트 계정을 삭제하고 실제 사용자별로 개별 계정을 생성하여 최소 권한을 부여하는 방식으로 조치해 주시기 바랍니다."

# 데이터베이스 접속 결과
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 계정 정보 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 점검을 완료하지 못했습니다."
  DETAIL_CONTENT="result=ERROR_TIMEOUT"
elif [[ "$RESULT" == "ERROR" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 조회 권한 부족으로 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="result=ERROR"
else
  VULN_COUNT=0
  VULN_LIST=()
  TOTAL_USER_INFO=""

  # 조회된 모든 계정의 상세 설정 값을 분석하여 공용 계정 유무 판단
  while IFS=$'\t' read -r user non_local wildcard hosts; do
    [[ -z "$user" ]] && continue
    
    TOTAL_USER_INFO="${TOTAL_USER_INFO}- ${user}@${hosts}\n"

    if in_csv "$user" "$EXEMPT_USERS_CSV"; then
      continue
    fi

    is_vuln="N"
    # 공용 계정명 패턴이거나 과도한 원격 접근이 허용된 경우 식별
    if in_csv "$user" "$COMMON_USERS_CSV"; then
      is_vuln="Y"
    elif [[ "$wildcard" -gt 0 && "$non_local" -gt 1 ]]; then
      is_vuln="Y"
    elif [[ "$non_local" -ge 3 ]]; then
      is_vuln="Y"
    fi

    if [[ "$is_vuln" == "Y" ]]; then
      VULN_COUNT=$((VULN_COUNT + 1))
      VULN_LIST+=("${user}@${hosts}")
    fi
  done <<< "$RESULT"

  # 점검 결과 및 현재 설정 상태 구성
  if [[ "$VULN_COUNT" -eq 0 ]]; then
    STATUS="PASS"
    REASON_LINE="공용/테스트 계정명이 발견되지 않고 모든 계정이 명확한 호스트로 제한되어 있어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    VULN_STR=$(IFS=', '; echo "${VULN_LIST[*]}")
    REASON_LINE="공용 의심 계정(${VULN_STR})이 존재하고 다수 호스트 접근이 허용되어 있어 이 항목에 대해 취약합니다."
  fi

  DETAIL_CONTENT="[현재 사용자 계정 설정 현황]\n${TOTAL_USER_INFO}"
fi

# raw_evidence 구성
CHECK_COMMAND="$MYSQL_CMD \"$QUERY\""
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF