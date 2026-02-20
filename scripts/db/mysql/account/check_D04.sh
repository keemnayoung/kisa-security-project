#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-04"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 허용된 관리자 계정 목록 정의
ALLOWED_ADMIN_USERS_CSV="${ALLOWED_ADMIN_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_ADMIN_PRINCIPALS_CSV="${ALLOWED_ADMIN_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"

# 관리자급 권한(SUPER, *_ADMIN 등)을 보유한 계정 목록 조회 쿼리
QUERY="
SELECT grantee,
       GROUP_CONCAT(DISTINCT privilege_type ORDER BY privilege_type SEPARATOR ',') AS privileges
FROM information_schema.user_privileges
WHERE privilege_type IN ('SUPER','SYSTEM_USER','CREATE USER','RELOAD','SHUTDOWN','PROCESS')
   OR privilege_type LIKE '%_ADMIN'
GROUP BY grantee;
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

extract_user() { echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"; }
extract_host() { echo "$1" | sed -E "s/^'[^']+'@'([^']+)'$/\1/"; }

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
# 자동 조치 시 발생할 수 있는 위험과 수동 조치 방법 정의
GUIDE_LINE="이 항목에 대해서 관리자 권한을 자동 회수할 경우 시스템 운영에 필수적인 계정이나 백업/모니터링 계정의 접근이 차단되어 서비스 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 불필요하게 SUPER 권한이 부여된 계정은 REVOKE 명령으로 권한을 회수하고, 필요한 경우에만 BINLOG_ADMIN 또는 SYSTEM_VARIABLES_ADMIN 등의 최소 권한으로 조치해 주시기 바랍니다."

# 데이터베이스 접속 및 쿼리 실행 결과 확인
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 점검을 완료하지 못했습니다."
  DETAIL_CONTENT="result=ERROR_TIMEOUT"
elif [[ "$RESULT" == "ERROR" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 조회 권한 부족으로 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="result=ERROR"
else
  VIOLATION_COUNT=0
  VIOLATIONS=()
  ALL_ADMINS=()

  # 조회된 계정들을 허용 목록과 비교하여 위반 사항 식별
  while IFS=$'\t' read -r grantee privs; do
    [[ -z "$grantee" ]] && continue

    user="$(extract_user "$grantee")"
    host="$(extract_host "$grantee")"
    principal="${user}@${host}"
    
    ALL_ADMINS+=("${principal}[${privs}]")

    if in_csv "$user" "$ALLOWED_ADMIN_USERS_CSV"; then
      continue
    fi
    if in_csv "$principal" "$ALLOWED_ADMIN_PRINCIPALS_CSV"; then
      continue
    fi

    VIOLATION_COUNT=$((VIOLATION_COUNT + 1))
    VIOLATIONS+=("${principal}(${privs})")
  done <<< "$RESULT"

  # 점검 결과에 따른 상세 내용 및 사유 작성
  if [[ "$VIOLATION_COUNT" -eq 0 ]]; then
    STATUS="PASS"
    REASON_LINE="관리자 권한을 가진 계정이 허용된 관리자 목록 내의 계정들로만 설정되어 있어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    REASON_LINE="허용되지 않은 ${VIOLATION_COUNT}개 계정에 관리자 권한이 부여되어 이 항목에 대해 취약합니다."
  fi

  # 전체 관리자 권한 보유 현황 나열 (DETAIL_CONTENT)
  DETAIL_CONTENT="[전체 관리자 권한 보유 현황]\n"
  for admin in "${ALL_ADMINS[@]}"; do
    DETAIL_CONTENT="${DETAIL_CONTENT}- ${admin}\n"
  done
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