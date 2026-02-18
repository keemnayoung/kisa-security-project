#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : DBMS 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-04"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# psql 접속 및 쿼리 실행 함수
run_psql() {
  local sql="$1"
  if PGPASSWORD="${POSTGRES_PASSWORD:-}" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -u "$PG_SUPERUSER" psql -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null
    return $?
  fi
  return 1
}

# 파이썬 대시보드 호환을 위해 특수문자 및 개행을 처리하는 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 허용된 관리자 계정 목록 정리 (환경변수 기반)
ALLOWED_SUPERUSERS="${ALLOWED_SUPERUSERS:-postgres}"
MERGED_ALLOWED="${ALLOWED_SUPERUSERS},${POSTGRES_USER},${PG_SUPERUSER}"
ALLOWED_SUPERUSERS_MERGED="$(printf '%s' "$MERGED_ALLOWED" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d' | awk '!seen[$0]++' | paste -sd, -)"
[ -z "$ALLOWED_SUPERUSERS_MERGED" ] && ALLOWED_SUPERUSERS_MERGED="postgres"

# SQL IN 절에 사용할 문자열 생성
SQL_LIST=""
IFS=',' read -r -a _allowed_roles <<< "$ALLOWED_SUPERUSERS_MERGED"
for role in "${_allowed_roles[@]}"; do
  role="${role#"${role%%[![:space:]]*}"}"
  role="${role%"${role##*[![:space:]]}"}"
  [ -z "$role" ] && continue
  SQL_LIST="${SQL_LIST}'${role}',"
done
SQL_LIST="${SQL_LIST%,}"
[ -z "$SQL_LIST" ] && SQL_LIST="'postgres'"

# 전체 SUPERUSER 계정 현황 조회
ALL_ADMINS=$(run_psql "SELECT rolname FROM pg_roles WHERE rolsuper = true ORDER BY rolname;")
RC=$?

# 허용 목록 외의 관리자 계정 추출
EXTRA_ADMINS=$(echo "$ALL_ADMINS" | grep -vE "^($(echo "$ALLOWED_SUPERUSERS_MERGED" | tr ',' '|'))$")

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 운영 권한 회수로 인한 서비스 장애 위험과 수동 조치 방법 정의
GUIDE_LINE="이 항목에 대해서 관리자 권한을 자동으로 회수할 경우, 해당 계정으로 수행되던 정기 백업, 모니터링, 데이터 이관 등 필수 관리 작업이 즉시 중단되어 시스템 운영에 심각한 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 불필요한 관리자 권한을 가진 계정에 대해 ALTER ROLE <계정명> NOSUPERUSER; 명령을 사용하여 권한을 회수하거나 꼭 필요한 권한만 부여하도록 조치해 주시기 바랍니다."

# 쿼리 실행 결과에 따른 점검 수행 분기점
if [ $RC -ne 0 ]; then
  STATUS="FAIL"
  REASON_LINE="데이터베이스 관리자 권한 목록을 조회할 수 없어 점검을 수행하지 못했습니다."
  DETAIL_CONTENT="connection_error(database_access=FAILED)"
else
  # 비인가 관리자 계정 존재 여부에 따른 결과 판단 분기점
  if [ -z "$EXTRA_ADMINS" ]; then
    STATUS="PASS"
    REASON_LINE="허용된 계정들만 관리자 권한(SUPERUSER)을 보유하고 있어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    EXTRA_COUNT=$(echo "$EXTRA_ADMINS" | sed '/^[[:space:]]*$/d' | wc -l)
    REASON_LINE="허용 목록 외 ${EXTRA_COUNT}개 계정이 SUPERUSER 권한을 보유하고 있어 이 항목에 대해 취약합니다."
  fi
  
  # 전체 SUPERUSER 설정 값을 상세 내용으로 구성
  DETAIL_CONTENT="[현재 SUPERUSER 권한 보유 계정 목록]\n$(echo "$ALL_ADMINS" | sed 's/^/- /')"
fi

# 증적 정보 구성
CHECK_COMMAND="SELECT rolname FROM pg_roles WHERE rolsuper = true;"
TARGET_FILE="pg_roles"

# 요구사항 반영한 RAW_EVIDENCE 구조화
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# 최종 이스케이프 및 출력
RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE")"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF