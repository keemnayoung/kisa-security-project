#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
# @Description : DBMS에 존재하는 계정 중 DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-02"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# psql 접속 및 쿼리 실행을 위한 공통 함수
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

# 파이썬 대시보드 및 DB에서 줄바꿈이 깨지지 않도록 JSON 문자열을 이스케이프 처리하는 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 현재 로그인 가능한 모든 ROLE 목록을 조회하여 변수에 저장
ALL_ROLES=$(run_psql "
SELECT rolname
FROM pg_roles
WHERE rolcanlogin = true
ORDER BY rolname;
")

# 관리자 계정(admin01) 및 시스템 계정(pg_%)을 제외한 의심 계정을 추출
CANDIDATES=$(echo "$ALL_ROLES" | grep -vE "^(admin01|pg_.*)$")
RC=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 애플리케이션 접속 차단 위험과 수동 조치 가이드를 변수로 정의
GUIDE_LINE="이 항목에 대해서 의심 계정을 자동으로 삭제하거나 잠금 처리할 경우, 해당 계정을 사용 중인 애플리케이션 접속이 즉시 차단되어 서비스가 중단될 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 사용하지 않는 계정에 대해 DROP ROLE <계정명>; 명령으로 삭제하거나 ALTER ROLE <계정명> NOLOGIN; 명령으로 접속을 차단하여 조치해 주시기 바랍니다."

# 쿼리 실행 성공 여부에 따른 점검 수행 분기점
if [ $RC -ne 0 ] && [ -z "$ALL_ROLES" ]; then
  STATUS="FAIL"
  REASON_LINE="데이터베이스 ROLE 정보를 조회할 수 없어 불필요 계정 존재 여부를 점검하지 못했습니다."
  DETAIL_CONTENT="connection_error(database_access=FAILED)"
else
  # 의심 계정 존재 여부에 따른 양호/취약 결과 판정 분기점
  if [ -z "$CANDIDATES" ]; then
    STATUS="PASS"
    REASON_LINE="로그인 가능한 계정이 허용된 관리자 및 시스템 계정으로만 구성되어 있어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    # 취약 계정 목록을 쉼표로 구분하여 자연스러운 한 문장으로 구성
    CLEAN_CANDIDATES=$(echo "$CANDIDATES" | tr '\n' ',' | sed 's/,$//')
    REASON_LINE="${CLEAN_CANDIDATES} 계정이 로그인 가능한 상태로 설정되어 있어 이 항목에 대해 취약합니다."
  fi
  
  # 양호/취약 관계 없이 현재의 전체 설정 값을 상세 내용으로 구성
  DETAIL_CONTENT="[현재 로그인 가능 계정 설정 현황]\n$(echo "$ALL_ROLES" | sed 's/^/- /')"
fi

# 증적을 위한 상세 정보 설정
CHECK_COMMAND="psql -c \"SELECT rolname FROM pg_roles WHERE rolcanlogin = true;\""
TARGET_FILE="pg_roles"

# 요구사항에 맞춘 RAW_EVIDENCE 데이터 구조화
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 데이터 최종 이스케이프 및 출력
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