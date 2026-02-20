#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-01"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# psql을 사용하여 데이터베이스 쿼리를 실행하는 함수
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


escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 관리자(SUPERUSER) 권한을 가진 계정들의 이름과 비밀번호 설정 여부를 조회
SUPER_USERS_INFO=$(run_psql "
SELECT s.usename, CASE WHEN (s.passwd IS NULL OR s.passwd = '') THEN 'NO_PASSWORD' ELSE 'ENCRYPTED' END 
FROM pg_shadow s
JOIN pg_roles r ON r.rolname = s.usename
WHERE r.rolsuper = true;
")
RC=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 관리용 스크립트 차단 위험과 수동 조치 가이드를 변수로 정의
GUIDE_LINE="이 항목에 대해서 관리자 계정의 비밀번호를 자동 생성된 값으로 변경할 경우, 해당 계정을 통해 DB를 관리하는 스크립트나 백업 도구가 즉시 차단되어 운영 및 유지보수 작업에 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 비밀번호가 설정되지 않은 관리자 계정에 대해 ALTER ROLE <계정명> WITH PASSWORD '<강력한_비밀번호>'; 명령을 사용하여 조치해 주시기 바랍니다."

# DB 접속 상태 및 권한 조회 가능 여부
if [ $RC -ne 0 ]; then
  STATUS="FAIL"
  REASON_LINE="데이터베이스 시스템 테이블 접근 권한 문제로 관리자 계정의 설정 상태를 확인할 수 없어 점검을 수행하지 못했습니다."
  DETAIL_CONTENT="connection_error(database_access=FAILED)"
else
  # 조회된 관리자 계정들 중 비밀번호 미설정(취약) 건수 파악
  VULN_USERS=$(echo "$SUPER_USERS_INFO" | grep "NO_PASSWORD" | cut -d'|' -f1)

  # 점검 결과(양호/취약) 판정 및 문구 생성
  if [ -z "$VULN_USERS" ]; then
    STATUS="PASS"
    REASON_LINE="모든 관리자(SUPERUSER) 계정에 비밀번호가 설정되어 있어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    CLEAN_VULN=$(echo "$VULN_USERS" | tr '\n' ',' | sed 's/,$//')
    REASON_LINE="${CLEAN_VULN} 관리자 계정의 비밀번호가 설정되어 있지 않아 이 항목에 대해 취약합니다."
  fi
  
  # 관리자 계정들에 대한 현재 설정값만 상세 내용으로 구성
  DETAIL_CONTENT="[관리자 계정 비밀번호 설정 현황]\n$(echo "$SUPER_USERS_INFO" | sed 's/|/: /g')"
fi

# 증적용 실행 명령어 및 대상 정의
CHECK_COMMAND="psql -c \"SELECT usename FROM pg_shadow JOIN pg_roles WHERE rolsuper = true...\""
TARGET_FILE="pg_shadow"

# raw_evidence 구성
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
RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE")"

# scan_history 저장용 JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF