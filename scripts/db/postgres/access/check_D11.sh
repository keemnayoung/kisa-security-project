#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# @Description : 시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-11"
STATUS="FAIL"

# 허용된 DBA 계정 목록 구성
ALLOWED_DBA_RAW="${D11_ALLOWED_DBA:-},postgres,${POSTGRES_USER},${PG_SUPERUSER}"

# 계정의 DBA 권한 허용 여부 확인 함수 (기존 로직 유지)
is_allowed_dba() {
  local acct="$1"
  local one=""
  IFS=',' read -r -a _arr <<< "$ALLOWED_DBA_RAW"
  for one in "${_arr[@]}"; do
    one="$(echo "$one" | xargs)"
    [ -z "$one" ] && continue
    [ "$acct" = "$one" ] && return 0
  done
  return 1
}

# 파이썬 대시보드 및 DB 저장 시 줄바꿈(\n) 처리를 위한 이스케이프 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 시스템 스키마 접근 위험 권한 후보 조회 (기존 쿼리 로직 유지)
RISK_CANDIDATES=$(run_psql "
WITH risk_role_member AS (
  SELECT DISTINCT m.rolname AS account
  FROM pg_auth_members am
  JOIN pg_roles m ON m.oid = am.member
  JOIN pg_roles r ON r.oid = am.roleid
  WHERE m.rolcanlogin = true
    AND m.rolsuper = false
    AND m.rolname <> 'admin01'
    AND m.rolname NOT LIKE 'pg_%'
    AND r.rolname IN (
      'pg_read_all_data',
      'pg_write_all_data',
      'pg_execute_server_program',
      'pg_read_server_files',
      'pg_write_server_files',
      'pg_signal_backend'
    )
),
risk_table_grant AS (
  SELECT DISTINCT tp.grantee AS account
  FROM information_schema.table_privileges tp
  JOIN pg_roles pr ON pr.rolname = tp.grantee
  WHERE tp.table_schema IN ('pg_catalog', 'information_schema')
    AND tp.grantee <> 'PUBLIC'
    AND pr.rolcanlogin = true
    AND pr.rolsuper = false
    AND pr.rolname <> 'admin01'
    AND pr.rolname NOT LIKE 'pg_%'
),
risk_accounts AS (
  SELECT account FROM risk_role_member
  UNION
  SELECT account FROM risk_table_grant
)
SELECT account
FROM risk_accounts
ORDER BY account;
")
RC=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 권한 부족으로 인한 애플리케이션 장애 위험과 수동 조치 가이드
GUIDE_LINE="이 항목에 대해서 시스템 테이블 접근 권한을 자동으로 회수할 경우, 해당 계정을 사용하는 운영 애플리케이션이나 모니터링 도구가 메타데이터를 조회하지 못해 서비스 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 미인가 계정에 대해 REVOKE 명령어를 사용하여 pg_catalog 및 information_schema 스키마에 대한 접근 권한을 회수하거나, pg_read_all_data와 같은 위험 내장 롤 멤버십을 제거하여 조치해 주시기 바랍니다."

# 쿼리 실행 성공 여부에 따른 점검 분기점
if [ $RC -ne 0 ]; then
  STATUS="FAIL"
  REASON_LINE="데이터베이스 시스템 권한 정보를 조회할 수 없어 미인가 계정 점검을 수행하지 못했습니다."
  DETAIL_CONTENT="database_query_error(access_denied_or_connection_fail)"
else
  # 허용된 DBA를 제외한 실제 미인가 위험 계정 필터링
  FILTERED=""
  while IFS= read -r acct; do
    [ -z "$acct" ] && continue
    if is_allowed_dba "$acct"; then
      continue
    fi
    FILTERED="${FILTERED}${acct}"$'\n'
  done <<< "$RISK_CANDIDATES"

  FILTERED_CSV="$(echo "$FILTERED" | sed '/^$/d' | tr '\n' ',' | sed 's/,$//')"

  # 점검 결과 판정 및 문장 구성 분기점
  if [ -z "$FILTERED_CSV" ]; then
    STATUS="PASS"
    REASON_LINE="허용되지 않은 일반 계정 중 시스템 스키마 접근 권한을 가진 계정이 존재하지 않아 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    # 취약한 설정 값(계정 목록)을 포함하여 사유 구성
    REASON_LINE="${FILTERED_CSV} 계정이 인가되지 않은 시스템 테이블 접근 권한을 보유하고 있어 이 항목에 대해 취약합니다."
  fi

  # 양호/취약 관계 없이 현재 설정값(조회된 모든 위험 후보 계정) 명시
  RAW_CANDIDATES_CSV="$(echo "$RISK_CANDIDATES" | sed '/^$/d' | tr '\n' ',' | sed 's/,$//')"
  DETAIL_CONTENT="[현재 시스템 테이블 접근 가능 위험 후보 계정 목록]\n${RAW_CANDIDATES_CSV:-없음}"
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="시스템 스키마 권한 위험 후보(role membership/table grants) 조회"
TARGET_FILE="pg_auth_members,information_schema.table_privileges"

# 요구사항을 반영한 RAW_EVIDENCE JSON 구성
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$(escape_json_str "$CHECK_COMMAND")",
  "detail": "$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "guide": "$(escape_json_str "$GUIDE_LINE")",
  "target_file": "$(escape_json_str "$TARGET_FILE")"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# 최종 결과 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF