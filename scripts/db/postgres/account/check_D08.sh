#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : 해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-08"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="pg_hba_file_rules,pg_authid.rolpassword"
CHECK_COMMAND="(pg_hba_file_rules의 md5 규칙 조회) + (pg_authid 로그인 계정 rolpassword SCRAM 여부 점검)"

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

# md5 인증 방식이 적용된 규칙을 가독성 있게 포맷팅하는 함수
format_md5_rules() {
  local rows="$1"
  local out=""
  while IFS='|' read -r ln typ db usr addr; do
    [ -n "$typ" ] || continue
    out="${out}${typ} db=${db} user=${usr} addr=${addr}, "
  done <<< "$rows"
  printf "%s" "${out%, }"
}

# SCRAM-SHA-256을 사용하지 않는 계정을 포맷팅하는 함수
format_non_scram() {
  local rows="$1"
  local out=""
  while IFS='|' read -r role algo; do
    [ -z "$role" ] && continue
    out="${out}${role}(${algo}), "
  done <<< "$rows"
  printf "%s" "${out%, }"
}

# pg_hba_file_rules에서 md5 인증 규칙 조회
MD5_RULE_ROWS=$(run_psql "
SELECT line_number || '|' || type || '|' ||
       COALESCE(array_to_string(database, ','), '') || '|' ||
       COALESCE(array_to_string(user_name, ','), '') || '|' ||
       COALESCE(address, 'local')
FROM pg_hba_file_rules
WHERE error IS NULL
  AND lower(auth_method) = 'md5'
ORDER BY line_number;
")
MD5_RC=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 접속 불능 위험과 수동 조치 가이드를 변수로 정의
GUIDE_LINE="이 항목에 대해서 인증 방식을 강제로 변경하거나 계정 암호를 재설정할 경우, 기존 md5 기반 클라이언트 프로그램이나 암호화 방식이 일치하지 않는 애플리케이션의 데이터베이스 접속이 즉시 차단되어 서비스 중단이 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 pg_hba.conf의 md5를 scram-sha-256으로 변경하고, 관련 계정의 비밀번호를 ALTER ROLE <계정명> WITH PASSWORD '<비밀번호>'; 명령을 통해 최신 알고리즘으로 갱신하여 조치해 주시기 바랍니다."

# pg_hba_file_rules 조회 성공 여부에 따른 분기점
if [ $MD5_RC -ne 0 ]; then
  STATUS="FAIL"
  REASON_LINE="pg_hba_file_rules 시스템 테이블 조회 권한이 부족하여 인증 규칙을 점검할 수 없습니다."
  DETAIL_CONTENT="database_access_error(pg_hba_file_rules=PERMISSION_DENIED)"
else
  # 로그인 계정의 암호 해시 알고리즘 현황 조회
  NON_SCRAM_ROWS=$(run_psql "
  SELECT rolname || '|' ||
         CASE
           WHEN COALESCE(rolpassword, '') = '' THEN 'NO_PASSWORD'
           WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256'
           WHEN rolpassword LIKE 'md5%' THEN 'MD5'
           ELSE 'OTHER'
         END
  FROM pg_authid
  WHERE rolcanlogin = true
    AND rolname NOT LIKE 'pg_%'
  ORDER BY rolname;
  ")
  
  MD5_DESC="$(format_md5_rules "$MD5_RULE_ROWS")"
  NON_SCRAM_DESC="$(format_non_scram "$NON_SCRAM_ROWS")"
  VULN_ACCOUNT_DESC="$(echo "$NON_SCRAM_ROWS" | grep -v "SCRAM-SHA-256" | while IFS='|' read -r role algo; do echo -n "${role}(${algo}), "; done | sed 's/, $//')"

  # 인증 규칙 및 계정 해시 상태에 따른 결과 판정 분기점
  if [ -z "$MD5_DESC" ] && [ -z "$VULN_ACCOUNT_DESC" ]; then
    STATUS="PASS"
    REASON_LINE="모든 인증 규칙이 scram-sha-256 이상이며 모든 로그인 계정이 안전한 암호화 알고리즘을 사용하고 있어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    # 취약한 부분의 설정값만 사용하여 사유 구성
    VULN_REASON=""
    [ -n "$MD5_DESC" ] && VULN_REASON="인증 규칙에 md5 방식(${MD5_DESC})이 포함되어 있고 "
    [ -n "$VULN_ACCOUNT_DESC" ] && VULN_REASON="${VULN_REASON}${VULN_ACCOUNT_DESC} 계정이 약한 알고리즘을 사용하고 있어 "
    REASON_LINE="${VULN_REASON}이 항목에 대해 취약합니다."
  fi
  
  # 전체 설정 현황을 상세 내용으로 구성
  DETAIL_CONTENT="[인증 및 암호화 알고리즘 설정 현황]\n- md5 인증 규칙: ${MD5_DESC:-없음}\n- 계정별 암호 알고리즘: ${NON_SCRAM_DESC:-없음}"
fi

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

# JSON 데이터 이스케이프 및 출력
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