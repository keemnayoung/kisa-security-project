#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정
# @Description : DBMS 계정 비밀번호에 대해 복잡도 정책이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-03"
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

escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# pg_hba.conf의 실제 파일 경로를 조회하여 변수에 저장
HBA_FILE="$(run_psql "SHOW hba_file;")"
HBA_FILE="$(echo "$HBA_FILE" | head -n 1 | xargs)"

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 운영 계정 잠금 위험과 수동 조치 가이드
GUIDE_LINE="이 항목에 대해서 일괄적으로 만료 정책이나 복잡도를 강제 적용할 경우, 기관 정책을 미처 인지하지 못한 운영 계정들이 대거 접속 차단되어 서비스 전체가 중단될 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 보안 가이드에 따라 ALTER ROLE <계정명> VALID UNTIL '<만료일>'; 명령을 사용하여 사용 기간을 설정하고, 필요 시 PAM 또는 LDAP과 연계하여 비밀번호 복잡도 정책을 조치해 주시기 바랍니다."

# pg_hba.conf 파일 존재 여부 및 접근 권한 확인
if [ -z "$HBA_FILE" ] || [ ! -f "$HBA_FILE" ]; then
  STATUS="FAIL"
  REASON_LINE="데이터베이스 설정 파일(pg_hba.conf)의 경로를 확인할 수 없거나 접근이 제한되어 점검을 수행하지 못했습니다."
  DETAIL_CONTENT="hba_file_path=NOT_FOUND_OR_PERMISSION_DENIED"
else
  # 인증 방식(method) 목록을 추출하여 현재 설정 값 파악
  AUTH_METHODS="$(grep -Ev '^\s*#|^\s*$' "$HBA_FILE" 2>/dev/null | awk '{print $NF}' | sort -u | tr '\n' ',' | sed 's/,$//')"
  
  # 만료 정책이 설정되지 않은 로그인 가능 계정 목록 조회
  NO_EXPIRY_USERS="$(run_psql "SELECT rolname FROM pg_roles WHERE rolcanlogin = true AND rolname NOT LIKE 'pg_%' AND rolvaliduntil IS NULL;")"
  
  # 인증 방식에 따른 보안성 판단 분기점
  if echo "$AUTH_METHODS" | grep -Eq 'pam|ldap|gss|sspi'; then
    STATUS="PASS"
    REASON_LINE="현재 pg_hba.conf에 외부 인증 방식(${AUTH_METHODS})이 설정되어 있어 이 항목에 대해 양호합니다."
  elif echo "$AUTH_METHODS" | grep -Eq 'password|md5|scram-sha-256'; then
    # 내부 인증 사용 시 계정별 만료 정책 설정 여부 판단
    if [ -z "$NO_EXPIRY_USERS" ]; then
      STATUS="PASS"
      REASON_LINE="내부 인증 방식(${AUTH_METHODS})을 사용 중이나 모든 로그인 계정에 만료 정책이 설정되어 있어 이 항목에 대해 양호합니다."
    else
      STATUS="FAIL"
      # 취약한 계정 목록을 쉼표로 나열하여 자연스러운 문장 구성
      CLEAN_USERS=$(echo "$NO_EXPIRY_USERS" | tr '\n' ',' | sed 's/,$//')
      REASON_LINE="내부 인증 방식(${AUTH_METHODS})을 사용 중이며 ${CLEAN_USERS} 계정에 만료 정책이 설정되어 있지 않아 이 항목에 대해 취약합니다."
    fi
  else
    STATUS="FAIL"
    REASON_LINE="현재 pg_hba.conf에 설정된 인증 방식(${AUTH_METHODS})이 보안 정책 충족 여부를 판단할 수 없는 방식이므로 이 항목에 대해 취약합니다."
  fi
  
  # 양호/취약 관계 없이 수집된 현재 설정 값들을 상세 내용으로 구성
  DETAIL_CONTENT="[비밀번호 정책 관련 현재 설정 현황]\n- 인증 방식: ${AUTH_METHODS}\n- 만료 미설정 계정 리스트:\n$(echo "${NO_EXPIRY_USERS:-None}" | sed 's/^/  * /')"
fi

# 증적 정보 및 명령어 설정
CHECK_COMMAND="psql -c \"SHOW hba_file; SELECT rolname FROM pg_roles WHERE rolvaliduntil IS NULL;\""
TARGET_FILE="$HBA_FILE"

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