#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-20
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 하
# @Title       : 인가되지 않은 Object Owner의 제한
# @Description : Object Owner가 인가된 계정에게만 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-20"
STATUS="FAIL"
ALLOWED_OBJECT_OWNERS="${ALLOWED_OBJECT_OWNERS:-postgres}"

# 허용된 소유자 목록을 SQL IN절 형식으로 변환
SQL_LIST=$(printf "'%s'," $(echo "$ALLOWED_OBJECT_OWNERS" | tr ',' ' '))
SQL_LIST=${SQL_LIST%,}

# 파이썬 대시보드 및 DB 연동 시 줄바꿈(\n) 유지를 위한 이스케이프 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 비시스템 스키마 객체 소유자 정보 조회 실행
UNAUTH_OWNERS=$(run_psql "
SELECT n.nspname || '.' || c.relname || ':' || pg_get_userbyid(c.relowner)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog','information_schema')
  AND c.relkind IN ('r','v','m','S','f')
  AND pg_get_userbyid(c.relowner) NOT IN (${SQL_LIST})
ORDER BY 1;
")
RC=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 소유권 변경으로 인한 애플리케이션의 객체 접근/관리 권한 유실 위험 및 조치 가이드
GUIDE_LINE="이 항목에 대해서 객체 소유자를 자동으로 변경할 경우, 기존에 해당 객체를 생성하고 관리하던 응용 프로그램 계정이 소유권 기반의 DDL 수행 권한을 잃게 되어 패치나 운영 작업 중 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 ALTER TABLE ... OWNER TO ... 명령어를 사용하여 비인가된 객체 소유권을 인가된 관리자 계정으로 수동 조치해 주시기 바랍니다."

# 쿼리 실행 결과 및 비인가 소유자 존재 여부에 따른 판정 분기점
if [ $RC -ne 0 ]; then
  STATUS="FAIL"
  REASON_LINE="객체 소유자 정보를 조회하지 못하여 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="database_query_error(connection_or_permission_issue)"
elif [ -z "$UNAUTH_OWNERS" ]; then
  STATUS="PASS"
  REASON_LINE="비시스템 스키마 객체의 소유자가 ${ALLOWED_OBJECT_OWNERS} 계정으로만 구성되어 있어 이 항목에 대해 양호합니다."
  # 양호 시에도 현재 점검 기준 정보 명시
  DETAIL_CONTENT="허용된 소유자 목록: ${ALLOWED_OBJECT_OWNERS}\n비인가 객체 발견되지 않음"
else
  # 비인가 소유자 및 객체 정보 정리
  UNAUTH_COUNT="$(printf '%s\n' "$UNAUTH_OWNERS" | sed '/^$/d' | wc -l | xargs)"
  UNAUTH_OWNER_LIST="$(printf '%s\n' "$UNAUTH_OWNERS" | awk -F: 'NF>=2{print $2}' | sed '/^$/d' | sort -u | tr '\n' ',' | sed 's/,$//')"
  
  STATUS="FAIL"
  # 취약 시 취약한 설정 값(비인가 계정 목록 및 객체 수)을 포함하여 사유 구성
  REASON_LINE="${UNAUTH_OWNER_LIST} 계정이 소유한 ${UNAUTH_COUNT}개의 객체가 허용 목록에 포함되지 않아 이 항목에 대해 취약합니다."
  # 현재의 모든 비인가 소유 현황을 상세 정보로 구성
  DETAIL_CONTENT="[현재 비인가 객체 소유 현황]\n- 인가 계정 기준: ${ALLOWED_OBJECT_OWNERS}\n- 비인가 소유자 목록: ${UNAUTH_OWNER_LIST}\n- 상세 객체 목록:\n$(echo "$UNAUTH_OWNERS" | sed 's/^/- /')"
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="pg_class/pg_namespace 기반 비시스템 스키마 객체의 소유자 허용 목록 외 점검"
TARGET_FILE="pg_class.relowner"

# 요구사항에 맞춘 RAW_EVIDENCE 구조화 및 JSON 이스케핑
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

# 최종 결과 JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF