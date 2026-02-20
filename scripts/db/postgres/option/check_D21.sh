#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 ROLE에 의하여 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-21"
STATUS="FAIL"

# 파이썬 대시보드 및 DB 연동 시 줄바꿈(\n) 유지를 위한 이스케이프 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 일반 사용자 중 GRANT OPTION(is_grantable=YES) 보유 현황 조회 실행
TARGET_GRANTS=$(run_psql "
SELECT grantee || ':' || table_schema || '.' || table_name || ':' || privilege_type
FROM information_schema.role_table_grants rtg
JOIN pg_roles r ON r.rolname = rtg.grantee
WHERE rtg.is_grantable = 'YES'
  AND r.rolsuper = false
  AND r.rolname NOT LIKE 'pg_%'
  AND rtg.grantee <> 'PUBLIC'
ORDER BY 1;
")
RC=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 권한 체인 단절로 인한 하위 사용자 접근 불가 위험 및 조치 가이드
GUIDE_LINE="이 항목에 대해서 GRANT OPTION을 자동으로 회수할 경우, 해당 사용자가 다른 사용자에게 부여했던 권한들이 연쇄적으로 회수(CASCADE)되어 업무 프로세스가 중단되거나 서비스 접근 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 REVOKE GRANT OPTION FOR <권한> ON <객체> FROM <계정명> 명령을 사용하여 불필요한 재위임 권한을 수동으로 회수해 주시기 바랍니다."

# 쿼리 실행 결과 및 권한 보유 여부
if [ $RC -ne 0 ]; then
  STATUS="FAIL"
  REASON_LINE="권한 재위임 정보(role_table_grants)를 조회하지 못하여 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="database_query_error(connection_or_permission_issue)"
elif [ -z "$TARGET_GRANTS" ]; then
  STATUS="PASS"
  REASON_LINE="일반 사용자 계정에 부여된 GRANT OPTION 항목이 존재하지 않아 이 항목에 대해 양호합니다."
  # 양호 시에도 현재 설정 상태 명시
  DETAIL_CONTENT="현재 GRANT OPTION 보유 일반 계정 없음"
else
  STATUS="FAIL"
  TOTAL_CNT="$(printf '%s\n' "$TARGET_GRANTS" | sed '/^$/d' | wc -l | xargs)"
  VULN_SUMMARY="$(printf '%s\n' "$TARGET_GRANTS" | sed '/^$/d' | tr '\n' ',' | sed 's/,$//')"
  
  # 취약 시 취약한 설정 값(권한 목록)을 포함하여 사유 구성
  REASON_LINE="${VULN_SUMMARY}와 같이 일반 사용자에게 권한 재위임이 가능한 GRANT OPTION이 설정되어 있어 이 항목에 대해 취약합니다."
  
  # 현재의 모든 설정 현황을 상세 정보로 구성
  DETAIL_CONTENT="[현재 일반 계정 GRANT OPTION 부여 현황]\n- 총 건수: ${TOTAL_CNT}건\n- 상세 목록:\n$(echo "$TARGET_GRANTS" | sed 's/^/- /')"
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="information_schema.role_table_grants 기반 GRANT OPTION(is_grantable='YES') 점검"
TARGET_FILE="information_schema.role_table_grants"

# raw_evidence 구성
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$(escape_json_str "$CHECK_COMMAND")",
  "detail": "$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "guide": "$(escape_json_str "$GUIDE_LINE")",
  "target_file": "$(escape_json_str "$TARGET_FILE")"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

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