#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-18
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정
# @Description : 응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-18"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

# 파이썬 대시보드 및 DB 연동 시 줄바꿈(\n)을 유지하기 위한 이스케이프 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# PUBLIC(grantee=0)에 부여된 스키마 권한 정보 조회 쿼리 실행
PUBLIC_SCHEMA_CREATE=$(run_psql "
SELECT n.nspname || ':' || e.privilege_type
FROM pg_namespace n
JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) e ON true
WHERE e.grantee = 0
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND (
    (n.nspname = 'public' AND e.privilege_type = 'CREATE')
    OR
    (n.nspname <> 'public' AND e.privilege_type IN ('CREATE','USAGE'))
  )
ORDER BY 1;
")
RC=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 권한 회수로 인한 응용 프로그램 장애 위험 및 수동 조치 방법 정의
GUIDE_LINE="이 항목에 대해서 PUBLIC 권한을 자동으로 회수할 경우, 해당 권한을 통해 임시 테이블을 생성하거나 스키마를 사용하던 기존 응용 프로그램의 쿼리가 즉시 실패하여 서비스 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 REVOKE CREATE ON SCHEMA public FROM PUBLIC; 명령을 사용하여 불필요한 PUBLIC 권한을 수동으로 회수해 주시기 바랍니다."

# 쿼리 실행 결과 및 권한 존재 여부에 따른 판정
if [ $RC -ne 0 ]; then
  STATUS="FAIL"
  REASON_LINE="데이터베이스 권한 정보(pg_namespace)를 조회하지 못하여 PUBLIC 권한 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="database_query_error(check_psql_connection_or_privilege)"
elif [ -z "$PUBLIC_SCHEMA_CREATE" ]; then
  STATUS="PASS"
  REASON_LINE="비시스템 스키마에서 PUBLIC에 부여된 CREATE 또는 USAGE 권한이 확인되지 않아 이 항목에 대해 양호합니다."
  # 양호 시에도 현재 설정 상태를 명시
  DETAIL_CONTENT="PUBLIC 권한 설정 현황: 발견된 위험 권한 없음"
else
  STATUS="FAIL"
  # 취약 시 확인된 설정 값들을 콤마로 연결하여 문장 구성
  VULN_VALS=$(echo "$PUBLIC_SCHEMA_CREATE" | tr '\n' ',' | sed 's/,$//')
  REASON_LINE="${VULN_VALS} 권한이 PUBLIC에 부여되어 있어 이 항목에 대해 취약합니다."
  # 현재의 모든 설정 값들을 상세 정보로 구성
  DETAIL_CONTENT="[현재 PUBLIC 부여 권한 목록]\n$(echo "$PUBLIC_SCHEMA_CREATE" | sed 's/^/- /')"
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="aclexplode 기반 PUBLIC(grantee=0) 스키마 권한(CREATE/USAGE) 점검"
TARGET_FILE="pg_namespace(nspacl),aclexplode(),schema(public 및 비시스템 스키마)"

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