#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-26"
STATUS="FAIL"

TARGET_FILE="postgresql.conf(logging_collector)"
CHECK_COMMAND="SHOW logging_collector;"

# JSON 내 특수문자 및 줄바꿈 처리를 위한 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# SQL logging_collector 설정값 조회
CURRENT_VALUE="$(run_psql "SHOW logging_collector;" | xargs)"

# 가이드 라인 변수 설정 (자동 조치 시 위험성 및 수동 조치 방법)
GUIDE_LINE="이 항목에 대해서 설정 값을 자동으로 변경하고 서비스를 재시작할 경우, 진행 중인 모든 세션이 강제로 종료되어 운영 중인 서비스에 즉각적인 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 postgresql.conf 파일에서 logging_collector 설정을 on으로 수정하거나 ALTER SYSTEM 명령을 사용한 뒤, 점검 시간대 외에 데이터베이스 서비스를 재시작하여 조치해 주시기 바랍니다."

# 설정 값에 따른 점검 결과 판정 분기점
if [ "$CURRENT_VALUE" = "on" ]; then
  STATUS="PASS"
  REASON_LINE="logging_collector 값이 on으로 설정되어 있어 이 항목에 대해 양호합니다."
elif [ "$CURRENT_VALUE" = "off" ]; then
  STATUS="FAIL"
  REASON_LINE="logging_collector 값이 off로 설정되어 있어 이 항목에 대해 취약합니다."
else
  STATUS="FAIL"
  REASON_LINE="logging_collector 설정 값을 확인하지 못하여 이 항목에 대해 취약합니다."
fi

# 양호/취약 여부와 관계없이 현재 설정 상태를 보여주는 상세 내용 구성
DETAIL_CONTENT="현재 PostgreSQL의 logging_collector 설정 값은 ${CURRENT_VALUE:-조회 실패}입니다."

# 데이터 수집 시점 기록
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# RAW_EVIDENCE JSON 구성 (detail은 사유와 상세 내용을 줄바꿈으로 구분)
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$(escape_json_str "$CHECK_COMMAND")",
  "detail": "$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "guide": "$(escape_json_str "$GUIDE_LINE")",
  "target_file": "$(escape_json_str "$TARGET_FILE")"
}
EOF
)

# 파이썬 및 DB 저장용 최종 이스케이프
RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# 최종 결과 출력 분기점
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF