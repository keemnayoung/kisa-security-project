#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-26
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : /dev에 존재하지 않는 device 파일 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-26"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/dev"
CHECK_COMMAND_MAIN='find /dev \( -path /dev/mqueue -o -path /dev/mqueue/\* -o -path /dev/shm -o -path /dev/shm/\* \) -prune -o -type f -print'

DETAIL_CONTENT=""
REASON_LINE=""

# /dev 디렉터리 내 일반 파일 탐색(예외: /dev/mqueue, /dev/shm)
INVALID_FILES=$(find /dev \
  \( -path /dev/mqueue -o -path /dev/mqueue/\* -o -path /dev/shm -o -path /dev/shm/\* \) -prune -o \
  -type f -print 2>/dev/null)

# 현재 설정값
if [ -n "$INVALID_FILES" ]; then
  INVALID_FILES_CSV=$(echo "$INVALID_FILES" | paste -sd ", " -)
  LS_INFO=$(echo "$INVALID_FILES" | xargs -r ls -l 2>/dev/null)
  DETAIL_CONTENT="일반 파일(-type f) 목록(쉼표 구분): ${INVALID_FILES_CSV}
ls -l 결과:
${LS_INFO}"
else
  INVALID_FILES_CSV="none"
  DETAIL_CONTENT="일반 파일(-type f) 목록(쉼표 구분): none
ls -l 결과:
none"
fi

# 양호/취약 판단 및 detail
if [ -n "$INVALID_FILES" ]; then
  STATUS="FAIL"
  REASON_LINE="/dev에 일반 파일(-type f)이 존재(${INVALID_FILES_CSV})하여 이 항목에 대해 취약합니다."
else
  STATUS="PASS"
  REASON_LINE="/dev에 일반 파일(-type f)이 존재하지 않아 이 항목에 대해 양호합니다."
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE="이 항목에 대해서 /dev 경로에서 잘못된 파일을 자동으로 삭제할 경우 정상 동작 중인 구성요소에 영향을 줄 수 있는 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 /dev에서 일반 파일을 점검하고 불필요하거나 존재하지 않는 파일을 rm로 삭제해 조치해 주시기 바랍니다."

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "${CHECK_COMMAND_MAIN}
예외: /dev/mqueue, /dev/shm",
  "detail": "${REASON_LINE}
${DETAIL_CONTENT}",
  "target_file": "${TARGET_FILE}
예외: /dev/mqueue, /dev/shm",
  "guide": "${GUIDE_LINE}"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
