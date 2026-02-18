#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-25
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : world writable 파일 점검
# @Description : 불필요한 world writable 파일 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-25"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/"
CHECK_COMMAND='find / \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o -type f -perm -2 -exec ls -l {} \; 2>/dev/null'

TMP_RESULT_FULL="/tmp/U25_world_writable_files_full.txt"
TMP_RESULT_VIEW="/tmp/U25_world_writable_files_view.txt"

DETAIL_CONTENT=""
REASON_LINE=""

# 점검: world writable 파일 탐색(가상/런타임 파일시스템 제외)
find / \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_RESULT_FULL"

FILE_COUNT=$(wc -l < "$TMP_RESULT_FULL" 2>/dev/null | tr -d ' ')

# 출력 과도 방지용으로 detail에 넣을 목록은 상위 일부만 사용(현재 설정값 표시 목적)
head -n 300 "$TMP_RESULT_FULL" > "$TMP_RESULT_VIEW" 2>/dev/null

if [ "${FILE_COUNT:-0}" -eq 0 ]; then
    # 양호 분기
    STATUS="PASS"
    REASON_LINE="world writable 파일이 0건으로 확인되어 이 항목에 대해 양호합니다."
    DETAIL_CONTENT="world writable 파일 검색 결과: 0건"
else
    # 취약 분기(기술적으로는 취약이며, 인지 여부는 관리자가 판단)
    STATUS="FAIL"
    FIRST_LINE="$(sed -n '1p' "$TMP_RESULT_FULL" 2>/dev/null)"
    if [ -n "$FIRST_LINE" ]; then
        REASON_LINE="world writable 파일이 ${FILE_COUNT}건 존재하며 예를 들어 '${FIRST_LINE}'와 같이 설정되어 있어 이 항목에 대해 취약합니다."
    else
        REASON_LINE="world writable 파일이 ${FILE_COUNT}건 존재하는 것으로 확인되어 이 항목에 대해 취약합니다."
    fi

    if [ "$FILE_COUNT" -le 300 ]; then
        DETAIL_CONTENT="world writable 파일 검색 결과: ${FILE_COUNT}건\n$(cat "$TMP_RESULT_VIEW")"
    else
        DETAIL_CONTENT="world writable 파일 검색 결과: ${FILE_COUNT}건\n$(cat "$TMP_RESULT_VIEW")\n표시: 총 ${FILE_COUNT}건 중 상위 300건"
    fi
fi

GUIDE_LINE="자동으로 권한을 변경하거나 파일을 삭제하면 해당 파일을 필요로 하는 서비스/배치/응용 프로그램에 장애가 발생할 수 있습니다.
관리자가 world writable 파일 목록을 직접 확인한 뒤 불필요한 경우 chmod o-w <파일>로 쓰기 권한을 제거하거나 rm <파일>로 제거해 주시기 바랍니다."

# raw_evidence 구성(detail은 1문장 + 줄바꿈 + 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리(따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF

# 임시 파일 정리
rm -f "$TMP_RESULT_FULL" "$TMP_RESULT_VIEW"
