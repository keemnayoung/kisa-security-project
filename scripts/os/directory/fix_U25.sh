#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-25
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : world writable 파일 점검
# @Description : world writable 권한 제거 (chmod o-w)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

###################
# 검토 필요
###################

# # 기본 변수
# ID="U-25"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# TMP_AFTER="/tmp/u25_world_writable_after.txt"

# CHECK_COMMAND="find / -type f -perm -2 -exec ls -l {} \\; 2>/dev/null"
# TARGET_FILE="/ (all files)"

# # 조치 수행: other write 제거
# find / -type f -perm -2 2>/dev/null | while IFS= read -r FILE_PATH; do
#   [ -f "$FILE_PATH" ] || continue
#   chmod o-w "$FILE_PATH" 2>/dev/null
# done

# # 조치 후 재확인(조치 후 상태만 detail에 표시)
# find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_AFTER"

# if [ ! -s "$TMP_AFTER" ]; then
#   IS_SUCCESS=1
#   REASON_LINE="world writable 파일이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   DETAIL_CONTENT=""
# else
#   IS_SUCCESS=0
#   REASON_LINE="조치를 수행했으나 world writable 파일이 남아 있어 조치가 완료되지 않았습니다."
#   DETAIL_CONTENT="$(cat "$TMP_AFTER")"
# fi

# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
#   | sed 's/"/\\"/g' \
#   | sed ':a;N;$!ba;s/\n/\\n/g')

# echo ""
# cat << EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF

# rm -f "$TMP_AFTER"