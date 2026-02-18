#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-15
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 조치
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#####################
# 수동 조치 필요
######################

# # 기본 변수
# ID="U-15"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND="find / -xdev \\( -nouser -o -nogroup \\) ! -path \"/proc/*\" ! -path \"/sys/*\" ! -path \"/dev/*\" 2>/dev/null"
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE="/ (excluding: /proc, /sys, /dev)"

# ORPHAN_FILES=$(find / \
#   -xdev \
#   \( -nouser -o -nogroup \) \
#   ! -path "/proc/*" \
#   ! -path "/sys/*" \
#   ! -path "/dev/*" \
#   2>/dev/null)

# if [ -n "$ORPHAN_FILES" ]; then
#   IS_SUCCESS=0
#   REASON_LINE="소유자 또는 그룹이 존재하지 않는 파일 및 디렉터리가 발견되어 조치가 완료되지 않았습니다."
#   DETAIL_CONTENT="$ORPHAN_FILES"
# else
#   IS_SUCCESS=1
#   REASON_LINE="소유자 또는 그룹이 존재하지 않는 파일 및 디렉터리가 존재하지 않아 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   DETAIL_CONTENT=""
# fi

# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# echo ""
# cat << EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF