#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-23
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 주요 실행 파일의 권한에 SUID와 SGID에 대한 설정 해제
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#######################
# 검토 필요
#######################

# # 기본 변수
# ID="U-23"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# CHECK_COMMAND="find / -xdev -user root -type f \\( -perm -04000 -o -perm -02000 \\) 2>/dev/null"
# TARGET_FILE="/ (xdev)"

# # SUID/SGID 대상 수집
# SUID_SGID_FILES=$(find / -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null)

# # 조치 수행
# if [ -n "$SUID_SGID_FILES" ]; then
#   for FILE in $SUID_SGID_FILES; do
#     chmod -s "$FILE" 2>/dev/null
#   done
# fi

# # 조치 후 재확인(조치 후 상태만 detail에 표시)
# REMAIN_FILES=$(find / -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null)

# if [ -z "$REMAIN_FILES" ]; then
#   IS_SUCCESS=1
#   if [ -z "$SUID_SGID_FILES" ]; then
#     REASON_LINE="SUID 또는 SGID가 설정된 대상 파일이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   else
#     REASON_LINE="SUID 및 SGID 권한이 제거되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   fi
#   DETAIL_CONTENT=""
# else
#   IS_SUCCESS=0
#   REASON_LINE="조치를 수행했으나 SUID 또는 SGID 권한이 남아 있어 조치가 완료되지 않았습니다."
#   DETAIL_CONTENT="$REMAIN_FILES"
# fi

# # raw_evidence 구성
# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# # JSON escape 처리 (따옴표, 줄바꿈)
# RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
#   | sed 's/"/\\"/g' \
#   | sed ':a;N;$!ba;s/\n/\\n/g')

# # DB 저장용 JSON 출력
# echo ""
# cat << EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF