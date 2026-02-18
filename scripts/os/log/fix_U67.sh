#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-16
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-67
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 로그 디렉터리 소유자 및 권한 설정
# @Description : 디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# # 기본 변수
# ID="U-67"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# TARGET_DIR="/var/log"
# TARGET_FILE="$TARGET_DIR"
# CHECK_COMMAND="find /var/log -type f -exec stat -c '%U %G %a %n' {} \\; 2>/dev/null | head -n 500"

# FOUND_FILES=0
# FAIL_FLAG=0
# MODIFIED=0
# DETAIL_CONTENT=""

# # 조치 수행
# if [ -d "$TARGET_DIR" ]; then
#   while IFS= read -r file; do
#     [ -f "$file" ] || continue
#     FOUND_FILES=1

#     OWNER=$(stat -c "%U" "$file" 2>/dev/null)
#     GROUP=$(stat -c "%G" "$file" 2>/dev/null)
#     PERM=$(stat -c "%a" "$file" 2>/dev/null)

#     if [ "$OWNER" != "root" ]; then
#       chown root "$file" 2>/dev/null
#       MODIFIED=1
#     fi

#     if [ -n "$PERM" ] && [ "$PERM" -gt 644 ]; then
#       chmod 644 "$file" 2>/dev/null
#       MODIFIED=1
#     fi
#   done < <(find "$TARGET_DIR" -type f 2>/dev/null)

#   # 조치 후 상태 수집(조치 후 상태만 detail에 표시)
#   while IFS= read -r file; do
#     [ -f "$file" ] || continue

#     AFTER_OWNER=$(stat -c "%U" "$file" 2>/dev/null)
#     AFTER_GROUP=$(stat -c "%G" "$file" 2>/dev/null)
#     AFTER_PERM=$(stat -c "%a" "$file" 2>/dev/null)

#     DETAIL_CONTENT="${DETAIL_CONTENT}owner=$AFTER_OWNER
# group=$AFTER_GROUP
# perm=$AFTER_PERM
# file=$file

# "

#     if [ "$AFTER_OWNER" != "root" ]; then
#       FAIL_FLAG=1
#       continue
#     fi

#     if [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 644 ]; then
#       FAIL_FLAG=1
#     fi
#   done < <(find "$TARGET_DIR" -type f 2>/dev/null)

#   if [ "$FOUND_FILES" -eq 0 ]; then
#     IS_SUCCESS=1
#     REASON_LINE="/var/log 디렉터리 내 로그 파일이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     DETAIL_CONTENT=""
#   else
#     if [ "$FAIL_FLAG" -eq 0 ]; then
#       IS_SUCCESS=1
#       if [ "$MODIFIED" -eq 1 ]; then
#         REASON_LINE="/var/log 디렉터리 내 로그 파일의 소유자가 root로 설정되고 권한이 644 이하로 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#       else
#         REASON_LINE="/var/log 디렉터리 내 로그 파일의 소유자가 root로 유지되고 권한이 644 이하로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#       fi
#     else
#       IS_SUCCESS=0
#       REASON_LINE="조치를 수행했으나 /var/log 디렉터리 내 일부 로그 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
#     fi
#   fi
# else
#   IS_SUCCESS=0
#   REASON_LINE="로그 디렉터리(/var/log)가 존재하지 않아 조치가 완료되지 않았습니다."
#   DETAIL_CONTENT=""
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