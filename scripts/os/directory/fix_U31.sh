#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-31
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# # 기본 변수
# ID="U-31"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# PASSWD_FILE="/etc/passwd"
# CHECK_COMMAND="awk -F: '(\$3+0)>=1000 {print \$1 \":\" \$6}' /etc/passwd 2>/dev/null | while IFS=: read -r u h; do [ -d \"\$h\" ] && stat -c '%U %a %n' \"\$h\"; done"
# TARGET_FILE="/etc/passwd"

# FAIL_FLAG=0
# FOUND=0
# MODIFIED=0
# DETAIL_CONTENT=""

# # 조치 수행
# if [ -f "$PASSWD_FILE" ]; then
#   while IFS=: read -r USER _ UID _ _ HOME _; do
#     UID_CLEAN=$(echo "$UID" | tr -cd '0-9')
#     [ -z "$UID_CLEAN" ] && continue
#     [ "$UID_CLEAN" -lt 1000 ] && continue

#     [ -d "$HOME" ] || continue
#     FOUND=1

#     CUR_OWNER=$(stat -c "%U" "$HOME" 2>/dev/null | tr -d '[:space:]')
#     CUR_PERM=$(stat -c "%a" "$HOME" 2>/dev/null | tr -d '[:space:]')

#     if [ -n "$CUR_OWNER" ] && [ "$CUR_OWNER" != "$USER" ]; then
#       chown "$USER":"$USER" "$HOME" 2>/dev/null
#       MODIFIED=1
#     fi

#     if [ -n "$CUR_PERM" ]; then
#       OTHER_DIGIT=$((CUR_PERM % 10))
#       if [ "$OTHER_DIGIT" -ge 2 ]; then
#         chmod o-w "$HOME" 2>/dev/null
#         MODIFIED=1
#       fi
#     fi
#   done < "$PASSWD_FILE"
# fi

# # 조치 후 상태 수집(조치 후 상태만 detail에 표시)
# if [ -f "$PASSWD_FILE" ]; then
#   while IFS=: read -r USER _ UID _ _ HOME _; do
#     UID_CLEAN=$(echo "$UID" | tr -cd '0-9')
#     [ -z "$UID_CLEAN" ] && continue
#     [ "$UID_CLEAN" -lt 1000 ] && continue

#     [ -d "$HOME" ] || continue

#     AFTER_OWNER=$(stat -c "%U" "$HOME" 2>/dev/null | tr -d '[:space:]')
#     AFTER_PERM=$(stat -c "%a" "$HOME" 2>/dev/null | tr -d '[:space:]')

#     DETAIL_CONTENT="${DETAIL_CONTENT}user=$USER
# home=$HOME
# owner=$AFTER_OWNER
# perm=$AFTER_PERM

# "

#     if [ "$AFTER_OWNER" != "$USER" ]; then
#       FAIL_FLAG=1
#       continue
#     fi

#     if [ -n "$AFTER_PERM" ]; then
#       AFTER_OTHER=$((AFTER_PERM % 10))
#       if [ "$AFTER_OTHER" -ge 2 ]; then
#         FAIL_FLAG=1
#       fi
#     else
#       FAIL_FLAG=1
#     fi
#   done < "$PASSWD_FILE"
# else
#   FAIL_FLAG=1
# fi

# # 최종 판정
# if [ ! -f "$PASSWD_FILE" ]; then
#   IS_SUCCESS=0
#   REASON_LINE="조치 대상 파일(/etc/passwd)이 존재하지 않아 조치가 완료되지 않았습니다."
#   DETAIL_CONTENT=""
# elif [ "$FOUND" -eq 0 ]; then
#   IS_SUCCESS=1
#   REASON_LINE="UID 1000 이상의 사용자 홈 디렉터리 조치 대상이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   DETAIL_CONTENT=""
# else
#   if [ "$FAIL_FLAG" -eq 0 ]; then
#     IS_SUCCESS=1
#     if [ "$MODIFIED" -eq 1 ]; then
#       REASON_LINE="UID 1000 이상의 사용자 홈 디렉터리 소유자가 해당 계정으로 설정되고 other 쓰기 권한이 제거되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     else
#       REASON_LINE="UID 1000 이상의 사용자 홈 디렉터리 소유자가 해당 계정으로 유지되고 other 쓰기 권한이 제거된 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     fi
#   else
#     IS_SUCCESS=0
#     REASON_LINE="조치를 수행했으나 일부 사용자 홈 디렉터리의 소유자 또는 other 쓰기 권한 기준을 충족하지 못해 조치가 완료되지 않았습니다."
#   fi
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