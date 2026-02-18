#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-32
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 홈 디렉토리가 존재하지 않는 계정이 발견되지 않도록 조치
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#######################
# 삭제는 수동으로 처리
#######################

# ID="U-32"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# PASSWD_FILE="/etc/passwd"
# TARGET_FILE="/etc/passwd"
# CHECK_COMMAND="awk -F: '(\$3+0)>=1000 {print \$1 \":\" \$6}' /etc/passwd 2>/dev/null | while IFS=: read -r u h; do [ -d \"\$h\" ] && echo \"\$u:\$h\" || echo \"\$u:\$h\"; done"

# FOUND_MISSING=0
# FOUND_USERS=0
# FAIL_FLAG=0
# MODIFIED=0
# DETAIL_CONTENT=""

# # 조치 수행
# if [ -f "$PASSWD_FILE" ]; then
#   while IFS=: read -r username _ uid _ _ homedir _; do
#     UID_CLEAN=$(echo "$uid" | tr -cd '0-9')
#     [ -z "$UID_CLEAN" ] && continue
#     [ "$UID_CLEAN" -lt 1000 ] && continue

#     FOUND_USERS=1

#     if [ ! -d "$homedir" ]; then
#       FOUND_MISSING=1

#       mkdir -p "$homedir" 2>/dev/null
#       chown "$username":"$username" "$homedir" 2>/dev/null
#       chmod 700 "$homedir" 2>/dev/null

#       MODIFIED=1
#     fi
#   done < "$PASSWD_FILE"
# fi

# # 조치 후 상태 수집(조치 후 상태만 detail에 표시)
# if [ -f "$PASSWD_FILE" ]; then
#   while IFS=: read -r username _ uid _ _ homedir _; do
#     UID_CLEAN=$(echo "$uid" | tr -cd '0-9')
#     [ -z "$UID_CLEAN" ] && continue
#     [ "$UID_CLEAN" -lt 1000 ] && continue

#     if [ -d "$homedir" ]; then
#       AFTER_OWNER=$(stat -c "%U" "$homedir" 2>/dev/null)
#       AFTER_GROUP=$(stat -c "%G" "$homedir" 2>/dev/null)
#       AFTER_PERM=$(stat -c "%a" "$homedir" 2>/dev/null)

#       DETAIL_CONTENT="${DETAIL_CONTENT}user=$username
# home=$homedir
# owner=$AFTER_OWNER
# group=$AFTER_GROUP
# perm=$AFTER_PERM

# "

#       if [ "$AFTER_OWNER" != "$username" ] || [ "$AFTER_GROUP" != "$username" ] || [ -z "$AFTER_PERM" ] || [ "$AFTER_PERM" -ne 700 ]; then
#         FAIL_FLAG=1
#       fi
#     else
#       DETAIL_CONTENT="${DETAIL_CONTENT}user=$username
# home=$homedir

# "

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
# else
#   if [ "$FOUND_USERS" -eq 0 ]; then
#     IS_SUCCESS=1
#     REASON_LINE="UID 1000 이상의 사용자 계정이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     DETAIL_CONTENT=""
#   else
#     if [ "$FAIL_FLAG" -eq 0 ]; then
#       IS_SUCCESS=1
#       if [ "$MODIFIED" -eq 1 ]; then
#         REASON_LINE="홈 디렉토리가 없던 계정의 홈 디렉토리가 생성되고 권한이 700으로 설정되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#       else
#         REASON_LINE="모든 사용자 계정의 홈 디렉토리가 존재하여 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#       fi
#     else
#       IS_SUCCESS=0
#       REASON_LINE="조치를 수행했으나 일부 계정의 홈 디렉토리 존재 여부 또는 권한 기준을 충족하지 못해 조치가 완료되지 않았습니다."
#     fi
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