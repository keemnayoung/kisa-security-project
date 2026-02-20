#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-08
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 관리자 그룹에 최소한의 계정 포함
# @Description : 관리자 그룹(root)에 등록된 불필요한 일반 계정을 제거하여 권한 오남용 방지
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# # 기본 변수
# ID="U-08"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# GROUP_FILE="/etc/group"
# PASSWD_FILE="/etc/passwd"
# TARGET_FILE="$GROUP_FILE,$PASSWD_FILE"

# CHECK_COMMAND="grep -nE '^root:x:0:' /etc/group 2>/dev/null; awk -F: '(\$4==0 && \$1!=\"root\"){print \$1\":\"\$4}' /etc/passwd 2>/dev/null"

# MODIFIED=0
# FAIL_FLAG=0
# DETAIL_CONTENT=""

# REMOVED_USERS_STR=""
# CHANGED_PRIMARY_GID_USERS_STR=""
# NOT_FIXED_PRIMARY_GID_USERS_STR=""

# # 조치 수행(백업 없음)
# if [ -f "$GROUP_FILE" ]; then
#   # 1) /etc/group: root 그룹 보조 멤버(root 제외) 제거
#   ROOT_LINE=$(grep -E '^root:x:0:' "$GROUP_FILE" 2>/dev/null | head -n 1)

#   EXTRA_USERS=$(echo "$ROOT_LINE" \
#     | awk -F: '{print $4}' \
#     | tr ',' '\n' \
#     | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
#     | sed '/^[[:space:]]*$/d' \
#     | grep -v '^root$' \
#     | xargs)

#   if [ -n "$EXTRA_USERS" ]; then
#     for user in $EXTRA_USERS; do
#       if gpasswd -d "$user" root >/dev/null 2>&1; then
#         MODIFIED=1
#         REMOVED_USERS_STR="${REMOVED_USERS_STR}${REMOVED_USERS_STR:+, }$user"
#       else
#         FAIL_FLAG=1
#       fi
#     done
#   fi

#   # /etc/passwd: 주 그룹(GID=0)인 계정(root 제외) 주 그룹 변경
#   if [ -f "$PASSWD_FILE" ]; then
#     PRIMARY_GID0_USERS=$(awk -F: '($4==0 && $1!="root"){print $1}' "$PASSWD_FILE" 2>/dev/null)

#     if [ -n "$PRIMARY_GID0_USERS" ]; then
#       for user in $PRIMARY_GID0_USERS; do
#         # 우선순위: 사용자명과 동일한 그룹이 있으면 그 그룹으로 변경 (일반적 기본 정책)
#         if getent group "$user" >/dev/null 2>&1; then
#           if usermod -g "$user" "$user" >/dev/null 2>&1; then
#             MODIFIED=1
#             CHANGED_PRIMARY_GID_USERS_STR="${CHANGED_PRIMARY_GID_USERS_STR}${CHANGED_PRIMARY_GID_USERS_STR:+, }$user"
#           else
#             FAIL_FLAG=1
#             NOT_FIXED_PRIMARY_GID_USERS_STR="${NOT_FIXED_PRIMARY_GID_USERS_STR}${NOT_FIXED_PRIMARY_GID_USERS_STR:+, }$user"
#           fi
#         else
#           # 동일명 그룹이 없으면 자동 변경은 보수적으로 실패 처리(필수 조치 누락 방지)
#           FAIL_FLAG=1
#           NOT_FIXED_PRIMARY_GID_USERS_STR="${NOT_FIXED_PRIMARY_GID_USERS_STR}${NOT_FIXED_PRIMARY_GID_USERS_STR:+, }$user"
#         fi
#       done
#     fi
#   else
#     FAIL_FLAG=1
#     NOT_FIXED_PRIMARY_GID_USERS_STR="passwd_file_not_found"
#   fi

#   # 조치 후 상태 수집
#   ROOT_LINE_AFTER=$(grep -E '^root:x:0:' "$GROUP_FILE" 2>/dev/null | head -n 1)
#   ROOT_MEMBERS_AFTER=$(echo "$ROOT_LINE_AFTER" | awk -F: '{print $4}')

#   REMAIN_USERS=$(echo "$ROOT_MEMBERS_AFTER" \
#     | tr ',' '\n' \
#     | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
#     | sed '/^[[:space:]]*$/d' \
#     | grep -v '^root$' \
#     | xargs)

#   PRIMARY_GID0_USERS_AFTER=""
#   if [ -f "$PASSWD_FILE" ]; then
#     PRIMARY_GID0_USERS_AFTER=$(awk -F: '($4==0 && $1!="root"){print $1}' "$PASSWD_FILE" 2>/dev/null | xargs)
#   fi

#   DETAIL_CONTENT="root_group_members=$ROOT_MEMBERS_AFTER"

#   if [ -n "$PRIMARY_GID0_USERS_AFTER" ]; then
#     DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"primary_gid0_users=$PRIMARY_GID0_USERS_AFTER"
#   else
#     DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"primary_gid0_users=empty"
#   fi

#   # 성공/실패 판단
#   if [ -z "$REMAIN_USERS" ] && [ -z "$PRIMARY_GID0_USERS_AFTER" ] && [ "$FAIL_FLAG" -eq 0 ]; then
#     IS_SUCCESS=1
#     if [ "$MODIFIED" -eq 1 ]; then
#       REASON_LINE="root 그룹(GID 0)에 포함된 불필요 계정(보조/주 그룹)이 제거 또는 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     else
#       REASON_LINE="root 그룹(GID 0)에 불필요 계정(보조/주 그룹)이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     fi
#   else
#     IS_SUCCESS=0
#     REASON_LINE="조치를 수행했으나 root 그룹 보조 멤버 또는 주 그룹(GID 0) 계정이 남아 있거나 일부 변경에 실패하여 조치가 완료되지 않았습니다."

#     if [ -n "$REMAIN_USERS" ]; then
#       DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"remain_root_group_members=$REMAIN_USERS"
#     fi
#     if [ -n "$PRIMARY_GID0_USERS_AFTER" ]; then
#       DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"remain_primary_gid0_users=$PRIMARY_GID0_USERS_AFTER"
#     fi
#     if [ -n "$NOT_FIXED_PRIMARY_GID_USERS_STR" ]; then
#       DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"primary_gid0_change_failed=$NOT_FIXED_PRIMARY_GID_USERS_STR"
#     fi
#   fi

# else
#   IS_SUCCESS=0
#   REASON_LINE="조치 대상 파일(/etc/group)이 존재하지 않아 조치가 완료되지 않았습니다."
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