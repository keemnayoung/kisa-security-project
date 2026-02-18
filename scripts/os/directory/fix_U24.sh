#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-24
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# @Description : 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한 부여
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# # 기본 변수
# ID="U-24"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# ENV_FILES=(
#   ".profile"
#   ".bashrc"
#   ".bash_profile"
#   ".kshrc"
#   ".cshrc"
#   ".login"
#   ".exrc"
#   ".netrc"
# )

# CHECK_COMMAND="while IFS=: read -r u _ _ _ _ h _; do [ -d \"\$h\" ] || continue; for f in .profile .bashrc .bash_profile .kshrc .cshrc .login .exrc .netrc; do p=\"\$h/\$f\"; [ -f \"\$p\" ] && stat -c '%U %G %a %n' \"\$p\"; done; done < /etc/passwd 2>/dev/null"

# ACTION_TARGET_FOUND=false
# FAIL_FLAG=0
# MODIFIED=0
# DETAIL_CONTENT=""
# TARGET_FILE=""

# # 조치 수행
# while IFS=: read -r USER _ UID _ _ HOME_DIR _; do
#   [ -d "$HOME_DIR" ] || continue

#   for ENV_FILE in "${ENV_FILES[@]}"; do
#     FILE_PATH="$HOME_DIR/$ENV_FILE"
#     [ -f "$FILE_PATH" ] || continue

#     ACTION_TARGET_FOUND=true
#     TARGET_FILE="${TARGET_FILE}${FILE_PATH}
# "

#     OWNER_BEFORE=$(stat -c "%U" "$FILE_PATH" 2>/dev/null)
#     PERM_BEFORE=$(stat -c "%A" "$FILE_PATH" 2>/dev/null)

#     if [[ "$OWNER_BEFORE" != "root" && "$OWNER_BEFORE" != "$USER" ]]; then
#       chown "$USER" "$FILE_PATH" 2>/dev/null
#       MODIFIED=1
#     fi

#     if [[ "${PERM_BEFORE:5:1}" == "w" || "${PERM_BEFORE:8:1}" == "w" ]]; then
#       chmod go-w "$FILE_PATH" 2>/dev/null
#       MODIFIED=1
#     fi
#   done
# done < /etc/passwd

# # 조치 후 상태 수집(조치 후 상태만 detail에 표시)
# if [ "$ACTION_TARGET_FOUND" = true ]; then
#   while IFS=: read -r USER _ UID _ _ HOME_DIR _; do
#     [ -d "$HOME_DIR" ] || continue

#     for ENV_FILE in "${ENV_FILES[@]}"; do
#       FILE_PATH="$HOME_DIR/$ENV_FILE"
#       [ -f "$FILE_PATH" ] || continue

#       AFTER_OWNER=$(stat -c "%U" "$FILE_PATH" 2>/dev/null)
#       AFTER_PERM=$(stat -c "%A" "$FILE_PATH" 2>/dev/null)

#       DETAIL_CONTENT="${DETAIL_CONTENT}owner=$AFTER_OWNER
# perm=$AFTER_PERM
# file=$FILE_PATH

# "

#       if [[ "$AFTER_OWNER" != "root" && "$AFTER_OWNER" != "$USER" ]] \
#         || [[ "${AFTER_PERM:5:1}" == "w" || "${AFTER_PERM:8:1}" == "w" ]]; then
#         FAIL_FLAG=1
#       fi
#     done
#   done < /etc/passwd
# fi

# # 최종 판정
# if [ "$ACTION_TARGET_FOUND" = false ]; then
#   IS_SUCCESS=1
#   REASON_LINE="조치 대상 환경변수 파일이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   DETAIL_CONTENT=""
#   TARGET_FILE=""
# else
#   if [ "$FAIL_FLAG" -eq 0 ]; then
#     IS_SUCCESS=1
#     if [ "$MODIFIED" -eq 1 ]; then
#       REASON_LINE="환경변수 파일의 소유자가 root 또는 해당 계정으로 설정되고 group/other 쓰기 권한이 제거되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     else
#       REASON_LINE="환경변수 파일의 소유자가 root 또는 해당 계정으로 유지되고 group/other 쓰기 권한이 제거된 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     fi
#   else
#     IS_SUCCESS=0
#     REASON_LINE="조치를 수행했으나 일부 환경변수 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
#   fi
# fi

# # target_file이 비어있는 경우 대비
# TARGET_FILE=${TARGET_FILE%$'\n'}

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