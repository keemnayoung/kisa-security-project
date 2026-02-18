#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-17
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : 시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# # 기본 변수
# ID="U-17"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# MODIFIED=0
# FAIL_FLAG=0

# # 조치 대상 수집
# INIT_FILES=""
# SYSTEMD_FILES=""

# if [ -d /etc/rc.d ]; then
#   INIT_FILES=$(readlink -f /etc/rc.d/*/* 2>/dev/null | sed 's/$/*/')
# fi

# if [ -d /etc/systemd/system ]; then
#   SYSTEMD_FILES=$(readlink -f /etc/systemd/system/* 2>/dev/null | sed 's/$/*/')
# fi

# ALL_FILES=$(echo -e "$INIT_FILES\n$SYSTEMD_FILES" | sed '/^\s*$/d' | sort -u)

# # 확인 명령어(command) 및 target_file 구성
# CHECK_COMMAND="for f in \$(readlink -f /etc/rc.d/*/* 2>/dev/null; readlink -f /etc/systemd/system/* 2>/dev/null); do [ -e \"\$f\" ] && stat -c '%U %A %n' \"\$f\"; done"
# TARGET_FILE=$(printf "%s\n" $ALL_FILES)

# # 조치 수행
# if [ -z "$ALL_FILES" ]; then
#   IS_SUCCESS=0
#   TARGET_FILE="/etc/rc.d/*/*\n/etc/systemd/system/*"
#   REASON_LINE="시스템 시작 스크립트 파일이 존재하지 않아 조치가 완료되지 않았습니다."
#   DETAIL_CONTENT=""
# else
#   for FILE in $ALL_FILES; do
#     [ -e "$FILE" ] || continue

#     OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
#     PERM=$(stat -c "%A" "$FILE" 2>/dev/null)

#     if [ "$OWNER" != "root" ]; then
#       chown root:root "$FILE" 2>/dev/null
#       MODIFIED=1
#     fi

#     if [ "$(echo "$PERM" | cut -c9)" = "w" ]; then
#       chmod o-w "$FILE" 2>/dev/null
#       MODIFIED=1
#     fi
#   done

#   # 조치 후 재검증
#   DETAIL_CONTENT=""
#   for FILE in $ALL_FILES; do
#     [ -e "$FILE" ] || continue

#     AFTER_OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
#     AFTER_PERM=$(stat -c "%A" "$FILE" 2>/dev/null)

#     DETAIL_CONTENT="${DETAIL_CONTENT}${AFTER_OWNER} ${AFTER_PERM} ${FILE}
# "

#     if [ "$AFTER_OWNER" != "root" ] || [ "$(echo "$AFTER_PERM" | cut -c9)" = "w" ]; then
#       FAIL_FLAG=1
#     fi
#   done

#   if [ "$FAIL_FLAG" -eq 0 ]; then
#     IS_SUCCESS=1
#     if [ "$MODIFIED" -eq 1 ]; then
#       REASON_LINE="시스템 시작 스크립트 파일의 소유자가 root로 설정되고 other 쓰기 권한이 제거되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     else
#       REASON_LINE="시스템 시작 스크립트 파일의 소유자가 root이고 other 쓰기 권한이 제거된 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     fi
#   else
#     IS_SUCCESS=0
#     REASON_LINE="일부 시스템 시작 스크립트 파일에서 소유자 또는 other 쓰기 권한 기준을 충족하지 못해 조치가 완료되지 않았습니다."
#   fi
# fi

# # raw_evidence 구성
# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE
# $DETAIL_CONTENT",
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