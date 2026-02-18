#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-28
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 접속 IP 및 포트 제한
# @Description : 접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

######################
# 검토 필요 (수동 설정)
#####################

# # 기본 변수
# ID="U-28"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE="/etc/hosts.allow
# /etc/hosts.deny"

# FIND_FLAG=0

# CHECK_COMMAND="( [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ] && { grep -nE '^ALL:ALL' /etc/hosts.deny 2>/dev/null; grep -nEv '^[[:space:]]*$|^[[:space:]]*#' /etc/hosts.allow 2>/dev/null; } )
# ( command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null )
# ( command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --list-rich-rules 2>/dev/null )
# ( command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null && ufw status numbered 2>/dev/null )"

# # TCP Wrapper
# TCP_DENY_LINE=""
# TCP_ALLOW_LINES=""
# if [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ]; then
#   TCP_DENY_LINE=$(grep -nE '^ALL:ALL' /etc/hosts.deny 2>/dev/null | head -n 1)
#   TCP_ALLOW_LINES=$(grep -nEv '^[[:space:]]*$|^[[:space:]]*#' /etc/hosts.allow 2>/dev/null)

#   if [ -n "$TCP_DENY_LINE" ] && [ -n "$TCP_ALLOW_LINES" ]; then
#     FIND_FLAG=1
#   fi
# fi

# # iptables
# IPT_LINES=""
# if command -v iptables >/dev/null 2>&1; then
#   IPT_LINES=$(iptables -S INPUT 2>/dev/null | grep -E -- '-A INPUT' | grep -E -- ' -j ACCEPT' | head -n 200)
#   if [ -n "$IPT_LINES" ]; then
#     FIND_FLAG=1
#   fi
# fi

# # firewalld
# FW_RICH=""
# if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
#   FW_RICH=$(firewall-cmd --list-rich-rules 2>/dev/null | sed '/^\s*$/d' | head -n 200)
#   if [ -n "$FW_RICH" ]; then
#     FIND_FLAG=1
#   fi
# fi

# # UFW
# UFW_SUMMARY=""
# UFW_RULES=""
# if command -v ufw >/dev/null 2>&1; then
#   UFW_SUMMARY=$(ufw status 2>/dev/null | head -n 50)
#   if echo "$UFW_SUMMARY" | grep -q "Status: active"; then
#     UFW_RULES=$(ufw status numbered 2>/dev/null | sed '/^\s*$/d' | head -n 200)
#     if echo "$UFW_RULES" | grep -qE '\bALLOW\b'; then
#       FIND_FLAG=1
#     fi
#   fi
# fi

# # detail(조치 후 상태만: 설정값만 출력)
# DETAIL_CONTENT=""

# if [ -n "$TCP_DENY_LINE" ] || [ -n "$TCP_ALLOW_LINES" ]; then
#   DETAIL_CONTENT="${DETAIL_CONTENT}${TCP_DENY_LINE}
# ${TCP_ALLOW_LINES}
# "
# fi

# if [ -n "$IPT_LINES" ]; then
#   DETAIL_CONTENT="${DETAIL_CONTENT}${IPT_LINES}
# "
# fi

# if [ -n "$FW_RICH" ]; then
#   DETAIL_CONTENT="${DETAIL_CONTENT}${FW_RICH}
# "
# fi

# if [ -n "$UFW_SUMMARY" ] || [ -n "$UFW_RULES" ]; then
#   DETAIL_CONTENT="${DETAIL_CONTENT}${UFW_SUMMARY}
# ${UFW_RULES}
# "
# fi

# # 최종 판정
# if [ "$FIND_FLAG" -eq 1 ]; then
#   IS_SUCCESS=1
#   REASON_LINE="접속 IP 및 포트 제한 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
# else
#   IS_SUCCESS=0
#   REASON_LINE="접속 IP 및 포트 제한 설정이 적용되어 있지 않아 조치가 완료되지 않았습니다."
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