#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-59
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상 
# @Title : 안전한 SNMP 버전 사용
# @Description : 안전한 SNMP 버전 사용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-59 안전한 SNMP 버전 사용

# # 기본 변수
# ID="U-59"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (command -v systemctl >/dev/null 2>&1 && systemctl is-enabled snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null | grep -nE "^(rouser|rwuser|createUser|com2sec|rocommunity|rwcommunity)\b" || echo "directives_not_found")'

# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE="N/A"

# append_detail(){ DETAIL_CONTENT="${DETAIL_CONTENT:+$DETAIL_CONTENT\n}$1"; }

# json_escape(){ echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'; }

# # root 권한 확인
# if [ "${EUID:-$(id -u)}" -ne 0 ]; then
#   IS_SUCCESS=0
#   REASON_LINE="root 권한이 아니어서 조치가 완료되지 않았습니다."
#   append_detail "run_as_root(after)=required (use sudo)"
# else
#   HAS_SYSTEMCTL=0; command -v systemctl >/dev/null 2>&1 && HAS_SYSTEMCTL=1

#   # SNMP 실행 여부
#   SNMP_ACTIVE="unknown"
#   SNMP_ENABLED="unknown"
#   if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
#     SNMP_ACTIVE="$(systemctl is-active snmpd 2>/dev/null || echo unknown)"
#     SNMP_ENABLED="$(systemctl is-enabled snmpd 2>/dev/null || echo unknown)"
#   fi
#   PROC_LINE="$(pgrep -a -x snmpd 2>/dev/null | head -n 1 || true)"

#   SNMP_RUNNING=0
#   [ "$SNMP_ACTIVE" = "active" ] && SNMP_RUNNING=1
#   [ -n "$PROC_LINE" ] && SNMP_RUNNING=1

#   # conf 선택
#   CONF=""
#   [ -f /etc/snmp/snmpd.conf ] && CONF="/etc/snmp/snmpd.conf"
#   [ -z "$CONF" ] && [ -f /usr/share/snmp/snmpd.conf ] && CONF="/usr/share/snmp/snmpd.conf"
#   [ -n "$CONF" ] && TARGET_FILE="$CONF"

#   # 1) SNMP 미사용이면: 중지/비활성화 보장(가능한 경우) 후 성공
#   if [ "$SNMP_RUNNING" -eq 0 ]; then
#     if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
#       systemctl stop snmpd >/dev/null 2>&1 || true
#       systemctl disable snmpd >/dev/null 2>&1 || true
#       SNMP_ACTIVE="$(systemctl is-active snmpd 2>/dev/null || echo unknown)"
#       SNMP_ENABLED="$(systemctl is-enabled snmpd 2>/dev/null || echo unknown)"
#     fi
#     PROC_LINE="$(pgrep -a -x snmpd 2>/dev/null | head -n 1 || true)"

#     IS_SUCCESS=1
#     REASON_LINE="SNMP(snmpd) 서비스가 비활성화 상태로 확인되어 변경 없이도 조치가 완료되었습니다."
#     append_detail "[systemd] snmpd_active(after)=$SNMP_ACTIVE snmpd_enabled(after)=$SNMP_ENABLED"
#     append_detail "[process] ${PROC_LINE:-snmpd_not_running(after)}"

#   else
#     # 2) 실행 중인데 conf 없으면 조치 불가
#     if [ -z "$CONF" ]; then
#       IS_SUCCESS=0
#       REASON_LINE="SNMP(snmpd) 서비스가 실행 중이나 snmpd.conf 파일을 찾지 못해 조치가 완료되지 않았습니다."
#       append_detail "[systemd] snmpd_active(after)=$SNMP_ACTIVE snmpd_enabled(after)=$SNMP_ENABLED"
#       append_detail "[process] ${PROC_LINE:-snmpd_running_unknown(after)}"
#       append_detail "snmp_conf_file(after)=not_found"

#     else
#       # conf 유효 라인에서 v3 / v1v2 흔적 확인
#       EFFECTIVE="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$CONF" 2>/dev/null || true)"
#       echo "$EFFECTIVE" | grep -qE '^(rouser|rwuser|createUser)\b' && V3_PRESENT=1 || V3_PRESENT=0
#       echo "$EFFECTIVE" | grep -qE '^(rocommunity|rwcommunity|com2sec)\b' && V12_PRESENT=1 || V12_PRESENT=0

#       # 2-1) v3가 있고 v1/v2c가 있으면: v1/v2c만 주석 처리
#       if [ "$V3_PRESENT" -eq 1 ] && [ "$V12_PRESENT" -eq 1 ]; then
#         cp -p "$CONF" "${CONF}.bak_u59_$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
#         sed -i 's/^[[:space:]]*\(rocommunity\|rwcommunity\|com2sec\)\b/# \1/gI' "$CONF" 2>/dev/null || true
#         if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
#           systemctl restart snmpd >/dev/null 2>&1 || true
#           SNMP_ACTIVE="$(systemctl is-active snmpd 2>/dev/null || echo unknown)"
#           SNMP_ENABLED="$(systemctl is-enabled snmpd 2>/dev/null || echo unknown)"
#         fi
#       fi

#       # 2-2) v3가 없으면: 기본은 실패(암호 필요로 자동 생성 불가)
#       #       단, FORCE_DISABLE_SNMP=1 이면 중지/비활성화로 조치
#       if [ "$V3_PRESENT" -eq 0 ] && [ "${FORCE_DISABLE_SNMP:-0}" = "1" ] && [ "$HAS_SYSTEMCTL" -eq 1 ]; then
#         systemctl stop snmpd >/dev/null 2>&1 || true
#         systemctl disable snmpd >/dev/null 2>&1 || true
#         SNMP_ACTIVE="$(systemctl is-active snmpd 2>/dev/null || echo unknown)"
#         SNMP_ENABLED="$(systemctl is-enabled snmpd 2>/dev/null || echo unknown)"
#       fi

#       # 조치 후 재검증
#       EFFECTIVE2="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$CONF" 2>/dev/null || true)"
#       echo "$EFFECTIVE2" | grep -qE '^(rouser|rwuser|createUser)\b' && V3_AFTER=1 || V3_AFTER=0
#       echo "$EFFECTIVE2" | grep -qE '^(rocommunity|rwcommunity|com2sec)\b' && V12_AFTER=1 || V12_AFTER=0
#       PROC_LINE="$(pgrep -a -x snmpd 2>/dev/null | head -n 1 || true)"

#       append_detail "snmp_conf_file(after)=$CONF"
#       append_detail "snmpv3_directives_present(after)=$([ "$V3_AFTER" -eq 1 ] && echo yes || echo no)"
#       append_detail "snmpv1v2_directives_present(after)=$([ "$V12_AFTER" -eq 1 ] && echo yes || echo no)"
#       append_detail "[systemd] snmpd_active(after)=$SNMP_ACTIVE snmpd_enabled(after)=$SNMP_ENABLED"
#       append_detail "[process] ${PROC_LINE:-snmpd_not_running(after)}"

#       # 최종 판정
#       if [ "$SNMP_ACTIVE" != "active" ] && [ -z "$PROC_LINE" ]; then
#         IS_SUCCESS=1
#         REASON_LINE="SNMP(snmpd) 서비스를 중지/비활성화하여 조치가 완료되었습니다."
#       elif [ "$V3_AFTER" -eq 1 ] && [ "$V12_AFTER" -eq 0 ]; then
#         IS_SUCCESS=1
#         REASON_LINE="SNMPv3만 사용하도록 구성되어 조치가 완료되었습니다."
#       else
#         IS_SUCCESS=0
#         if [ "$V3_AFTER" -eq 0 ]; then
#           REASON_LINE="SNMP(snmpd)가 실행 중이며 SNMPv3 설정이 확인되지 않아 조치가 완료되지 않았습니다. 조치: SNMPv3 사용자(createUser) 및 권한(rouser/rwuser)을 구성하고, v1/v2c(rocommunity/rwcommunity/com2sec)는 제거(주석/삭제)하세요."
#         else
#           REASON_LINE="SNMPv3 설정은 있으나 SNMPv1/v2c 설정이 남아 있어 조치가 완료되지 않았습니다. 조치: v1/v2c(rocommunity/rwcommunity/com2sec) 라인을 제거(주석/삭제)하고 snmpd를 재기동하세요."
#         fi
#       fi
#     fi
#   fi
# fi

# [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

# echo ""
# cat <<EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF