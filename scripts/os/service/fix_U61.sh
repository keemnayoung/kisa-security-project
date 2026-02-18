#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-61
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : SNMP Access Control 설정
# @Description : SNMP 접근 제어 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-61 SNMP Access Control 설정

# # 기본 변수
# ID="U-61"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# # 기본값은 가장 안전한 로컬 제한(필요 시 환경변수로 변경)
# ALLOW_NET="${ALLOW_NET:-127.0.0.1}"
# ALLOW_NET_V6="${ALLOW_NET_V6:-::1}"

# CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (ls -l /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || true); (grep -inE "^[[:space:]]*(com2sec|rocommunity|rwcommunity|agentAddress|rouser|rwuser|createUser)\b" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "snmpd_conf_not_found_or_no_directives")'

# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE="N/A"

# append_detail(){ DETAIL_CONTENT="${DETAIL_CONTENT:+$DETAIL_CONTENT\n}$1"; }

# # root 권한 확인
# if [ "${EUID:-$(id -u)}" -ne 0 ]; then
#   REASON_LINE="root 권한이 아니어서 SNMP 설정 점검/조치를 수행할 수 없어 조치가 완료되지 않았습니다."
#   append_detail "guide(after)=sudo로 실행해야 합니다."
# else
#   HAS_SYSTEMCTL=0; command -v systemctl >/dev/null 2>&1 && HAS_SYSTEMCTL=1
#   SNMP_ACTIVE=0; SNMP_PROC=0
#   [ "$HAS_SYSTEMCTL" -eq 1 ] && systemctl is-active --quiet snmpd 2>/dev/null && SNMP_ACTIVE=1
#   pgrep -x snmpd >/dev/null 2>&1 && SNMP_PROC=1

#   # SNMP 미사용이면 조치 대상 없음
#   if [ "$SNMP_ACTIVE" -eq 0 ] && [ "$SNMP_PROC" -eq 0 ]; then
#     IS_SUCCESS=1
#     REASON_LINE="SNMP(snmpd) 서비스가 비활성화되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     append_detail "snmpd_service_active(after)=inactive_or_not_running"
#     append_detail "snmpd_process(after)=not_running"
#   else
#     # 설정 파일 선택(우선 /etc)
#     CONF="/etc/snmp/snmpd.conf"
#     [ -f "$CONF" ] || CONF="/usr/share/snmp/snmpd.conf"
#     if [ ! -f "$CONF" ]; then
#       REASON_LINE="SNMP(snmpd) 서비스가 실행 중이나 snmpd.conf 파일을 찾지 못해 조치가 완료되지 않았습니다."
#       append_detail "snmp_conf_file(after)=not_found"
#     else
#       TARGET_FILE="$CONF"
#       BK="${CONF}.bak_$(date +%Y%m%d_%H%M%S)"
#       cp -a "$CONF" "$BK" 2>/dev/null || true

#       # 조치: 광범위/누락 source를 로컬로 제한
#       # - com2sec: source가 default/전체대역이면 127.0.0.1로
#       sed -i -E \
#         "s/^([[:space:]]*com2sec[[:space:]]+[^#[:space:]]+[[:space:]]+)(default|0\.0\.0\.0(\/0)?|::(\/0)?)([[:space:]]+)/\1${ALLOW_NET}\4/" \
#         "$CONF" 2>/dev/null || true

#       # - rocommunity/rwcommunity: source 없으면 추가, 광범위면 교체(IPv4/IPv6)
#       sed -i -E \
#         "s/^([[:space:]]*(rocommunity|rwcommunity)[[:space:]]+[^#[:space:]]+)[[:space:]]*$/\1 ${ALLOW_NET}/" \
#         "$CONF" 2>/dev/null || true
#       sed -i -E \
#         "s/^([[:space:]]*(rocommunity|rwcommunity)[[:space:]]+[^#[:space:]]+[[:space:]]+)(default|0\.0\.0\.0(\/0)?)([[:space:]]*|$)/\1${ALLOW_NET}\5/" \
#         "$CONF" 2>/dev/null || true
#       sed -i -E \
#         "s/^([[:space:]]*(rocommunity|rwcommunity)[[:space:]]+[^#[:space:]]+[[:space:]]+)(::(\/0)?)([[:space:]]*|$)/\1${ALLOW_NET_V6}\4/" \
#         "$CONF" 2>/dev/null || true

#       # 조치 후 상태 수집(after만)
#       append_detail "snmp_conf_file(after)=$CONF"
#       COM2SEC_AFTER="$(grep -inE '^[[:space:]]*com2sec[[:space:]]+' "$CONF" 2>/dev/null | head -n 10 | tr '\n' '|' )"
#       RO_RW_AFTER="$(grep -inE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+' "$CONF" 2>/dev/null | head -n 10 | tr '\n' '|' )"
#       [ -n "$COM2SEC_AFTER" ] && append_detail "com2sec_lines(after)=${COM2SEC_AFTER%|}" || append_detail "com2sec_lines(after)=not_found"
#       [ -n "$RO_RW_AFTER" ] && append_detail "ro_rwcommunity_lines(after)=${RO_RW_AFTER%|}" || append_detail "ro_rwcommunity_lines(after)=not_found"

#       # 최종 검증: 취약 패턴 잔존 여부
#       CLEAN="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$CONF" 2>/dev/null || true)"
#       VULN_LEFT=0
#       echo "$CLEAN" | grep -qE '^[[:space:]]*com2sec[[:space:]]+[^#[:space:]]+[[:space:]]+(default|0\.0\.0\.0(\/0)?|::(\/0)?)([[:space:]]|$)' && VULN_LEFT=1
#       echo "$CLEAN" | grep -qE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+[^#[:space:]]+[[:space:]]*$' && VULN_LEFT=1
#       echo "$CLEAN" | grep -qE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+[^#[:space:]]+[[:space:]]+(default|0\.0\.0\.0(\/0)?|::(\/0)?)([[:space:]]|$)' && VULN_LEFT=1

#       # 재시작(실행 중일 때만)
#       if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
#         systemctl is-active --quiet snmpd 2>/dev/null && {
#           systemctl restart snmpd >/dev/null 2>&1 && append_detail "snmpd_restart(after)=success" || append_detail "snmpd_restart(after)=failed"
#         }
#         systemctl is-active --quiet snmpd 2>/dev/null && append_detail "snmpd_service_active(after)=active" || append_detail "snmpd_service_active(after)=inactive"
#       else
#         append_detail "snmpd_service_active(after)=systemctl_not_found"
#       fi
#       pgrep -x snmpd >/dev/null 2>&1 && append_detail "snmpd_process(after)=running" || append_detail "snmpd_process(after)=not_running"

#       # 결과
#       if echo "$DETAIL_CONTENT" | grep -q 'snmpd_restart(after)=failed'; then
#         IS_SUCCESS=0
#         REASON_LINE="SNMP 설정을 변경했으나 snmpd 서비스 재시작에 실패하여 조치가 완료되지 않았습니다."
#         append_detail "guide(after)=snmpd.conf 구문/권한을 확인 후 systemctl restart snmpd 를 수동 수행해야 합니다."
#       elif [ "$VULN_LEFT" -eq 1 ]; then
#         IS_SUCCESS=0
#         REASON_LINE="SNMP 접근 제어 설정을 로컬로 제한하려 했으나 취약 패턴이 남아 있어 조치가 완료되지 않았습니다."
#         append_detail "guide(after)=snmpd.conf에서 com2sec/rocommunity/rwcommunity의 허용 네트워크(source)를 ${ALLOW_NET} 등으로 제한했는지 확인해야 합니다."
#       else
#         IS_SUCCESS=1
#         REASON_LINE="SNMP 접근 제어 설정의 허용 네트워크(source)가 로컬(${ALLOW_NET})로 제한되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#       fi
#     fi
#   fi
# fi

# # raw_evidence 구성 (after만 포함)
# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# # escape 처리(백슬래시/따옴표/줄바꿈)
# RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

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