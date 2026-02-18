#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로그램
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-60
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String 복잡성 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-60 SNMP Community String 복잡성 설정


# # 기본 변수
# ID="U-60"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (ls -l /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf /var/lib/net-snmp/snmpd.conf 2>/dev/null || true); (grep -inE "^[[:space:]]*(rocommunity|rwcommunity|com2sec|createUser)\b" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf /var/lib/net-snmp/snmpd.conf 2>/dev/null || echo "snmp_directives_not_found")'

# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# append_detail(){ DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }

# # 토큰 마스킹(현재 설정 노출 최소화)
# mask_token(){ local s="$1" n="${#s}"; [ "$n" -le 3 ] && echo "***" || echo "${s:0:2}***${s: -2}"; }

# # 가이드 취약 기준: public/private OR (len<8) OR (alnum-only && len<10)
# is_weak(){
#   local s="${1:-}" low
#   low="$(echo "$s" | tr '[:upper:]' '[:lower:]')"
#   [[ "$low" =~ ^(public|private)$ ]] && return 0
#   [ "${#s}" -lt 8 ] && return 0
#   echo "$s" | grep -qE '^[A-Za-z0-9]+$' && [ "${#s}" -lt 10 ] && return 0
#   return 1
# }

# # root 권한 확인
# if [ "${EUID:-$(id -u)}" -ne 0 ]; then
#   IS_SUCCESS=0
#   REASON_LINE="root 권한이 아니어서 SNMP 설정 점검/조치를 수행할 수 없어 조치가 완료되지 않았습니다."
#   DETAIL_CONTENT="sudo로 실행해야 합니다."
# else
#   # SNMP 실행 여부(서비스/프로세스 중 하나라도 보이면 '사용 중'으로 간주)
#   ACTIVE="unknown"
#   if command -v systemctl >/dev/null 2>&1; then
#     systemctl is-active --quiet snmpd 2>/dev/null && ACTIVE="active" || ACTIVE="inactive"
#   fi
#   pgrep -x snmpd >/dev/null 2>&1 && PROC="running" || PROC="not_running"
#   append_detail "snmpd_service_active(after)=$ACTIVE"
#   append_detail "snmpd_process(after)=$PROC"

#   if [ "$ACTIVE" != "active" ] && [ "$PROC" != "running" ]; then
#     IS_SUCCESS=1
#     REASON_LINE="SNMP(snmpd) 서비스가 비활성화되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     append_detail "snmp_conf_checked(after)=not_applicable"
#     TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf, /var/lib/net-snmp/snmpd.conf"
#   else
#     # 점검 대상 파일(존재하는 것만)
#     FILES=()
#     for f in /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf /var/lib/net-snmp/snmpd.conf; do
#       [ -f "$f" ] && FILES+=("$f")
#     done

#     if [ "${#FILES[@]}" -eq 0 ]; then
#       IS_SUCCESS=0
#       REASON_LINE="SNMP(snmpd) 서비스가 실행 중이나 설정 파일을 찾지 못해 조치가 완료되지 않았습니다."
#       append_detail "snmp_conf_file(after)=not_found"
#       TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf, /var/lib/net-snmp/snmpd.conf"
#     else
#       TARGET_FILE="$(printf "%s, " "${FILES[@]}")"; TARGET_FILE="${TARGET_FILE%, }"

#       WEAK_FOUND=0
#       FOUND_V12=0
#       FOUND_V3=0

#       for conf in "${FILES[@]}"; do
#         # 주석/공백 제외 후 관심 지시자만
#         LINES="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$conf" 2>/dev/null | grep -E '^[[:space:]]*(com2sec|rocommunity|rwcommunity|createUser)\b' || true)"
#         [ -z "$LINES" ] && append_detail "snmp_conf($conf)(after)=no_relevant_directives" && continue
#         append_detail "snmp_conf($conf)(after)=relevant_directives_found"

#         while IFS= read -r line; do
#           key="$(echo "$line" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"

#           # v1/v2c community
#           if [[ "$key" =~ ^(com2sec|rocommunity|rwcommunity)$ ]]; then
#             FOUND_V12=1
#             [ "$key" = "com2sec" ] && tok="$(echo "$line" | awk '{print $4}')" || tok="$(echo "$line" | awk '{print $2}')"
#             [ -z "${tok:-}" ] && append_detail "parse($conf)(after)=$key token=NOT_PARSED" && continue
#             if is_weak "$tok"; then
#               WEAK_FOUND=1
#               append_detail "check($conf)(after)=$key token=WEAK($(mask_token "$tok"))"
#             else
#               append_detail "check($conf)(after)=$key token=OK($(mask_token "$tok"))"
#             fi

#           # v3 createUser (authpass/privpass)
#           elif [ "$key" = "createuser" ]; then
#             FOUND_V3=1
#             authpass="$(echo "$line" | awk '{print $4}')"
#             privpass="$(echo "$line" | awk '{print $6}')"

#             if [ -n "${authpass:-}" ]; then
#               if is_weak "$authpass"; then
#                 WEAK_FOUND=1
#                 append_detail "check($conf)(after)=createUser authpass=WEAK($(mask_token "$authpass"))"
#               else
#                 append_detail "check($conf)(after)=createUser authpass=OK($(mask_token "$authpass"))"
#               fi
#             else
#               append_detail "parse($conf)(after)=createUser authpass=NOT_FOUND"
#             fi

#             if [ -n "${privpass:-}" ]; then
#               if is_weak "$privpass"; then
#                 WEAK_FOUND=1
#                 append_detail "check($conf)(after)=createUser privpass=WEAK($(mask_token "$privpass"))"
#               else
#                 append_detail "check($conf)(after)=createUser privpass=OK($(mask_token "$privpass"))"
#               fi
#             fi
#           fi
#         done <<< "$LINES"
#       done

#       if [ "$FOUND_V12" -eq 0 ] && [ "$FOUND_V3" -eq 0 ]; then
#         IS_SUCCESS=0
#         REASON_LINE="SNMP(snmpd) 서비스가 실행 중이나 Community String 또는 SNMPv3(createUser) 설정을 확인할 수 없어 조치가 완료되지 않았습니다."
#         append_detail "manual_guide(after)=snmpd.conf 및 /var/lib/net-snmp/snmpd.conf에서 설정(include 포함) 경로를 확인 후, 인증정보가 기준을 충족하도록 설정하고 snmpd 재시작"
#       elif [ "$WEAK_FOUND" -eq 1 ]; then
#         IS_SUCCESS=0
#         REASON_LINE="SNMP 인증정보(Community String 또는 SNMPv3 인증 비밀번호)가 단순/기본값으로 확인되어 조치가 완료되지 않았습니다. 정책에 맞게 수동 변경이 필요합니다."
#         append_detail "manual_guide(after)=public/private 제거, (영문+숫자 10자 이상) 또는 (영문/숫자/특수문자 포함 8자 이상)으로 변경 후 systemctl restart snmpd"
#       else
#         IS_SUCCESS=1
#         REASON_LINE="SNMP 인증정보(Community String 또는 SNMPv3 인증 비밀번호)가 복잡성 기준을 충족하도록 설정되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#       fi
#     fi
#   fi
# fi

# # raw_evidence 구성 (조치 후/현재 상태만)
# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n${DETAIL_CONTENT:-none}",
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