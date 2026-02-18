#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-28
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 접속 IP 및 포트 제한
# @Description : 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-28"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE=""
CHECK_COMMAND='[ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ] && (grep -n "^ALL:ALL" /etc/hosts.deny; grep -nEv "^\s*$|^\s*#" /etc/hosts.allow | head); command -v iptables >/dev/null && iptables -L INPUT -n; command -v firewall-cmd >/dev/null && firewall-cmd --state && firewall-cmd --list-rich-rules; command -v ufw >/dev/null && ufw status && ufw status numbered'

DETAIL_CONTENT=""
REASON_LINE=""

FOUND_GOOD="N"

TCPW_OK_LINE=""
IPT_OK_LINE=""
FWD_OK_LINE=""
UFW_OK_LINE=""

TCPW_VULN_DESC=""
IPT_VULN_DESC=""
FWD_VULN_DESC=""
UFW_VULN_DESC=""

GUIDE_LINE="자동 조치 시 방화벽 정책 변경으로 원격 접속(예: SSH) 또는 서비스 통신이 차단되어 장애가 발생할 수 있어 수동 조치가 필요합니다. 
관리자가 직접 확인 후 OS 방화벽 또는 TCP Wrapper에서 허용할 IP와 포트만 접근 가능하도록 정책을 등록해 주시기 바랍니다."

# 현재 설정값 수집용(DETAIL_CONTENT)
TCPW_CUR=""
IPT_CUR=""
FWD_CUR=""
UFW_CUR=""

# TCP Wrapper 점검
if [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ]; then
  TARGET_FILE+="/etc/hosts.allow /etc/hosts.deny "

  TCPW_DENY_ALL=$(grep -n "^ALL:ALL" /etc/hosts.deny 2>/dev/null | head -n 1)
  TCPW_ALLOW_LINES=$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts.allow 2>/dev/null | head -n 20)

  TCPW_CUR+="[TCP Wrapper]\n"
  TCPW_CUR+="hosts.deny:\n${TCPW_DENY_ALL:-ALL:ALL_not_set}\n"
  TCPW_CUR+="hosts.allow(non-comment, top20):\n${TCPW_ALLOW_LINES:-allow_rules_not_found}\n"

  if [ -n "$TCPW_DENY_ALL" ] && [ -n "$TCPW_ALLOW_LINES" ]; then
    FOUND_GOOD="Y"
    TCPW_OK_LINE="$(echo "$TCPW_ALLOW_LINES" | head -n 1)"
  else
    if [ -z "$TCPW_DENY_ALL" ] && [ -z "$TCPW_ALLOW_LINES" ]; then
      TCPW_VULN_DESC="TCP Wrapper에서 hosts.deny의 ALL:ALL 및 hosts.allow 허용 규칙이 확인되지 않습니다"
    elif [ -z "$TCPW_DENY_ALL" ]; then
      TCPW_VULN_DESC="TCP Wrapper에서 hosts.deny의 ALL:ALL 설정이 확인되지 않습니다"
    else
      TCPW_VULN_DESC="TCP Wrapper에서 hosts.allow 허용 규칙이 확인되지 않습니다"
    fi
  fi
else
  TCPW_CUR+="[TCP Wrapper]\n"
  TCPW_CUR+="hosts.allow or hosts.deny: file_not_found\n"

  TCPW_VULN_DESC="TCP Wrapper의 /etc/hosts.allow 또는 /etc/hosts.deny 파일이 없어 전체 접근이 허용될 수 있습니다"
fi

# iptables 점검
if command -v iptables >/dev/null 2>&1; then
  TARGET_FILE+="iptables "

  IPT_INPUT_ALL="$(iptables -L INPUT -n 2>/dev/null | head -n 200)"
  IPT_CUR+="[iptables]\n"
  IPT_CUR+="iptables -L INPUT -n (top200):\n${IPT_INPUT_ALL:-iptables_input_read_failed}\n"

  IPT_OK=$(iptables -L INPUT -n 2>/dev/null | awk '
    /ACCEPT/ && /dpt:/ {
      src=$4;
      if (src != "0.0.0.0/0" && src != "::/0") { print $0; exit }
    }')

  if [ -n "$IPT_OK" ]; then
    FOUND_GOOD="Y"
    IPT_OK_LINE="$IPT_OK"
  else
    IPT_DPT_ANY=$(iptables -L INPUT -n 2>/dev/null | awk '/ACCEPT/ && /dpt:/ { print $0 }' | head -n 1)
    if [ -n "$IPT_DPT_ANY" ]; then
      IPT_VULN_DESC="iptables에서 소스 IP 제한 없이 포트만 허용하는 규칙이 확인됩니다: $(echo "$IPT_DPT_ANY" | tr -d '\n')"
    else
      IPT_VULN_DESC="iptables에서 IP와 포트를 함께 제한하는 허용 규칙이 확인되지 않습니다"
    fi
  fi
else
  IPT_CUR+="[iptables]\nnot_installed_or_not_used\n"
  IPT_VULN_DESC="iptables 명령을 찾을 수 없습니다"
fi

# firewalld 점검
if command -v firewall-cmd >/dev/null 2>&1; then
  TARGET_FILE+="firewalld "

  if firewall-cmd --state >/dev/null 2>&1; then
    FWD_RULES="$(firewall-cmd --list-rich-rules 2>/dev/null)"
    FWD_CUR+="[firewalld]\nstate: active\n"
    FWD_CUR+="rich-rules:\n${FWD_RULES:-no_rich_rules}\n"

    FWD_OK=$(echo "$FWD_RULES" | grep -E 'source address=' | grep -E 'port port=' | head -n 1)
    if [ -n "$FWD_OK" ]; then
      FOUND_GOOD="Y"
      FWD_OK_LINE="$FWD_OK"
    else
      if [ -n "$FWD_RULES" ]; then
        FWD_VULN_DESC="firewalld에서 source address 및 port 조건을 함께 포함한 rich-rule이 확인되지 않습니다"
      else
        FWD_VULN_DESC="firewalld에서 rich-rule이 설정되어 있지 않습니다"
      fi
    fi
  else
    FWD_CUR+="[firewalld]\nstate: inactive\n"
    FWD_VULN_DESC="firewalld가 비활성 상태입니다"
  fi
else
  FWD_CUR+="[firewalld]\nnot_installed_or_not_used\n"
  FWD_VULN_DESC="firewall-cmd 명령을 찾을 수 없습니다"
fi

# UFW 점검
if command -v ufw >/dev/null 2>&1; then
  TARGET_FILE+="ufw "

  UFW_STATUS="$(ufw status 2>/dev/null | head -n 50)"
  UFW_CUR+="[UFW]\nufw status (top50):\n${UFW_STATUS:-ufw_status_read_failed}\n"

  if ufw status 2>/dev/null | grep -q "Status: active"; then
    UFW_OK=$(ufw status numbered 2>/dev/null \
      | grep -E '([0-9]{1,5})/(tcp|udp)' \
      | grep -E 'ALLOW' \
      | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' \
      | head -n 1)

    if [ -n "$UFW_OK" ]; then
      FOUND_GOOD="Y"
      UFW_OK_LINE="$UFW_OK"
    else
      UFW_ALLOW_ANY=$(ufw status numbered 2>/dev/null | grep -E 'ALLOW' | head -n 1)
      if [ -n "$UFW_ALLOW_ANY" ]; then
        UFW_VULN_DESC="UFW에서 IP와 포트를 함께 제한하는 허용 규칙이 확인되지 않습니다: $(echo "$UFW_ALLOW_ANY" | tr -d '\n')"
      else
        UFW_VULN_DESC="UFW에서 허용 규칙이 확인되지 않습니다"
      fi
    fi
  else
    UFW_VULN_DESC="UFW가 비활성 상태입니다"
  fi
else
  UFW_CUR+="[UFW]\nnot_installed_or_not_used\n"
  UFW_VULN_DESC="ufw 명령을 찾을 수 없습니다"
fi

# 최종 판단 및 REASON_LINE/DETAIL_CONTENT 구성
if [ "$FOUND_GOOD" = "Y" ]; then
  STATUS="PASS"

  if [ -n "$TCPW_OK_LINE" ]; then
    REASON_LINE="TCP Wrapper에서 hosts.deny는 ALL:ALL로 차단되고 hosts.allow에 허용 규칙(${TCPW_OK_LINE})이 설정되어 있어 이 항목에 대해 양호합니다."
  elif [ -n "$IPT_OK_LINE" ]; then
    REASON_LINE="iptables INPUT 체인에 소스 IP 제한 및 포트 조건이 포함된 허용 규칙(${IPT_OK_LINE})이 존재하여 이 항목에 대해 양호합니다."
  elif [ -n "$FWD_OK_LINE" ]; then
    REASON_LINE="firewalld rich-rule에 source address 및 port 조건이 포함된 규칙(${FWD_OK_LINE})이 존재하여 이 항목에 대해 양호합니다."
  else
    REASON_LINE="UFW에 IP 및 포트 조건이 포함된 허용 규칙(${UFW_OK_LINE})이 존재하여 이 항목에 대해 양호합니다."
  fi
else
  STATUS="FAIL"

  VULN_REASON=""
  if [ -n "$TCPW_VULN_DESC" ]; then VULN_REASON+="${TCPW_VULN_DESC}\n"; fi
  if [ -n "$IPT_VULN_DESC" ]; then VULN_REASON+="${IPT_VULN_DESC}\n"; fi
  if [ -n "$FWD_VULN_DESC" ]; then VULN_REASON+="${FWD_VULN_DESC}\n"; fi
  if [ -n "$UFW_VULN_DESC" ]; then VULN_REASON+="${UFW_VULN_DESC}\n"; fi
  VULN_REASON="$(printf "%b" "$VULN_REASON" | sed 's/[[:space:]]*$//')"

  # 평가 문장은 1줄(줄바꿈 없음)이어야 하므로, 취약 사유는 ";"로 연결
  VULN_ONE_LINE="$(echo "$VULN_REASON" | tr '\n' ';' | sed 's/;*$//' )"
  REASON_LINE="${VULN_ONE_LINE} 상태로 접속 IP 및 포트 제한이 충분히 적용되지 않아 이 항목에 대해 취약합니다."
fi

# DETAIL_CONTENT는 PASS/FAIL 무관하게 "현재 설정값 전체"를 줄바꿈으로 제공
DETAIL_CONTENT="$(printf "%b\n%b\n%b\n%b" "$TCPW_CUR" "$IPT_CUR" "$FWD_CUR" "$UFW_CUR" | sed 's/[[:space:]]*$//')"

TARGET_FILE="$(echo "$TARGET_FILE" | tr -s ' ' | sed 's/[[:space:]]*$//')"
[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

# raw_evidence 구성 (detail: 1줄 평가 문장 + 다음 줄부터 DETAIL_CONTENT)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
