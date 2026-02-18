#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-61
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : SNMP Access Control 설정
# @Description : SNMP 접근 제어 설정 여부 점검
# @Criteria_Good : SNMP 서비스에 접근 제어 설정이 되어 있는 경우
# @Criteria_Bad : SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-61"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (command -v systemctl >/dev/null 2>&1 && systemctl is-enabled snmpd 2>/dev/null || true); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (grep -nE "^[[:space:]]*(agentAddress|com2sec|rocommunity|rwcommunity|rouser|rwuser|createUser)\b" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "snmpd_conf_not_found_or_no_directives")'

GUIDE_LINE="이 항목에 대해서 자동 조치 시 허용 네트워크/호스트를 잘못 제한하면 모니터링 장애가 발생하거나 반대로 과도한 허용으로 정보 노출 위험이 커질 수 있어 수동 조치가 필요합니다.
관리자가 직접 운영 정책(관리망/허용 대상)을 확인 후 /etc/snmp/snmpd.conf의 com2sec 또는 rocommunity/rwcommunity에 허용 네트워크(source)를 명시하고 snmpd를 재시작해 주시기 바랍니다."

append_detail() { DETAIL_CONTENT="${DETAIL_CONTENT:+$DETAIL_CONTENT\n}$1"; }

# SNMP 실행 여부 판단 분기
SNMP_RUNNING=0
ACTIVE="N"; ENABLED="N"; PROC="N"

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet snmpd 2>/dev/null; then ACTIVE="Y"; SNMP_RUNNING=1; fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet snmpd 2>/dev/null; then ENABLED="Y"; fi
if pgrep -x snmpd >/dev/null 2>&1; then PROC="Y"; SNMP_RUNNING=1; fi

append_detail "[systemd] snmpd_active=${ACTIVE} snmpd_enabled=${ENABLED}"
append_detail "[process] snmpd_running=${PROC}"

REASON_OK=""
REASON_BAD=""

# SNMP 미사용 분기(PASS)
if [ "$SNMP_RUNNING" -eq 0 ]; then
  STATUS="PASS"
  REASON_OK="systemd/프로세스 기준 snmpd_active=${ACTIVE}, snmpd_running=${PROC}로 비활성화되어"
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"
else
  # 설정 파일 확인 분기
  CONF_FILES=(/etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf)
  FOUND=0

  VULN=0
  OK_HINT=0

  # 설정값 기반 이유(양호/취약) 생성용
  OK_ITEMS=""
  BAD_ITEMS=""

  add_ok(){ OK_ITEMS="${OK_ITEMS:+$OK_ITEMS; }$1"; }
  add_bad(){ BAD_ITEMS="${BAD_ITEMS:+$BAD_ITEMS; }$1"; VULN=1; }

  for f in "${CONF_FILES[@]}"; do
    [ -f "$f" ] || continue
    FOUND=1
    TARGET_FILE="${TARGET_FILE:+$TARGET_FILE, }$f"

    CLEAN="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null || true)"

    # 현재 설정값(라인)만 DETAIL_CONTENT에 기록
    LINES="$(echo "$CLEAN" | grep -nE '^[[:space:]]*(agentAddress|com2sec|rocommunity|rwcommunity|rouser|rwuser|createUser)\b' 2>/dev/null || true)"
    if [ -n "$LINES" ]; then
      append_detail "[conf:$f]"
      while IFS= read -r line; do
        append_detail "$line"
      done <<< "$LINES"
    else
      append_detail "[conf:$f] (no_directives_found)"
    fi

    # agentAddress 광범위 리슨 여부(취약 근거는 설정값으로만)
    AG="$(echo "$CLEAN" | grep -E '^[[:space:]]*agentAddress\b' || true)"
    if [ -n "$AG" ]; then
      if echo "$AG" | grep -qE '0\.0\.0\.0|::|udp:161|udp6:161'; then
        add_bad "agentAddress=${AG#agentAddress }"
      else
        add_ok "agentAddress=${AG#agentAddress }"
        OK_HINT=1
      fi
    fi

    # com2sec source 점검
    C2="$(echo "$CLEAN" | grep -E '^[[:space:]]*com2sec\b' || true)"
    if [ -n "$C2" ]; then
      OK_HINT=1
      while IFS= read -r line; do
        src="$(echo "$line" | awk '{print $3}')"
        comm="$(echo "$line" | awk '{print $4}')"
        if echo "$src" | grep -qE '^(default|0\.0\.0\.0(/0)?|::(/0)?)$'; then
          add_bad "com2sec_source=${src} community=${comm}"
        else
          add_ok "com2sec_source=${src}"
        fi
      done <<< "$C2"
    fi

    # rocommunity/rwcommunity source 점검
    CR="$(echo "$CLEAN" | grep -E '^[[:space:]]*(rocommunity|rwcommunity)\b' || true)"
    if [ -n "$CR" ]; then
      OK_HINT=1
      while IFS= read -r line; do
        kind="$(echo "$line" | awk '{print $1}')"
        comm="$(echo "$line" | awk '{print $2}')"
        src="$(echo "$line" | awk '{print $3}')"
        nf="$(echo "$line" | awk '{print NF}')"
        if [ -z "$nf" ] || [ "$nf" -le 2 ]; then
          add_bad "${kind}=${comm} source=NOT_SET"
        else
          if echo "$src" | grep -qE '^(default|0\.0\.0\.0(/0)?|::(/0)?)$'; then
            add_bad "${kind}=${comm} source=${src}"
          else
            add_ok "${kind}=${comm} source=${src}"
          fi
        fi
      done <<< "$CR"
    fi

    # SNMPv3 사용자(양호 힌트)
    V3="$(echo "$CLEAN" | grep -E '^[[:space:]]*(rouser|rwuser|createUser)\b' || true)"
    if [ -n "$V3" ]; then
      OK_HINT=1
      add_ok "snmpv3_user=FOUND"
    fi
  done

  # 설정 파일을 확인할 수 없는 분기(FAIL)
  if [ "$FOUND" -eq 0 ]; then
    STATUS="FAIL"
    REASON_BAD="snmpd_active=${ACTIVE}, snmpd_running=${PROC}인데 snmpd.conf를 확인할 수 없어"
    append_detail "[conf] /etc/snmp/snmpd.conf,/usr/share/snmp/snmpd.conf=NOT_FOUND"
  else
    # 접근 제어 힌트 자체가 없으면 FAIL
    if [ "$OK_HINT" -eq 0 ]; then
      STATUS="FAIL"
      VULN=1
      BAD_ITEMS="${BAD_ITEMS:+$BAD_ITEMS; }access_control_directives=NOT_FOUND"
    fi

    if [ "$VULN" -eq 1 ]; then
      STATUS="FAIL"
      REASON_BAD="${BAD_ITEMS:-접근 제어 설정이 미흡하여}"
    else
      STATUS="PASS"
      REASON_OK="${OK_ITEMS:-접근 제어 설정이 확인되어}"
    fi
  fi
fi

# RAW_EVIDENCE.detail 문장 구성 분기
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="${REASON_OK} 로 이 항목에 대해 양호합니다."
else
  REASON_LINE="${REASON_BAD:-${BAD_ITEMS}} 로 이 항목에 대해 취약합니다."
fi

# raw_evidence 구성 (detail은 1문장 + 줄바꿈 + 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
  $DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (백슬래시/따옴표/줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
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