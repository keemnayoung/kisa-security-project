#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-59
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 안전한 SNMP 버전 사용
# @Description : 안전한 SNMP 버전 사용 여부 점검
# @Criteria_Good : SNMP 서비스를 v3 이상으로 사용하는 경우
# @Criteria_Bad : SNMP 서비스를 v2 이하로 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-59"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='systemctl is-active snmpd; systemctl is-enabled snmpd; pgrep -a -x snmpd; grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null | grep -nE "^(rouser|rwuser|createUser|com2sec|rocommunity|rwcommunity)\b"'

DETAIL_CONTENT=""
TARGET_FILE=""

append_line() { DETAIL_CONTENT="${DETAIL_CONTENT:+$DETAIL_CONTENT\n}$1"; }
add_file() { TARGET_FILE="${TARGET_FILE:+$TARGET_FILE, }$1"; }
count_lines() { echo "$1" | sed '/^$/d' | wc -l | tr -d ' '; }

# systemd/프로세스 기준으로 SNMP 실행 여부를 판단
ACTIVE="$(systemctl is-active snmpd 2>/dev/null || echo unknown)"
ENABLED="$(systemctl is-enabled snmpd 2>/dev/null || echo unknown)"
PROC_LINE="$(pgrep -a -x snmpd 2>/dev/null | head -n 1 || true)"

SNMP_RUNNING=0
if [ "$ACTIVE" = "active" ] || [ -n "$PROC_LINE" ]; then SNMP_RUNNING=1; fi

append_line "[systemd] snmpd_active=$ACTIVE snmpd_enabled=$ENABLED"
append_line "[process] ${PROC_LINE:-snmpd_not_running}"

# 자동조치 위험 + 조치 방법
GUIDE_LINE="이 항목에 대해서 SNMP 설정을 자동 변경하면 모니터링 연동(NMS) 장애 또는 인증 정보 불일치로 서비스 영향이 발생할 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 snmpd.conf에서 SNMPv1/v2c(rocommunity/rwcommunity/com2sec) 설정을 제거 또는 주석 처리하고, SNMPv3 사용자(createUser) 생성 및 rouser/rwuser 권한 부여를 적용한 뒤 snmpd 재기동으로 반영해 주시기 바랍니다."

REASON_SENTENCE=""

# SNMP가 실행 중이 아니면 설정 기반으로는 안전 상태로 간주
if [ "$SNMP_RUNNING" -eq 0 ]; then
  STATUS="PASS"
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"
  REASON_SENTENCE="snmpd_active=$ACTIVE 및 snmpd_process=${PROC_LINE:-not_running}로 이 항목에 대해 양호합니다."
else
  # 실행 중이면 snmpd.conf에서 SNMPv3 / v1v2c 지시자 존재 여부를 확인
  CONFS=("/etc/snmp/snmpd.conf" "/usr/share/snmp/snmpd.conf")
  FOUND_CONF=0
  V3_FOUND=0
  V12C_FOUND=0

  for f in "${CONFS[@]}"; do
    if [ -f "$f" ]; then
      FOUND_CONF=1
      add_file "$f"

      EFFECTIVE="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null || true)"
      V3_LINES="$(echo "$EFFECTIVE" | grep -E '^(rouser|rwuser|createUser)\b' || true)"
      V12C_LINES="$(echo "$EFFECTIVE" | grep -E '^(com2sec|rocommunity|rwcommunity)\b' || true)"

      if [ -n "$V3_LINES" ]; then
        V3_FOUND=1
        append_line "[conf] $f snmpv3_directives=FOUND (lines=$(count_lines "$V3_LINES"))"
      else
        append_line "[conf] $f snmpv3_directives=NOT_FOUND"
      fi

      if [ -n "$V12C_LINES" ]; then
        V12C_FOUND=1
        append_line "[conf] $f snmpv1v2c_directives=FOUND (lines=$(count_lines "$V12C_LINES"))"
      else
        append_line "[conf] $f snmpv1v2c_directives=NOT_FOUND"
      fi
    else
      append_line "[conf] $f=NOT_FOUND"
    fi
  done

  # 설정 파일을 확인할 수 없으면 안전 버전 사용 여부 판단 불가
  if [ "$FOUND_CONF" -eq 0 ]; then
    STATUS="FAIL"
    TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"
    REASON_SENTENCE="snmpd_active=$ACTIVE 및 snmpd_process=${PROC_LINE:-running} 상태에서 snmpd.conf를 확인할 수 없어 취약합니다."
  else
    # SNMPv3만 확인되면 양호, v1/v2c가 있거나 v3가 없으면 취약
    if [ "$V3_FOUND" -eq 1 ] && [ "$V12C_FOUND" -eq 0 ]; then
      STATUS="PASS"
      REASON_SENTENCE="createUser/rouser/rwuser 설정이 존재하고 rocommunity/rwcommunity/com2sec 설정이 없어 이 항목에 대해 양호합니다."
    else
      STATUS="FAIL"
      if [ "$V12C_FOUND" -eq 1 ]; then
        REASON_SENTENCE="rocommunity/rwcommunity/com2sec 설정이 존재하여 취약합니다."
      else
        REASON_SENTENCE="createUser/rouser/rwuser 설정이 확인되지 않아 취약합니다."
      fi
    fi
  fi
fi

[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

# PASS/FAIL
if [ "$STATUS" = "PASS" ]; then
  DETAIL_VALUE="${REASON_SENTENCE}\n${DETAIL_CONTENT}"
else
  DETAIL_VALUE="${REASON_SENTENCE}\n${DETAIL_CONTENT}"
fi

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_VALUE",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 문자열로 DB 저장 시에도 줄바꿈이 유지되도록 escape 처리
RAW_EVIDENCE_ESCAPED="$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
