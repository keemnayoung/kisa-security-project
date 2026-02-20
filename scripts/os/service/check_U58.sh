#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-58
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 점검
# @Criteria_Good : SNMP 서비스를 사용하지 않는 경우
# @Criteria_Bad :  SNMP 서비스를 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-58"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/usr/sbin/snmpd"

# 대시보드 표시용(줄바꿈 포함) 커맨드 문자열
COMMAND_DISPLAY=$'systemctl is-active snmpd snmptrapd\nsystemctl is-enabled snmpd snmptrapd\nsystemctl list-units --type=service | grep -nE "(snmpd|snmptrapd)"\npgrep -a -x snmpd\npgrep -a -x snmptrapd\ncommand -v snmpd\ncommand -v snmptrapd'

# 점검 대상(불필요 SNMP 서비스 범위)
UNITS=("snmpd" "snmptrapd")
PROCS=("snmpd" "snmptrapd")

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE=""

ACTIVE_HIT=0
ENABLED_HIT=0
PROC_HIT=0
VULN_REASON=""

append_line() {
  local _line="$1"
  [ -z "$_line" ] && return 0
  DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}${_line}"
}

append_reason() {
  local _r="$1"
  [ -z "$_r" ] && return 0
  VULN_REASON="${VULN_REASON}${VULN_REASON:+, }${_r}"
}

# systemd 상태 수집(서비스 단위가 있을 때 active/enabled 기반 판단)
for u in "${UNITS[@]}"; do
  a="$(systemctl is-active "$u" 2>/dev/null || echo "unknown")"
  e="$(systemctl is-enabled "$u" 2>/dev/null || echo "unknown")"
  append_line "[systemd] ${u}: active=${a}, enabled=${e}"

  [ "$a" = "active" ] && ACTIVE_HIT=1 && append_reason "${u}.service active"
  [ "$e" = "enabled" ] && ENABLED_HIT=1 && append_reason "${u}.service enabled"
done

# 프로세스 확인(서비스가 아니어도 떠 있을 수 있어 보조 판단)
for p in "${PROCS[@]}"; do
  if pgrep -x "$p" >/dev/null 2>&1; then
    PROC_HIT=1
    append_line "[process] ${p}: running=Y"
    append_reason "${p} process running"
  else
    append_line "[process] ${p}: running=N"
  fi
done

# 분기: 바이너리 경로(증적/target_file용)
SNMPD_BIN="$(command -v snmpd 2>/dev/null || true)"
SNMPTRAPD_BIN="$(command -v snmptrapd 2>/dev/null || true)"
[ -n "$SNMPD_BIN" ] && TARGET_FILE="$SNMPD_BIN"
append_line "[binary] snmpd_path=${SNMPD_BIN:-NOT_FOUND}, snmptrapd_path=${SNMPTRAPD_BIN:-NOT_FOUND}"

# 최종 판정 및 detail/guide 구성
if [ $ACTIVE_HIT -eq 1 ] || [ $ENABLED_HIT -eq 1 ] || [ $PROC_HIT -eq 1 ]; then
  STATUS="FAIL"
  [ -z "$VULN_REASON" ] && VULN_REASON="snmpd/snmptrapd 상태가 활성로 확인"
  REASON_LINE="${VULN_REASON}로 설정되어 있어 이 항목에 대해 취약합니다."
else
  STATUS="PASS"
  REASON_LINE="snmpd/snmptrapd가 inactive이고 enabled가 disabled로 설정되어 있어 이 항목에 대해 양호합니다."
fi

GUIDE_LINE=$'자동 조치:
systemd에서 snmpd/snmptrapd를 중지(stop)하고 비활성화(disable)한 뒤 재활성화를 방지하기 위해 mask를 적용하며, 잔존 프로세스가 있으면 종료(pkill)합니다.
주의사항: 
SNMP를 통해 모니터링/알림(trap)을 사용하는 환경에서는 중지 시 모니터링 공백이 발생할 수 있으므로 운영/관제 연동 여부를 확인한 뒤 적용해야 합니다.'

# JSON escape (백슬래시/따옴표/줄바꿈)
json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$(json_escape "$COMMAND_DISPLAY")",
  "detail": "$(json_escape "$REASON_LINE
$DETAIL_CONTENT")",
  "guide": "$(json_escape "$GUIDE_LINE")",
  "target_file": "$(json_escape "$TARGET_FILE")"
}
EOF
)

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$(json_escape "$RAW_EVIDENCE")",
    "scan_date": "$SCAN_DATE"
}
EOF
