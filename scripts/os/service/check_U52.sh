#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-52
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : Telnet 서비스 비활성화
# @Description : 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# @Criteria_Good : 원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우
# @Criteria_Bad : 원격 접속 시 Telnet 프로토콜을 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-52 Telnet 서비스 비활성화

# 기본 변수
ID="U-52"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/inetd.conf | grep -nE "^[[:space:]]*telnet([[:space:]]|$)" ) || echo "inetd_telnet_not_enabled_or_file_missing";
( [ -f /etc/xinetd.d/telnet ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/xinetd.d/telnet | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*(no|yes)\b" ) || echo "xinetd_telnet_disable_directive_not_found_or_file_missing";
systemctl is-enabled telnet.socket 2>/dev/null || echo "telnet.socket_not_enabled_or_not_found";
systemctl is-active telnet.socket 2>/dev/null || echo "telnet.socket_not_active_or_not_found";
systemctl is-enabled telnet.service 2>/dev/null || echo "telnet.service_not_enabled_or_not_found";
systemctl is-active telnet.service 2>/dev/null || echo "telnet.service_not_active_or_not_found";
systemctl is-active sshd 2>/dev/null || echo "sshd_not_active"
'

VULNERABLE=0
DETAIL_LINES=""
BAD_REASON_PARTS=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\n}$1"; }
add_bad(){ [ -n "${1:-}" ] && BAD_REASON_PARTS="${BAD_REASON_PARTS}${BAD_REASON_PARTS:+, }$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

# inetd.conf 분기: 파일 존재 여부 및 telnet 라인(주석 제외) 존재 여부로 판단
INETD="/etc/inetd.conf"
if [ -f "$INETD" ]; then
  add_target "$INETD"
  INETD_TELNET_LINE="$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$INETD" 2>/dev/null | grep -nE '^[[:space:]]*telnet([[:space:]]|$)' | head -n 1)"
  if [ -n "$INETD_TELNET_LINE" ]; then
    VULNERABLE=1
    add_bad "/etc/inetd.conf: ${INETD_TELNET_LINE}"
    add_detail "inetd:/etc/inetd.conf telnet_line=${INETD_TELNET_LINE}"
  else
    add_detail "inetd:/etc/inetd.conf telnet_line=not_found_or_commented"
  fi
else
  add_detail "inetd:/etc/inetd.conf file=not_found"
fi

# xinetd 분기: 파일 존재 시 disable 값(no/yes/unknown)을 수집하고 no 또는 unknown이면 취약으로 판단
XINETD="/etc/xinetd.d/telnet"
if [ -f "$XINETD" ]; then
  add_target "$XINETD"
  X_DISABLE_LINE="$(grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
  X_DISABLE_VAL="$(echo "$X_DISABLE_LINE" | awk -F= '{print tolower($2)}' | tr -d '[:space:]' | sed 's/[;#].*$//')"
  [ -z "$X_DISABLE_VAL" ] && X_DISABLE_VAL="unknown"
  add_detail "xinetd:/etc/xinetd.d/telnet disable=${X_DISABLE_VAL}${X_DISABLE_LINE:+ (${X_DISABLE_LINE})}"
  if [ "$X_DISABLE_VAL" = "no" ] || [ "$X_DISABLE_VAL" = "unknown" ]; then
    VULNERABLE=1
    if [ "$X_DISABLE_VAL" = "no" ]; then
      add_bad "/etc/xinetd.d/telnet: disable=no"
    else
      add_bad "/etc/xinetd.d/telnet: disable=unknown"
    fi
  fi
else
  add_detail "xinetd:/etc/xinetd.d/telnet file=not_found"
fi

# systemd: telnet.socket / telnet.service의 enabled 또는 active 상태를 수집하고 enabled/active면 취약으로 판단
SYS_FIND=0
for u in telnet.socket telnet.service; do
  EN="unknown"; AC="unknown"
  if command -v systemctl >/dev/null 2>&1; then
    EN="$(systemctl is-enabled "$u" 2>/dev/null || echo not_found)"
    AC="$(systemctl is-active  "$u" 2>/dev/null || echo not_found)"
  fi
  add_detail "systemd:${u} enabled=${EN} active=${AC}"
  if [ "$EN" = "enabled" ] || [ "$AC" = "active" ]; then
    VULNERABLE=1
    SYS_FIND=1
    add_bad "systemd:${u} enabled=${EN} active=${AC}"
  fi
done
[ $SYS_FIND -eq 0 ] && add_detail "systemd:telnet.socket/telnet.service enabled_or_active=none_detected"

# SSH: sshd 실행 상태만 수집(판정에는 영향 없음)
SSHD="unknown"
if command -v systemctl >/dev/null 2>&1; then
  SSHD="$(systemctl is-active sshd 2>/dev/null || echo not_found_or_inactive)"
fi
add_detail "ssh:sshd active=${SSHD}"

DETAIL_CONTENT="${DETAIL_LINES:-none}"
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/telnet, systemd(telnet.socket/service)"

# 최종 판정 분기: 취약 근거는 취약 부분 설정만 사용하고, 상세에는 현재 설정 값 전체를 유지
if [ $VULNERABLE -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="${BAD_REASON_PARTS} 로 설정되어 이 항목에 대해 취약합니다."
else
  STATUS="PASS"
  REASON_LINE="inetd_telnet=not_found_or_commented, xinetd_disable=yes, systemd_telnet=disabled_or_inactive 로 설정되어 이 항목에 대해 양호합니다."
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE="$(cat <<'EOF'
자동 조치: 
/etc/inetd.conf에서 telnet 라인을 주석 처리하거나 제거합니다.
/etc/xinetd.d/telnet에서 disable 값을 yes로 설정하고 disable 라인이 없으면 추가합니다.
systemd의 telnet.socket 및 telnet.service(또는 telnetd.*)를 stop 후 disable 및 mask 처리합니다.
주의사항: 
원격 접속을 Telnet에 의존하던 환경에서는 즉시 접속이 끊길 수 있으므로 SSH 접속 가능 여부를 먼저 확인해야 합니다.
inetd/xinetd 재시작 또는 systemd unit 변경은 관련 서비스에 순간적인 영향이 있을 수 있으므로 운영 시간대를 고려해야 합니다.
배포판/패키지 구성에 따라 telnet 관련 unit 이름이 다를 수 있어 적용 전 현재 상태를 확인해야 합니다.
EOF
)"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$( [ "$STATUS" = "PASS" ] && echo "$REASON_LINE" || echo "$REASON_LINE" )\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# escape (backslash/quote/newline)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
