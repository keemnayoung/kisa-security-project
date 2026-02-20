#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-54
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 암호화되지 않는 FTP 서비스 비활성화
# @Description : 암호화되지 않은 FTP 서비스 비활성화 여부 점검
# @Criteria_Good : 암호화되지 않은 FTP 서비스가 비활성화된 경우
# @Criteria_Bad : 암호화되지 않은 FTP 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-54"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

CHECK_COMMAND=$'grep -nE "^[[:space:]]*ftp\\b" /etc/inetd.conf 2>/dev/null\n'\
$'grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\\b" /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp 2>/dev/null\n'\
$'systemctl list-unit-files 2>/dev/null | grep -Ei "^(vsftpd|proftpd|pure-ftpd)\\.service"\n'\
$'systemctl is-active vsftpd proftpd pure-ftpd 2>/dev/null\n'\
$'systemctl is-enabled vsftpd proftpd pure-ftpd 2>/dev/null'

VULNERABLE=0
DETAIL_LINES=""
REASON_FACTS=""

add_detail() { [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\n}$1"; }
add_reason() { [ -n "${1:-}" ] && REASON_FACTS="${REASON_FACTS}${REASON_FACTS:+; }$1"; }
add_file() { [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

# inetd 설정 점검: /etc/inetd.conf 내 ftp 활성 라인(주석 제외) 존재 여부
INETD="/etc/inetd.conf"
if [ -f "$INETD" ]; then
  add_file "$INETD"
  INETD_ACTIVE_LINES="$(grep -nEv '^[[:space:]]*#' "$INETD" 2>/dev/null | grep -nE '^[[:space:]]*ftp([[:space:]]|$)' || true)"
  if [ -n "$INETD_ACTIVE_LINES" ]; then
    VULNERABLE=1
    add_reason "/etc/inetd.conf 에 ftp 활성 라인이 존재함"
    add_detail "[inetd] active_ftp_lines:\n$INETD_ACTIVE_LINES"
  else
    add_detail "[inetd] active_ftp_lines: none"
  fi
else
  add_detail "[inetd] file: not_found (/etc/inetd.conf)"
fi

# xinetd 설정 점검: /etc/xinetd.d/{ftp,proftp,vsftp} 내 disable=no 여부
if [ -d "/etc/xinetd.d" ]; then
  for f in /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp; do
    if [ -f "$f" ]; then
      add_file "$f"
      X_DISABLE_LINE="$(grep -nEvi '^[[:space:]]*#' "$f" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1 || true)"
      X_DISABLE_NO="$(grep -nEvi '^[[:space:]]*#' "$f" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)' | head -n 1 || true)"
      if [ -n "$X_DISABLE_NO" ]; then
        VULNERABLE=1
        add_reason "$(basename "$f") 에 disable=no 설정이 존재함"
        add_detail "[xinetd] file=$f disable_line: $X_DISABLE_LINE"
      else
        [ -z "$X_DISABLE_LINE" ] && X_DISABLE_LINE="disable_line_not_found"
        add_detail "[xinetd] file=$f disable_line: $X_DISABLE_LINE"
      fi
    else
      add_detail "[xinetd] file: not_found ($f)"
    fi
  done
else
  add_detail "[xinetd] dir: not_found (/etc/xinetd.d)"
fi

# systemd 점검: vsftpd/proftpd/pure-ftpd 의 active/enabled 여부
if command -v systemctl >/dev/null 2>&1; then
  for s in vsftpd proftpd pure-ftpd; do
    if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.service"; then
      add_file "systemd:${s}.service"
      S_ACTIVE="$(systemctl is-active "$s" 2>/dev/null || echo "unknown")"
      S_ENABLED="$(systemctl is-enabled "$s" 2>/dev/null || echo "unknown")"
      add_detail "[systemd] ${s}.service active=$S_ACTIVE enabled=$S_ENABLED"
      if [ "$S_ACTIVE" = "active" ] || [ "$S_ENABLED" = "enabled" ]; then
        VULNERABLE=1
        [ "$S_ACTIVE" = "active" ] && add_reason "${s}.service 가 active 임"
        [ "$S_ENABLED" = "enabled" ] && add_reason "${s}.service 가 enabled 임"
      fi
    else
      add_detail "[systemd] ${s}.service unit: not_found"
    fi
  done
else
  add_detail "[systemd] systemctl: not_available"
fi

DETAIL_CONTENT="${DETAIL_LINES:-none}"
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/{ftp,proftp,vsftp}, systemd:{vsftpd,proftpd,pure-ftpd}.service"

# 최종 판정 및 detail
if [ "$VULNERABLE" -eq 1 ]; then
  STATUS="FAIL"
  [ -z "$REASON_FACTS" ] && REASON_FACTS="암호화되지 않은 FTP 관련 설정/서비스가 활성 상태로 확인됨"
  REASON_LINE="${REASON_FACTS}로 이 항목에 대해 취약합니다."
else
  STATUS="PASS"
  REASON_LINE="/etc/inetd.conf 에 ftp 활성 라인이 없고 /etc/xinetd.d 에서 disable=no 설정이 없으며 systemd 의 FTP 데몬이 active/enabled 가 아니어서 이 항목에 대해 양호합니다."
fi

GUIDE_LINE=$(cat <<'EOF'
자동 조치:
inetd 환경이면 /etc/inetd.conf 의 ftp 관련 라인을 주석 처리합니다.
xinetd 환경이면 /etc/xinetd.d 의 ftp 계열 설정에서 disable 값을 yes 로 표준화하고 필요 시 xinetd 를 재시작합니다.
systemd 환경이면 vsftpd/proftpd/pure-ftpd 서비스를 stop 하고 disable 및 mask 처리합니다.
주의사항:
FTP 서비스를 업무적으로 사용 중인 시스템에서는 중지/비활성화로 파일 전송 업무가 중단될 수 있으니 영향도를 확인한 뒤 적용해야 합니다.
inetd/xinetd 재시작 또는 systemd 서비스 변경은 관련 서비스 구성이 있는 경우 연결이 끊길 수 있으므로 유지보수 시간대에 적용하는 것이 안전합니다.
EOF
)

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
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
