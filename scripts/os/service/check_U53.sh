#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-53
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 정보 노출 제한
# @Description : FTP 서비스 정보 노출 여부 점검
# @Criteria_Good : FTP 접속 배너에 노출되는 정보가 없는 경우
# @Criteria_Bad : FTP 접속 배너에 노출되는 정보가 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-53"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE=""
TARGET_FILE=""
CHECK_COMMAND='command -v vsftpd; command -v proftpd; systemctl is-active vsftpd proftpd; egrep -n "^[[:space:]]*(ftpd_banner|banner_file)[[:space:]]*=" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; egrep -n "^[[:space:]]*ServerIdent\\b" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null'

FOUND_ANY=0
VULN=0

DETAIL_LINES=""
OK_SUMMARY=""
VULN_SUMMARY=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\n}$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }
add_ok(){ [ -n "${1:-}" ] && OK_SUMMARY="${OK_SUMMARY}${OK_SUMMARY:+; }$1"; }
add_vuln(){ [ -n "${1:-}" ] && VULN_SUMMARY="${VULN_SUMMARY}${VULN_SUMMARY:+; }$1"; }

is_leaky_banner() {
  local s="${1:-}"
  echo "$s" | grep -qiE '(vsftpd|proftpd|version|[0-9]+\.[0-9]+)'
}

get_kv_value() {
  echo "$1" | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"$//'
}

if command -v vsftpd >/dev/null 2>&1; then
  FOUND_ANY=1
  VS_CONF_FOUND=0
  VS_HAS_SETTING=0
  VS_HAS_SAFE=0
  VS_HAS_LEAK=0

  for conf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [ -f "$conf" ] || continue
    VS_CONF_FOUND=1
    add_target "$conf"

    ft_line="$(grep -nE '^[[:space:]]*ftpd_banner[[:space:]]*=' "$conf" 2>/dev/null | grep -vE '^[[:space:]]*#' | head -n1)"
    bf_line="$(grep -nE '^[[:space:]]*banner_file[[:space:]]*=' "$conf" 2>/dev/null | grep -vE '^[[:space:]]*#' | head -n1)"

    if [ -n "$ft_line" ]; then
      VS_HAS_SETTING=1
      val="$(get_kv_value "$ft_line")"
      add_detail "[vsftpd] $conf | $ft_line"
      if is_leaky_banner "$val"; then
        VULN=1; VS_HAS_LEAK=1
        add_detail "[vsftpd] ftpd_banner_value=LEAKY"
        add_vuln "vsftpd:$conf ftpd_banner=${val:-empty}"
      else
        VS_HAS_SAFE=1
        add_detail "[vsftpd] ftpd_banner_value=OK"
        add_ok "vsftpd:$conf ftpd_banner=${val:-empty}"
      fi
    fi

    if [ -n "$bf_line" ]; then
      VS_HAS_SETTING=1
      bf="$(get_kv_value "$bf_line")"
      add_detail "[vsftpd] $conf | $bf_line"
      if [ -n "$bf" ] && [ -f "$bf" ]; then
        add_target "$bf"
        btxt="$(head -n 3 "$bf" 2>/dev/null | tr '\n' ' ')"
        add_detail "[vsftpd] banner_file_content(head)=${btxt:-empty}"
        if is_leaky_banner "$btxt"; then
          VULN=1; VS_HAS_LEAK=1
          add_detail "[vsftpd] banner_file_content=LEAKY"
          add_vuln "vsftpd:$conf banner_file=${bf} content(head)=${btxt:-empty}"
        else
          VS_HAS_SAFE=1
          add_detail "[vsftpd] banner_file_content=OK"
          add_ok "vsftpd:$conf banner_file=${bf} content(head)=${btxt:-empty}"
        fi
      else
        VULN=1; VS_HAS_LEAK=1
        add_detail "[vsftpd] banner_file=NOT_FOUND"
        add_vuln "vsftpd:$conf banner_file=${bf:-empty}(not_found)"
      fi
    fi

    if [ -z "$ft_line" ] && [ -z "$bf_line" ]; then
      VULN=1; VS_HAS_LEAK=1
      add_detail "[vsftpd] $conf | ftpd_banner/banner_file=NOT_SET"
      add_vuln "vsftpd:$conf ftpd_banner/banner_file=not_set"
    fi
  done

  if [ $VS_CONF_FOUND -eq 0 ]; then
    VULN=1
    add_detail "[vsftpd] command=FOUND but config_file=NOT_FOUND"
    add_vuln "vsftpd config_file=not_found"
  else
    if [ $VS_HAS_SETTING -eq 1 ] && [ $VS_HAS_LEAK -eq 0 ] && [ $VS_HAS_SAFE -eq 1 ]; then
      : # ok summary already added
      :
    fi
  fi

  if systemctl is-active --quiet vsftpd 2>/dev/null; then
    add_detail "[vsftpd] service_active=Y"
  else
    add_detail "[vsftpd] service_active=N"
  fi
fi

if command -v proftpd >/dev/null 2>&1; then
  FOUND_ANY=1
  PF_CONF_FOUND=0

  for conf in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
    [ -f "$conf" ] || continue
    PF_CONF_FOUND=1
    add_target "$conf"

    si_line="$(grep -nE '^[[:space:]]*ServerIdent\b' "$conf" 2>/dev/null | grep -vE '^[[:space:]]*#' | head -n1)"
    if [ -z "$si_line" ]; then
      VULN=1
      add_detail "[proftpd] $conf | ServerIdent=NOT_SET"
      add_vuln "proftpd:$conf ServerIdent=not_set"
      continue
    fi

    add_detail "[proftpd] $conf | $si_line"

    if echo "$si_line" | grep -qiE '\bServerIdent[[:space:]]+off\b'; then
      add_detail "[proftpd] ServerIdent_value=OK"
      add_ok "proftpd:$conf ServerIdent=off"
      continue
    fi

    if echo "$si_line" | grep -qiE '\bServerIdent[[:space:]]+on\b'; then
      banner="$(echo "$si_line" | sed -nE 's/.*ServerIdent[[:space:]]+on[[:space:]]+"([^"]*)".*/\1/p')"
      [ -z "$banner" ] && banner="$(echo "$si_line" | sed -E 's/^[[:space:]]*//')"
      if is_leaky_banner "$banner"; then
        VULN=1
        add_detail "[proftpd] ServerIdent_value=LEAKY"
        add_vuln "proftpd:$conf ServerIdent_on=${banner}"
      else
        add_detail "[proftpd] ServerIdent_value=OK"
        add_ok "proftpd:$conf ServerIdent_on=${banner}"
      fi
    else
      VULN=1
      add_detail "[proftpd] ServerIdent=UNKNOWN_FORMAT"
      add_vuln "proftpd:$conf ServerIdent=unknown_format"
    fi
  done

  if [ $PF_CONF_FOUND -eq 0 ]; then
    VULN=1
    add_detail "[proftpd] command=FOUND but config_file=NOT_FOUND"
    add_vuln "proftpd config_file=not_found"
  fi

  if systemctl is-active --quiet proftpd 2>/dev/null; then
    add_detail "[proftpd] service_active=Y"
  else
    add_detail "[proftpd] service_active=N"
  fi
fi

if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 이 항목에 대해 양호합니다."
  DETAIL_CONTENT="none"
  GUIDE_LINE="none"
else
  DETAIL_CONTENT="${DETAIL_LINES:-none}"

  if [ $VULN -eq 1 ]; then
    STATUS="FAIL"
    [ -z "$VULN_SUMMARY" ] && VULN_SUMMARY="FTP 배너 관련 설정 상태를 확인하지 못했습니다"
    REASON_LINE="${VULN_SUMMARY}로 이 항목에 대해 취약합니다."
    GUIDE_LINE=$(cat <<'EOF'
자동 조치:
vsftpd는 설정 파일의 ftpd_banner/banner_file을 일반 안내 문구로 변경하고, banner_file 사용 시 배너 파일을 생성/내용을 일반 문구로 고정합니다.
ProFTPD는 설정 파일의 ServerIdent를 off로 설정합니다.
자동 조치 후에는 관련 서비스를 재시작하여 설정이 반영되도록 처리합니다.
주의사항:
서비스 재시작 시 기존 FTP 세션이 끊길 수 있으며, 배너 변경은 운영/모니터링 환경에서 안내 문구 정책과 충돌할 수 있어 사전 확인이 필요합니다.
설정 파일/배너 파일을 수정하므로 백업 후 적용하고, 배너 파일 경로 권한/소유자 정책에 따라 접근 오류가 발생할 수 있습니다.
EOF
)
  else
    STATUS="PASS"
    [ -z "$OK_SUMMARY" ] && OK_SUMMARY="FTP 배너 관련 설정이 식별정보 노출 없이 구성되어 있습니다"
    REASON_LINE="${OK_SUMMARY}로 이 항목에 대해 양호합니다."
    GUIDE_LINE="none"
  fi
fi

[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf, /etc/proftpd/proftpd.conf, /etc/proftpd.conf"

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

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
