#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-38
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DoS 공격에 취약한 서비스 비활성화
# @Description : 사용하지 않는 DoS 공격에 취약한 서비스의 실행 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-38"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

DOS_SERVICES=("echo" "discard" "daytime" "chargen")

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)" ) || echo "inetd_conf_not_found_or_no_active";
for s in echo discard daytime chargen; do
  [ -f "/etc/xinetd.d/$s" ] && echo "xinetd_file:$s" && grep -nEv "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -niE "^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*" | head -n 2 || true;
done;
(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -Eqi "^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]") || echo "systemd_units_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/(echo,discard,daytime,chargen)
systemd(echo/discard/daytime/chargen 및 -dgram/-stream 변형)"

ACTION_ERR_LOG=""
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MODIFIED=0

# 유틸리티 함수 정의
append_err() {
  if [ -n "$ACTION_ERR_LOG" ]; then
    ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
  else
    ACTION_ERR_LOG="$1"
  fi
}

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

# root 권한 안내
if [ "$(id -u)" -ne 0 ]; then
  append_err "(주의) root 권한이 아니면 sed/systemctl 조치가 실패할 수 있습니다."
fi

# 서비스 재시작 함수 정의
restart_inetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^inetd\.service" || return 0
  systemctl restart inetd 2>/dev/null || append_err "systemctl restart inetd 실패"
}

restart_xinetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^xinetd\.service" || return 0
  systemctl restart xinetd 2>/dev/null || append_err "systemctl restart xinetd 실패"
}

# systemd 유닛 비활성화 처리
disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

# 서비스 존재 여부 확인
unit_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]"
}

any_service_present() {
  local seen_sep=0
  for x in "$@"; do
    if [ "$x" = "--" ]; then
      seen_sep=1
      continue
    fi
    if [ $seen_sep -eq 0 ]; then
      unit_exists "$x" && return 0
    else
      command -v "$x" >/dev/null 2>&1 && return 0
    fi
  done
  return 1
}

# 1) inetd 서비스 조치
if [ -f "/etc/inetd.conf" ]; then
  if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)" ; then
    cp -a /etc/inetd.conf "/etc/inetd.conf.bak_${TIMESTAMP}" 2>/dev/null || append_err "inetd.conf 백업 실패"
    for s in "${DOS_SERVICES[@]}"; do
      sed -i "s/^\([[:space:]]*${s}\([[:space:]]\|$\)\)/#\1/g" /etc/inetd.conf 2>/dev/null || true
    done
    MODIFIED=1
    restart_inetd_if_exists
  fi
fi

# 2) xinetd 서비스 조치
XINETD_CHANGED=0
for s in "${DOS_SERVICES[@]}"; do
  f="/etc/xinetd.d/$s"
  if [ -f "$f" ]; then
    if grep -Ev "^[[:space:]]*#" "$f" 2>/dev/null | grep -qiE "^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*no([[:space:]]|$)"; then
      cp -a "$f" "${f}.bak_${TIMESTAMP}" 2>/dev/null || append_err "$f 백업 실패"
      perl -0777 -i -pe 's/^(\s*disable\s*(?:=)?\s*)no(\s*(?:#.*)?)?$/\1yes\2/gim' "$f" 2>/dev/null || append_err "$f disable=yes 변경 실패"
      XINETD_CHANGED=1
      MODIFIED=1
    fi
  fi
done

if [ "$XINETD_CHANGED" -eq 1 ]; then
  restart_xinetd_if_exists
fi

# 3) systemd 유닛 조치
for base in echo discard daytime chargen; do
  for suf in "" "-dgram" "-stream"; do
    disable_systemd_unit_if_exists "${base}${suf}.service"
    disable_systemd_unit_if_exists "${base}${suf}.socket"
  done
done

# 4) 조치 결과 검증 및 상세 정보 수집
FAIL_FLAG=0

INETD_POST="inetd_conf_not_found(na)"
if [ -f "/etc/inetd.conf" ]; then
  INETD_POST="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)' | head -n 5)"
  [ -z "$INETD_POST" ] && INETD_POST="no_active_dos_services"
  [ "$INETD_POST" != "no_active_dos_services" ] && FAIL_FLAG=1
fi

XINETD_POST_SUMMARY=""
for s in "${DOS_SERVICES[@]}"; do
  f="/etc/xinetd.d/$s"
  if [ -f "$f" ]; then
    line="$(grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -niE '^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*' | head -n 1)"
    [ -z "$line" ] && line="disable_setting_not_found"
    XINETD_POST_SUMMARY="${XINETD_POST_SUMMARY}${s}:${line}; "

    if grep -Ev "^[[:space:]]*#" "$f" 2>/dev/null | grep -qiE "^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*no([[:space:]]|$)"; then
      FAIL_FLAG=1
    fi
  fi
done
[ -z "$XINETD_POST_SUMMARY" ] && XINETD_POST_SUMMARY="no_xinetd_dos_service_files"

SYSTEMD_UNITS_AFTER="systemd_units_not_found"
SYSTEMD_BAD=0
if command -v systemctl >/dev/null 2>&1; then
  SYSTEMD_UNITS_AFTER="$(systemctl list-unit-files 2>/dev/null | grep -Ei '^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]' || echo 'systemd_units_not_found')"
  for base in echo discard daytime chargen; do
    for suf in "" "-dgram" "-stream"; do
      for typ in service socket; do
        u="${base}${suf}.${typ}"
        if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
          en="$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)"
          ac="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
          append_detail "${u}_status: enabled=${en}, active=${ac}"
          echo "$en" | grep -qiE "^enabled" && SYSTEMD_BAD=1
          echo "$ac" | grep -qiE "^active" && SYSTEMD_BAD=1
        fi
      done
    done
  done
fi
[ "$SYSTEMD_BAD" -eq 1 ] && FAIL_FLAG=1

append_detail "inetd_status: $INETD_POST"
append_detail "xinetd_status: $XINETD_POST_SUMMARY"
append_detail "systemd_status: $SYSTEMD_UNITS_AFTER"

# 추가 수동 조치 필요 서비스 확인
if any_service_present chronyd.service ntpd.service systemd-timesyncd.service -- chronyd ntpd; then
  append_detail "manual_note: NTP 관련 서비스가 활성화되어 있습니다. 미사용 시 수동 조치가 필요합니다."
fi

if any_service_present named.service unbound.service dnsmasq.service systemd-resolved.service -- named unbound dnsmasq resolvectl; then
  append_detail "manual_note: DNS 관련 서비스가 활성화되어 있습니다. 서버 역할에 따라 수동 조치가 필요합니다."
fi

if any_service_present snmpd.service snmptrapd.service -- snmpd snmptrapd; then
  append_detail "manual_note: SNMP 서비스가 활성화되어 있습니다. 미사용 시 수동 조치가 필요합니다."
fi

# 최종 판정 및 REASON_LINE 구성
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="DoS 공격에 취약한 서비스(echo, discard, daytime, chargen)를 중지하고 비활성화하여 조치를 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  REASON_LINE="일부 DoS 공격에 취약한 서비스가 여전히 활성화되어 있거나 중지되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n[Error_Log]\n$ACTION_ERR_LOG"
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF