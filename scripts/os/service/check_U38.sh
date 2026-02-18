#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-38
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DoS 공격에 취약한 서비스 비활성화
# @Description : 사용하지 않는 DoS 공격에 취약한 서비스의 실행 여부 점검
# @Criteria_Good : DoS 공격에 취약한 서비스가 비활성화된 경우
# @Criteria_Bad : DoS 공격에 취약한 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-38"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

DOS_SERVICES=("echo" "discard" "daytime" "chargen")

TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/(echo|discard|daytime|chargen)
systemd(echo|discard|daytime|chargen 및 -dgram/-stream 변형 unit)"

CHECK_COMMAND='
[ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | egrep -n "^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)" || echo "inetd_conf_not_found_or_no_active";
for f in /etc/xinetd.d/echo /etc/xinetd.d/discard /etc/xinetd.d/daytime /etc/xinetd.d/chargen; do
  [ -f "$f" ] && echo "xinetd_file:$f" && grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -niE "^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*" | head -n 2 || true;
done;
(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --type=socket 2>/dev/null | grep -Ei "^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]") || echo "systemd_units_not_found";
(command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --type=socket 2>/dev/null | grep -Ei "^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]") || true
'

REASON_LINE=""
DETAIL_CONTENT=""
FOUND_LIST=()

add_found() {
  local msg="$1"
  [ -n "$msg" ] && FOUND_LIST+=("$msg")
}

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

json_escape() {
  echo "$1" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# inetd 현재 상태 수집: 활성 라인(주석 제외) 출력
if [ -f "/etc/inetd.conf" ]; then
  inetd_lines="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)' | head -n 10)"
  if [ -z "$inetd_lines" ]; then
    append_detail "inetd(after/current)=no_active_dos_services"
  else
    append_detail "inetd(after/current)=\n$inetd_lines"
  fi
else
  append_detail "inetd(after/current)=inetd_conf_not_found"
fi

# xinetd 현재 상태 수집: disable 라인(있으면) 출력
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${DOS_SERVICES[@]}"; do
    f="/etc/xinetd.d/$svc"
    if [ -f "$f" ]; then
      line="$(grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -niE '^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*' | head -n 1)"
      [ -z "$line" ] && line="disable_setting_not_found"
      append_detail "xinetd_${svc}(after/current)=${line}"
    else
      append_detail "xinetd_${svc}(after/current)=file_not_found"
    fi
  done
else
  append_detail "xinetd(after/current)=xinetd_dir_not_found"
fi

# systemd 현재 상태 수집: 존재하는 unit의 enabled/active 상태 출력
SYSTEMD_SUMMARY="systemd_units_not_found"
SYSTEMD_FOUND=""

if command -v systemctl >/dev/null 2>&1; then
  SYSTEMD_SUMMARY="$(systemctl list-unit-files --type=service --type=socket 2>/dev/null | grep -Ei '^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]' || echo 'systemd_units_not_found')"
  for base in "${DOS_SERVICES[@]}"; do
    for suf in "" "-dgram" "-stream"; do
      for typ in "socket" "service"; do
        unit="${base}${suf}.${typ}"
        if systemctl list-unit-files --type=service --type=socket 2>/dev/null | grep -qiE "^${unit}[[:space:]]"; then
          en="$(systemctl is-enabled "$unit" 2>/dev/null || echo unknown)"
          ac="$(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
          append_detail "systemd_${unit}(after/current)=enabled:${en},active:${ac}"
          if echo "$ac" | grep -qiE "^active$"; then
            SYSTEMD_FOUND="${SYSTEMD_FOUND}${unit}(active) "
          else
            if echo "$en" | grep -qiE "^enabled"; then
              SYSTEMD_FOUND="${SYSTEMD_FOUND}${unit}(${en}) "
            fi
          fi
        fi
      done
    done
  done
else
  append_detail "systemd(after/current)=systemctl_not_found"
fi

append_detail "systemd_units(after/current)=\n$SYSTEMD_SUMMARY"

# 취약 판정 로직
# inetd: 주석 제외 후 해당 서비스 라인 존재하면 취약
if [ -f "/etc/inetd.conf" ]; then
  for svc in "${DOS_SERVICES[@]}"; do
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}([[:space:]]|$)"; then
      STATUS="FAIL"
      add_found "/etc/inetd.conf:${svc}"
    fi
  done
fi

# xinetd: disable=no면 취약
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${DOS_SERVICES[@]}"; do
    f="/etc/xinetd.d/$svc"
    if [ -f "$f" ]; then
      if grep -Ev "^[[:space:]]*#" "$f" 2>/dev/null | grep -qiE "^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*no([[:space:]]|$)"; then
        STATUS="FAIL"
        add_found "$f:disable=no"
      fi
    fi
  done
fi

# systemd: active 또는 enabled면 취약
if [ -n "$SYSTEMD_FOUND" ]; then
  STATUS="FAIL"
  add_found "systemd:${SYSTEMD_FOUND% }"
fi

# reason(설정값 기반) + guide(자동조치 가정) 구성
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="inetd에서 echo/discard/daytime/chargen 활성 라인이 없고 xinetd에서 disable=no가 없으며 systemd에서 관련 unit이 active/enabled가 아니라 이 항목에 대해 양호합니다."
else
  VULN_CAUSE="$(printf "%s, " "${FOUND_LIST[@]}")"
  VULN_CAUSE="${VULN_CAUSE%, }"
  REASON_LINE="${VULN_CAUSE} 설정이 확인되어 이 항목에 대해 취약합니다."
fi

GUIDE_LINE="자동 조치:
inetd는 /etc/inetd.conf에서 echo/discard/daytime/chargen 활성 라인을 주석 처리하고, xinetd는 /etc/xinetd.d/* 파일의 disable=no를 disable=yes로 변경하며, systemd는 관련 socket/service를 stop 후 disable 및 mask 처리합니다.
주의사항: 
미사용 서비스만 대상으로 해야 하며, 시간대별/운영 중 서비스 의존성이 있는 환경에서는 xinetd/inetd 재시작 또는 systemd unit 비활성화로 예상치 못한 서비스 영향이 발생할 수 있으므로 적용 전 점검 및 적용 후 즉시 검증이 필요합니다."

# RAW_EVIDENCE 생성 (줄바꿈은 실제 \n로 들어가고, 최종 JSON에는 \\n으로 escape)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
