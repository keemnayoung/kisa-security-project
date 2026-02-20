#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-44
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : tftp, talk 서비스 비활성화
# @Description : tftp, talk, ntalk 서비스의 활성화 여부 점검 
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-44"
CATEGORY="서비스 관리"
TITLE="tftp, talk 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/*, systemd(service/socket)"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

SERVICES=("tftp" "talk" "ntalk")
SYSTEMD_UNITS_CANDIDATES=(
  "tftp.service" "tftp.socket" "talk.service" "ntalk.service" "talkd.service" "ntalkd.service"
)

# 유틸리티 함수 정의
escape_json_str() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

unit_exists() {
  local u="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"
}

# inetd 기반 서비스 조치
INETD_CHANGED=0
if [ -f "/etc/inetd.conf" ]; then
  for svc in "${SERVICES[@]}"; do
    if grep -v "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}\b"; then
      INETD_CHANGED=1
      break
    fi
  done

  if [ $INETD_CHANGED -eq 1 ]; then
    cp -p /etc/inetd.conf "/etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    for svc in "${SERVICES[@]}"; do
      sed -i -E "s/^([[:space:]]*)(${svc}\b)/#\1\2/" /etc/inetd.conf 2>/dev/null || true
    done
    systemctl restart inetd 2>/dev/null || killall -HUP inetd 2>/dev/null || true
  fi
fi

# xinetd 기반 서비스 조치
XINETD_CHANGED=0
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${SERVICES[@]}"; do
    CONF="/etc/xinetd.d/${svc}"
    if [ -f "$CONF" ]; then
      cp -p "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
      if grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b" "$CONF" 2>/dev/null; then
        sed -i -E 's/^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b/        disable = yes/I' "$CONF" 2>/dev/null || true
        XINETD_CHANGED=1
      else
        if ! grep -qiE "^[[:space:]]*disable[[:space:]]*=" "$CONF" 2>/dev/null; then
          if grep -q "}" "$CONF" 2>/dev/null; then
            sed -i -E '0,/}/s/}/        disable = yes\n}/' "$CONF" 2>/dev/null || true
          else
            printf '\n        disable = yes\n' >> "$CONF" 2>/dev/null || true
          fi
          XINETD_CHANGED=1
        fi
      fi
    fi
  done
  if [ $XINETD_CHANGED -eq 1 ]; then
    systemctl restart xinetd 2>/dev/null || true
  fi
fi

# systemd 기반 서비스 조치
SYSTEMD_CHANGED=0
SYSTEMD_FOUND_UNITS=""
if command -v systemctl >/dev/null 2>&1; then
  for u in "${SYSTEMD_UNITS_CANDIDATES[@]}"; do
    if unit_exists "$u"; then SYSTEMD_FOUND_UNITS="${SYSTEMD_FOUND_UNITS}${u} "; fi
  done
  EXTRA_UNITS=$(systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -E '(^|/)(tftp|talk|ntalk).*\.((service)|(socket))$' | tr '\n' ' ')
  SYSTEMD_FOUND_UNITS="${SYSTEMD_FOUND_UNITS}${EXTRA_UNITS}"
  SYSTEMD_FOUND_UNITS=$(printf "%s\n" $SYSTEMD_FOUND_UNITS 2>/dev/null | awk 'NF{seen[$0]=1} END{for(k in seen) print k}' | tr '\n' ' ')

  for u in $SYSTEMD_FOUND_UNITS; do
    if systemctl is-active --quiet "$u" 2>/dev/null; then
      systemctl stop "$u" 2>/dev/null || true
      SYSTEMD_CHANGED=1
    fi
    if systemctl is-enabled --quiet "$u" 2>/dev/null; then
      systemctl disable "$u" 2>/dev/null || true
      SYSTEMD_CHANGED=1
    fi
  done
fi

# 조치 후 상태 검증 및 수집
AFTER_INETD_ACTIVE=""
AFTER_XINETD_BAD=""
AFTER_SYSTEMD_BAD=""

if [ -f "/etc/inetd.conf" ]; then
  AFTER_INETD_ACTIVE=$(grep -v "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -E "^[[:space:]]*(tftp|talk|ntalk)\b" | awk '{print $1}' | tr '\n' ',')
fi
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${SERVICES[@]}"; do
    if [ -f "/etc/xinetd.d/$svc" ]; then
      grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b" "/etc/xinetd.d/$svc" 2>/dev/null && AFTER_XINETD_BAD="${AFTER_XINETD_BAD}${svc} "
    fi
  done
fi
if command -v systemctl >/dev/null 2>&1; then
  for u in $SYSTEMD_FOUND_UNITS; do
    en=$(systemctl is-enabled "$u" 2>/dev/null || echo "disabled")
    ac=$(systemctl is-active "$u" 2>/dev/null || echo "inactive")
    [ "$en" = "enabled" ] || [ "$ac" = "active" ] && AFTER_SYSTEMD_BAD="${AFTER_SYSTEMD_BAD}${u}(${en}/${ac}) "
  done
fi

# 최종 판정 및 REASON_LINE 확정
if [ -z "$AFTER_INETD_ACTIVE" ] && [ -z "$AFTER_XINETD_BAD" ] && [ -z "$AFTER_SYSTEMD_BAD" ]; then
  IS_SUCCESS=1
  REASON_LINE="tftp, talk, ntalk 서비스를 모든 관리 체계에서 중지하고 비활성화하여 조치를 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  REASON_LINE="일부 tftp/talk/ntalk 서비스가 여전히 활성화되어 있거나 중지되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
fi

DETAIL_CONTENT="inetd_status: ${AFTER_INETD_ACTIVE:-no_active_lines}
xinetd_status: ${AFTER_XINETD_BAD:-all_disabled}
systemd_status: ${AFTER_SYSTEMD_BAD:-all_stopped}"

# 결과 데이터 구성 및 출력
CHECK_COMMAND="( [ -f /etc/inetd.conf ] && grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf | grep -nE '^[[:space:]]*(tftp|talk|ntalk)\\b' || true ); ( [ -d /etc/xinetd.d ] && grep -nEi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\\b' /etc/xinetd.d/{tftp,talk,ntalk} 2>/dev/null || true ); ( command -v systemctl >/dev/null 2>&1 && ( systemctl list-unit-files 2>/dev/null | egrep '(^|/)(tftp|talk|ntalk).*\\.(service|socket)[[:space:]]' || true ) )"

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(escape_json_str "$TARGET_FILE")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

echo ""
cat <<EOF
{
  "item_code": "$ID",
  "action_date": "$ACTION_DATE",
  "is_success": $IS_SUCCESS,
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF