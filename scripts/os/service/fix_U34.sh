#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-34
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 초기화 분기점
ID="U-34"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -Ei "^(finger|fingerd)\.(service|socket)[[:space:]]") || echo "systemd_units_not_found"; ( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*finger([[:space:]]|$)" ) || echo "inetd_no_active_finger"; ( [ -f /etc/xinetd.d/finger ] && grep -nEv "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*(no|yes)([[:space:]]|$)" ) || echo "xinetd_finger_not_found_or_no_disable"'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/finger
systemd(finger/fingerd)"

ACTION_ERR_LOG=""

# 권한 체크 및 로그 처리 함수 분기점
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 sed/systemctl 조치가 실패할 수 있습니다."
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MODIFIED=0

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

# 서비스 제어 유틸리티 함수 분기점
disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

restart_xinetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^xinetd\.service" || return 0
  systemctl restart xinetd 2>/dev/null || append_err "systemctl restart xinetd 실패"
}

restart_inetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^inetd\.service" || return 0
  systemctl restart inetd 2>/dev/null || append_err "systemctl restart inetd 실패"
}

# 1) systemd 서비스 조치 분기점
disable_systemd_unit_if_exists "finger.socket"
disable_systemd_unit_if_exists "finger.service"
disable_systemd_unit_if_exists "fingerd.service"
disable_systemd_unit_if_exists "fingerd.socket"

# 2) inetd 설정 파일 조치 분기점
if [ -f "/etc/inetd.conf" ]; then
  if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
    cp -a /etc/inetd.conf "/etc/inetd.conf.bak_${TIMESTAMP}" 2>/dev/null || append_err "inetd.conf 백업 실패"
    sed -i -E '/^[[:space:]]*#/! s/^([[:space:]]*finger([[:space:]]|$))/#\1/' /etc/inetd.conf 2>/dev/null \
      || append_err "inetd.conf finger 라인 주석 처리 실패"
    MODIFIED=1
    restart_inetd_if_exists
  fi
fi

# 3) xinetd 설정 파일 조치 분기점
if [ -f "/etc/xinetd.d/finger" ]; then
  cp -a /etc/xinetd.d/finger "/etc/xinetd.d/finger.bak_${TIMESTAMP}" 2>/dev/null || append_err "xinetd finger 파일 백업 실패"
  if grep -nEv "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*="; then
    sed -i -E 's/^[[:space:]]*disable[[:space:]]*=.*/\tdisable = yes/I' /etc/xinetd.d/finger 2>/dev/null \
      || append_err "xinetd finger disable 라인 표준화(disable=yes) 실패"
    MODIFIED=1
    restart_xinetd_if_exists
  else
    if grep -qiE "^[[:space:]]*service[[:space:]]+finger([[:space:]]|\{)" /etc/xinetd.d/finger 2>/dev/null && \
       grep -qE "^[[:space:]]*\}[[:space:]]*$" /etc/xinetd.d/finger 2>/dev/null; then
      sed -i -E '0,/^[[:space:]]*\}[[:space:]]*$/ { s/^[[:space:]]*\}[[:space:]]*$/\tdisable = yes\n}/ }' /etc/xinetd.d/finger 2>/dev/null \
        || append_err "xinetd finger disable=yes 블록 삽입 실패"
      MODIFIED=1
      restart_xinetd_if_exists
    else
      echo -e "\n\tdisable = yes" >> /etc/xinetd.d/finger 2>/dev/null \
        || append_err "xinetd finger disable=yes 파일 끝 추가 실패"
      MODIFIED=1
      restart_xinetd_if_exists
    fi
  fi
fi

# 4) 조치 후 상태 검증 분기점
FINGER_ACTIVE=0
if [ -f "/etc/inetd.conf" ]; then
  if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
    FINGER_ACTIVE=1
  fi
fi

if [ -f "/etc/xinetd.d/finger" ]; then
  if ! grep -Ev "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes([[:space:]]|$)"; then
    FINGER_ACTIVE=1
  fi
fi

SYSTEMD_FINGER_BAD=0
if command -v systemctl >/dev/null 2>&1; then
  for u in finger.socket finger.service fingerd.service fingerd.socket; do
    if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
      if systemctl is-enabled "$u" 2>/dev/null | grep -qiE "enabled" || systemctl is-active "$u" 2>/dev/null | grep -qiE "active"; then
        SYSTEMD_FINGER_BAD=1
      fi
    fi
  done
fi

# 현재 설정 값 정보 수집 분기점
if [ -f "/etc/inetd.conf" ]; then
    INET_VAL=$(grep -E "^[[:space:]]*#?[[:space:]]*finger" /etc/inetd.conf | head -n 1)
    [ -n "$INET_VAL" ] && append_detail "inetd_status: $INET_VAL"
fi

if [ -f "/etc/xinetd.d/finger" ]; then
    XINET_VAL=$(grep -iE "disable[[:space:]]*=" /etc/xinetd.d/finger | head -n 1)
    [ -n "$XINET_VAL" ] && append_detail "xinetd_status: $XINET_VAL"
fi

if command -v systemctl >/dev/null 2>&1; then
  for u in finger.socket finger.service fingerd.service fingerd.socket; do
    if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
      S_EN=$(systemctl is-enabled "$u" 2>/dev/null || echo 'unknown')
      S_AC=$(systemctl is-active "$u" 2>/dev/null || echo 'unknown')
      append_detail "${u}: enabled=${S_EN}, active=${S_AC}"
    fi
  done
fi

# 최종 결과 판정 및 REASON_LINE 확정 분기점
if [ "$FINGER_ACTIVE" -eq 0 ] && [ "$SYSTEMD_FINGER_BAD" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="Finger 서비스를 중지 및 비활성화하고 관련 설정 파일의 불필요한 항목을 제거하여 조치를 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  REASON_LINE="일부 Finger 서비스가 여전히 활성화되어 있거나 설정 파일에 서비스 실행 옵션이 남아 있는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="${DETAIL_CONTENT}\n[Error Log]\n${ACTION_ERR_LOG}"
fi

# RAW_EVIDENCE 작성을 위한 JSON 구조 생성 분기점
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 데이터 이스케이프 처리 분기점
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 JSON 결과 출력 분기점
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF