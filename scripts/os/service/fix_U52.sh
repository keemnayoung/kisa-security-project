#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-52
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : Telnet 서비스 비활성화
# @Description : 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정 분기점
ID="U-52"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
ACTION_ERR_LOG=""
MODIFIED=0

# 유틸리티 함수 정의 분기점
add_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
add_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

unit_exists() {
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$1"
}

restart_svc_if_exists() {
  unit_exists "$1" || return 0
  systemctl restart "$1" >/dev/null 2>&1 || return 1
  return 0
}

disable_mask_if_exists() {
  unit_exists "$1" || return 0
  systemctl stop "$1" >/dev/null 2>&1 || true
  systemctl disable "$1" >/dev/null 2>&1 || true
  systemctl mask "$1" >/dev/null 2>&1 || true
  return 0
}

# 권한 확인 및 조치 수행 분기점
if [ "$(id -u)" -ne 0 ]; then
  REASON_LINE="root 권한이 아니어서 Telnet 서비스 비활성화를 적용할 수 없어 조치를 중단합니다."
  add_err "(주의) root 권한이 아니면 설정 파일 수정 및 서비스 중지/비활성화가 실패할 수 있습니다."
else
  # 1) inetd 기반 설정 조치 분기점
  INETD="/etc/inetd.conf"
  add_target "$INETD"
  if [ -f "$INETD" ] && grep -v '^[[:space:]]*#' "$INETD" 2>/dev/null | grep -qE '^[[:space:]]*telnet([[:space:]]|$)'; then
    cp -a "$INETD" "${INETD}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || add_err "$INETD 백업 실패"
    sed -i 's/^[[:space:]]*telnet[[:space:]]/#&/g' "$INETD" 2>/dev/null || add_err "$INETD telnet 주석 처리 실패"
    MODIFIED=1
    restart_svc_if_exists "inetd.service" || add_err "inetd.service 재시작 실패"
  fi

  # 2) xinetd 기반 설정 조치 분기점
  XINETD="/etc/xinetd.d/telnet"
  add_target "$XINETD"
  if [ -f "$XINETD" ]; then
    cp -a "$XINETD" "${XINETD}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    if grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
      sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)no\b/\1yes/I' "$XINETD" 2>/dev/null || add_err "$XINETD disable=yes 변경 실패"
      MODIFIED=1
    fi
    if ! grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*='; then
      printf "\n  disable = yes\n" >> "$XINETD" 2>/dev/null || add_err "$XINETD disable=yes 삽입 실패"
      MODIFIED=1
    fi
    restart_svc_if_exists "xinetd.service" || true
  fi

  # 3) systemd 기반 서비스 조치 분기점
  for u in telnet.socket telnet.service telnetd.socket telnetd.service; do
    disable_mask_if_exists "$u"
  done

  # 조치 후 최종 상태 데이터 수집 분기점
  INETD_VAL="not_found"
  if [ -f "$INETD" ]; then
    INETD_VAL=$(grep -E "^[[:space:]]*#?telnet([[:space:]]|$)" "$INETD" | head -n 1 | awk '{$1=$1;print}' || echo "no_telnet_line")
  fi
  add_detail "inetd_status: $INETD_VAL"

  XINETD_VAL="not_found"
  if [ -f "$XINETD" ]; then
    XINETD_VAL=$(grep -i "disable" "$XINETD" | awk '{$1=$1;print}' | tr '\n' ' ' || echo "no_disable_line")
  fi
  add_detail "xinetd_status: $XINETD_VAL"

  if command -v systemctl >/dev/null 2>&1; then
    for u in telnet.socket telnet.service telnetd.socket telnetd.service; do
      if unit_exists "$u"; then
        en=$(systemctl is-enabled "$u" 2>/dev/null)
        ac=$(systemctl is-active "$u" 2>/dev/null)
        add_detail "systemd_status($u): enabled=$en, active=$ac"
      fi
    done
    SSH_ACTIVE="$(systemctl is-active sshd.service 2>/dev/null || systemctl is-active ssh.service 2>/dev/null || echo inactive)"
    add_detail "ssh_status: $SSH_ACTIVE"
  fi

  # 조치 후 최종 검증 및 판정 분기점
  TELNET_BAD=0
  if [ -f "$INETD" ] && grep -v '^[[:space:]]*#' "$INETD" 2>/dev/null | grep -qE '^[[:space:]]*telnet([[:space:]]|$)'; then TELNET_BAD=1; fi
  if [ -f "$XINETD" ]; then
    if grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then TELNET_BAD=1; fi
    if ! grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*='; then TELNET_BAD=1; fi
  fi
  if command -v systemctl >/dev/null 2>&1; then
    for u in telnet.socket telnet.service telnetd.socket telnetd.service; do
      systemctl is-active --quiet "$u" 2>/dev/null && TELNET_BAD=1
      systemctl is-enabled "$u" 2>/dev/null | grep -qx "enabled" && TELNET_BAD=1
    done
  fi

  if [ "$TELNET_BAD" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="Telnet 서비스를 모든 관리 경로(inetd/xinetd/systemd)에서 중지하고 비활성화하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="설정 파일 수정 실패 또는 서비스 중지 거부 등의 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

# 결과 데이터 출력 분기점
[ -n "$ACTION_ERR_LOG" ] && add_detail "[Error_Log]\n$ACTION_ERR_LOG"
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/telnet, systemd(telnet*.socket/service)"
CHECK_COMMAND="grep telnet /etc/inetd.conf; cat /etc/xinetd.d/telnet; systemctl status telnet.socket"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF