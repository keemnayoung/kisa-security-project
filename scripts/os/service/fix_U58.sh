#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-58
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-58"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0
UNITS=("snmpd" "snmptrapd")
PROCS=("snmpd" "snmptrapd")
CHECK_COMMAND='systemctl is-active snmpd snmptrapd 2>/dev/null; systemctl is-enabled snmpd snmptrapd 2>/dev/null; systemctl list-unit-files 2>/dev/null | grep -E "^(snmpd|snmptrapd)\.service"; pgrep -a -x snmpd 2>/dev/null; pgrep -a -x snmptrapd 2>/dev/null; command -v snmpd 2>/dev/null; command -v snmptrapd 2>/dev/null'
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/usr/sbin/snmpd"

# 유틸리티 함수 정의
append_detail(){ [ -n "${1:-}" ] || return 0; DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }

# 권한 확인 및 환경 변수 설정
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="current_user: $(id -un)"
else
  HAS_SYSTEMCTL=0; command -v systemctl >/dev/null 2>&1 && HAS_SYSTEMCTL=1
  MODIFIED=0

  # 서비스 중지 및 비활성화 조치
  if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
    for u in "${UNITS[@]}"; do
      if systemctl list-unit-files 2>/dev/null | grep -qE "^${u}\.service"; then
        systemctl stop "$u" >/dev/null 2>&1 && MODIFIED=1
        systemctl disable "$u" >/dev/null 2>&1 && MODIFIED=1
        systemctl mask "$u" >/dev/null 2>&1 && MODIFIED=1
      fi
    done
  fi

  # 잔존 프로세스 강제 종료
  for p in "${PROCS[@]}"; do
    if pgrep -x "$p" >/dev/null 2>&1; then
      pkill -x "$p" >/dev/null 2>&1 || true
      sleep 1
      pgrep -x "$p" >/dev/null 2>&1 && pkill -9 -x "$p" >/dev/null 2>&1 || true
      MODIFIED=1
    fi
  done

  # 조치 후 최종 상태 수집
  STILL_BAD=0
  if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
    for u in "${UNITS[@]}"; do
      a="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
      e="$(systemctl is-enabled "$u" 2>/dev/null | head -n 1 | tr -d '\r')"
      [ -z "$e" ] && e="unknown"
      append_detail "unit_status($u): active=${a}, enabled=${e}"
      [ "$a" = "active" ] && STILL_BAD=1
      [ "$e" = "enabled" ] && STILL_BAD=1
    done
  else
    append_detail "systemctl: not_found"
  fi

  for p in "${PROCS[@]}"; do
    if pgrep -a -x "$p" >/dev/null 2>&1; then
      append_detail "process_status($p): running"
      STILL_BAD=1
    else
      append_detail "process_status($p): stopped"
    fi
  done

  SNMPD_BIN="$(command -v snmpd 2>/dev/null || true)"
  SNMPTRAPD_BIN="$(command -v snmptrapd 2>/dev/null || true)"
  [ -n "$SNMPD_BIN" ] && TARGET_FILE="$SNMPD_BIN"
  append_detail "binary_path: snmpd=${SNMPD_BIN:-none}, snmptrapd=${SNMPTRAPD_BIN:-none}"

  # 최종 판정
  if [ "$STILL_BAD" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="실행 중인 SNMP 서비스를 모두 중지하고 자동 시작되지 않도록 마스킹 처리하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="프로세스 종료 거부 또는 서비스 설정 해제 실패 등의 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
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

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF