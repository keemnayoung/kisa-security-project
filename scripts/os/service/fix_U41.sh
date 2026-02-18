#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-41
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 automountd 제거
# @Description : automountd 서비스 데몬의 실행 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정 분기점
ID="U-41"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
(command -v systemctl >/dev/null 2>&1 && (
  systemctl list-unit-files 2>/dev/null | grep -Ei "^(autofs)\.(service|socket)[[:space:]]" || echo "autofs_unit_files_not_found";
  systemctl list-units --type=service 2>/dev/null | grep -Ei "autofs" || echo "no_running_autofs_service";
  systemctl list-units --type=socket 2>/dev/null | grep -Ei "autofs" || echo "no_running_autofs_socket";
  systemctl list-unit-files 2>/dev/null | grep -Ei "automount.*\.mount[[:space:]]" || echo "no_automount_mount_units";
  for u in autofs.service autofs.socket; do
    systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || true) active=$(systemctl is-active "$u" 2>/dev/null || true)";
  done
)) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="systemd(autofs.service, autofs.socket, automount*.mount)"

ACTION_ERR_LOG=""
MODIFIED=0
FAIL_FLAG=0

# 유틸리티 함수 정의 분기점
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

disable_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

disable_mount_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

get_is_enabled() {
  local u="$1"
  local out
  out="$(systemctl is-enabled "$u" 2>/dev/null || true)"
  out="$(printf "%s" "$out" | head -n 1 | tr -d '\r')"
  [ -z "$out" ] && out="unknown"
  echo "$out"
}

get_is_active() {
  local u="$1"
  local out
  out="$(systemctl is-active "$u" 2>/dev/null || true)"
  out="$(printf "%s" "$out" | head -n 1 | tr -d '\r')"
  [ -z "$out" ] && out="unknown"
  echo "$out"
}

# 권한 체크 분기점
if [ "$(id -u)" -ne 0 ]; then
  append_err "(주의) root 권한이 아니면 조치가 실패할 수 있습니다."
fi

# 조치 수행 분기점
if ! command -v systemctl >/dev/null 2>&1; then
  IS_SUCCESS=0
  REASON_LINE="systemctl 명령을 사용할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="systemctl_not_found"
else
  disable_unit_if_exists "autofs.socket"
  disable_unit_if_exists "autofs.service"

  AUTOMOUNT_MOUNTS="$(systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -E '^automount.*\.mount$' | head -n 50)"
  if [ -n "$AUTOMOUNT_MOUNTS" ]; then
    for m in $AUTOMOUNT_MOUNTS; do
      disable_mount_if_exists "$m"
    done
  fi

  # 조치 후 상태 검증 및 수집 분기점
  if systemctl list-unit-files 2>/dev/null | grep -qiE "^autofs\.socket[[:space:]]"; then
    en="$(get_is_enabled autofs.socket)"
    ac="$(get_is_active autofs.socket)"
    append_detail "autofs.socket: enabled=$en, active=$ac"
    [ "$en" = "enabled" ] && FAIL_FLAG=1
    [ "$ac" = "active" ] && FAIL_FLAG=1
  else
    append_detail "autofs.socket: not_installed"
  fi

  if systemctl list-unit-files 2>/dev/null | grep -qiE "^autofs\.service[[:space:]]"; then
    en="$(get_is_enabled autofs.service)"
    ac="$(get_is_active autofs.service)"
    append_detail "autofs.service: enabled=$en, active=$ac"
    [ "$en" = "enabled" ] && FAIL_FLAG=1
    [ "$ac" = "active" ] && FAIL_FLAG=1
  else
    append_detail "autofs.service: not_installed"
  fi

  if [ -n "$AUTOMOUNT_MOUNTS" ]; then
    for m in $AUTOMOUNT_MOUNTS; do
      en="$(get_is_enabled "$m")"
      ac="$(get_is_active "$m")"
      append_detail "${m}: enabled=$en, active=$ac"
      [ "$en" = "enabled" ] && FAIL_FLAG=1
      [ "$ac" = "active" ] && FAIL_FLAG=1
    done
  else
    append_detail "automount_mount_units: not_found"
  fi

  # 최종 판정 및 REASON_LINE 확정 분기점
  if [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="불필요한 automountd(autofs) 서비스 및 관련 유닛을 모두 중지하고 비활성화하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="automountd(autofs) 서비스 또는 관련 유닛이 여전히 활성화 상태인 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n[Error_Log]\n$ACTION_ERR_LOG"
fi

# 결과 데이터 구성 및 출력 분기점
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