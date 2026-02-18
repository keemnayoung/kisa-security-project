#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-39
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 NFS 서비스 비활성화
# @Description : 불필요한 NFS 서비스 사용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정 분기점
ID="U-39"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
(command -v systemctl >/dev/null 2>&1 && (
  systemctl list-unit-files 2>/dev/null | grep -Ei "^(nfs-server|nfs|rpcbind|rpc-statd|rpc-idmapd|nfs-mountd|nfs-idmapd|rpcbind)\.(service|socket)[[:space:]]" || echo "nfs_related_unit_files_not_found";
  for u in nfs-server.service nfs.service rpcbind.service rpcbind.socket rpc-statd.service rpc-idmapd.service nfs-mountd.service nfs-idmapd.service; do
    systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null | head -n 1) active=$(systemctl is-active "$u" 2>/dev/null | head -n 1)";
  done
)) || echo "systemctl_not_found";
[ -f /etc/exports ] && (grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports || echo "exports_empty") || echo "exports_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="systemd(NFS related services), /etc/exports"

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

get_is_enabled() {
  local unit="$1"
  local out
  out="$(systemctl is-enabled "$unit" 2>/dev/null | head -n 1)"
  [ -z "$out" ] && out="unknown"
  echo "$out"
}

get_is_active() {
  local unit="$1"
  local out
  out="$(systemctl is-active "$unit" 2>/dev/null | head -n 1)"
  [ -z "$out" ] && out="unknown"
  echo "$out"
}

unit_exists() {
  local unit="$1"
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]"
}

disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  unit_exists "$unit" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

# 권한 체크 및 초기화 분기점
if [ "$(id -u)" -ne 0 ]; then
  append_err "(주의) root 권한이 아니면 조치가 실패할 수 있습니다."
fi

# NFS 서비스 및 공유 설정 조치 수행 분기점
if ! command -v systemctl >/dev/null 2>&1; then
  IS_SUCCESS=0
  REASON_LINE="systemctl 명령을 사용할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="systemctl_not_found"
else
  UNITS=(
    "nfs-server.service"
    "nfs.service"
    "rpcbind.service"
    "rpcbind.socket"
    "rpc-statd.service"
    "rpc-idmapd.service"
    "nfs-mountd.service"
    "nfs-idmapd.service"
    "nfsdcld.service"
  )

  for u in "${UNITS[@]}"; do
    disable_systemd_unit_if_exists "$u"
  done

  EXPORTS_FILE="/etc/exports"
  if [ -f "$EXPORTS_FILE" ]; then
    EXPORTS_ACTIVE="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$EXPORTS_FILE" 2>/dev/null || true)"
    if [ -n "$EXPORTS_ACTIVE" ]; then
      sed -i -E 's/^([[:space:]]*[^#[:space:]].*)/# \1/' "$EXPORTS_FILE" 2>/dev/null \
        || append_err "/etc/exports 주석 처리 실패"
      MODIFIED=1
    fi
  fi

  # 조치 후 검증 및 상태 수집 분기점
  for u in "${UNITS[@]}"; do
    if unit_exists "$u"; then
      en="$(get_is_enabled "$u")"
      ac="$(get_is_active "$u")"
      append_detail "${u}: enabled=$en, active=$ac"

      echo "$en" | grep -qiE "^(enabled|enabled-runtime)$" && FAIL_FLAG=1
      echo "$ac" | grep -qiE "^(active|running|listening)$" && FAIL_FLAG=1
    fi
  done

  if [ -f "$EXPORTS_FILE" ]; then
    EXPORTS_AFTER="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$EXPORTS_FILE" 2>/dev/null || true)"
    if [ -n "$EXPORTS_AFTER" ]; then
      append_detail "/etc/exports: active_entries_exist"
      FAIL_FLAG=1
    else
      append_detail "/etc/exports: no_active_entries"
    fi
  else
    append_detail "/etc/exports: file_not_found"
  fi

  # 최종 판정 및 REASON_LINE 확정 분기점
  if [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="NFS 관련 서비스를 모두 중지 및 비활성화하고 공유 설정 파일의 유효 라인을 주석 처리하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="일부 NFS 서비스가 여전히 구동 중이거나 공유 설정 파일에 활성화된 항목이 남아 있는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
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