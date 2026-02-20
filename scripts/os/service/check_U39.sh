#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-39
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 NFS 서비스 비활성화
# @Description : 불필요한 NFS 서비스 사용 여부 점검
# @Criteria_Good : 불필요한 NFS 서비스 관련 데몬이 비활성화된 경우
# @Criteria_Bad : 불필요한 NFS 서비스 관련 데몬이 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-39"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="systemd(nfs-server, rpcbind 등), /etc/exports"

CHECK_COMMAND='
systemctl list-units --type=service 2>/dev/null | egrep -i "(nfs|rpcbind)" || echo "no_nfs_related_services";
for u in nfs-server.service rpcbind.service rpcbind.socket nfs-mountd.service nfs-idmapd.service rpc-statd.service nfsdcld.service; do
  systemctl is-enabled "$u" 2>/dev/null || true;
  systemctl is-active "$u" 2>/dev/null || true;
done;
[ -f /etc/exports ] && (grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports || echo "exports_empty") || echo "exports_not_found"
'

DETAIL_CONTENT=""
REASON_LINE=""

# 점검 대상 유닛(서비스/소켓 포함)
UNITS=(
  "nfs-server.service"
  "rpcbind.service"
  "rpcbind.socket"
  "nfs-mountd.service"
  "nfs-idmapd.service"
  "rpc-statd.service"
  "nfsdcld.service"
)

# systemctl 출력값에서 disabled/inactive가 나와도 exit code 때문에 unknown이 덧붙는 현상을 방지
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

# 현재 설정값(항상 출력)과, 판정 사유(양호/취약용)를 분리 관리
CURRENT_LINES=()
VULN_LINES=()
GOOD_LINES=()

add_current() { [ -n "$1" ] && CURRENT_LINES+=("$1"); }
add_vuln()    { [ -n "$1" ] && VULN_LINES+=("$1"); }
add_good()    { [ -n "$1" ] && GOOD_LINES+=("$1"); }

# systemctl 사용 불가한 경우는 정확한 판정이 어려우므로 취약으로 간주하고, 현재값에 사유를 남김
if ! command -v systemctl >/dev/null 2>&1; then
  STATUS="FAIL"
  add_current "systemctl=not_found"
  add_vuln "systemctl=not_found"
else
  # 유닛별 활성/자동시작 상태를 수집하고, 활성(active/running/listening) 또는 enabled면 취약 신호로 분류
  for u in "${UNITS[@]}"; do
    en="$(get_is_enabled "$u")"
    ac="$(get_is_active "$u")"
    add_current "systemd:$u is-enabled=$en is-active=$ac"

    if echo "$ac" | grep -qiE "^(active|running|listening)$"; then
      STATUS="FAIL"
      add_vuln "systemd:$u is-active=$ac"
      continue
    fi

    if echo "$en" | grep -qiE "^(enabled|enabled-runtime)$"; then
      STATUS="FAIL"
      add_vuln "systemd:$u is-enabled=$en"
      continue
    fi

    add_good "systemd:$u is-enabled=$en is-active=$ac"
  done
fi

# /etc/exports는 주석/공백 제외 라인이 있으면 구성 흔적으로 판단
if [ -f /etc/exports ]; then
  EXPORTS_ACTIVE="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports 2>/dev/null || true)"
  if [ -n "$EXPORTS_ACTIVE" ]; then
    STATUS="FAIL"
    add_current "/etc/exports(active_lines)=$(echo "$EXPORTS_ACTIVE" | head -n 5 | tr '\n' '; ' | sed 's/; $//')"
    add_vuln "/etc/exports(active_lines)=$(echo "$EXPORTS_ACTIVE" | head -n 5 | tr '\n' '; ' | sed 's/; $//')"
  else
    add_current "/etc/exports=exports_empty"
    add_good "/etc/exports=exports_empty"
  fi
else
  add_current "/etc/exports=exports_not_found"
  add_good "/etc/exports=exports_not_found"
fi

# DETAIL_CONTENT 구성
DETAIL_CONTENT="$(printf "%s\n" "${CURRENT_LINES[@]}")"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# REASON_LINE 구성
if [ "$STATUS" = "FAIL" ]; then
  VULN_COUNT="${#VULN_LINES[@]}"
  REASON_LINE="NFS 관련 서비스/소켓 ${VULN_COUNT}건이 활성 또는 자동 시작 상태로 이 항목에 대해 취약합니다."
else
  REASON_LINE="모든 NFS 관련 서비스 및 /etc/exports가 비활성화 상태로 이 항목에 대해 양호합니다."
fi

# 취약 가정 자동 조치
GUIDE_LINE=$(cat <<'EOF'
자동 조치:
NFS 관련 유닛이 존재하면 systemctl stop <unit> 후 systemctl disable <unit> 및 systemctl mask <unit>를 적용합니다.
/etc/exports에 주석/공백이 아닌 라인이 있으면 해당 라인을 주석 처리하여 공유 구성을 비활성화합니다.
주의사항: 
NFS를 실제로 사용 중인 서버에서 서비스를 중지하거나 exports 구성을 변경하면 업무 서비스(공유 디렉터리, 백업, 배치 등)가 중단될 수 있습니다.
rpcbind/socket 비활성화는 NFS 외 RPC 기반 기능에도 영향을 줄 수 있으므로 사전 영향도 확인이 필요합니다.
mask 적용은 향후 정상 재가동을 막을 수 있으므로 운영 정책에 따라 disable까지만 적용할지 검토가 필요합니다.
/etc/exports 변경 전 파일 백업 및 변경 후 점검(exportfs/서비스 상태 확인)을 수행하는 것이 안전합니다.
EOF
)

# raw_evidence 구성
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

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
