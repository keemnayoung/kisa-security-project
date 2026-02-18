#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-40
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NFS 접근 통제
# @Description : NFS(Network File System)의 접근 통제 설정 적용 여부 점검
# @Criteria_Good : 접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우
# @Criteria_Bad : 접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-40"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/exports"
CHECK_COMMAND='
( command -v systemctl >/dev/null 2>&1 && (
    systemctl is-active nfs-server 2>/dev/null || true;
    systemctl is-enabled nfs-server 2>/dev/null || true;
    systemctl is-active rpcbind 2>/dev/null || true;
    systemctl is-enabled rpcbind 2>/dev/null || true;
  ) ) || echo "systemctl_not_found";
[ -f /etc/exports ] && (stat -c "%U %a %n" /etc/exports; grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports || echo "exports_empty") || echo "exports_not_found"
'
CHECK_COMMAND="$(echo "$CHECK_COMMAND" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"

DETAIL_CONTENT=""
REASON_LINE=""

# 취약 포인트를 설정값 형태로 누적(최종 reason 문장 구성용)
VULN_FLAGS=()
add_vuln() { [ -n "$1" ] && VULN_FLAGS+=("$1"); }

# 분기 1) systemctl 존재 여부에 따라 서비스 상태를 수집
NFS_ACTIVE="unknown"
NFS_ENABLED="unknown"
RPCBIND_ACTIVE="unknown"
RPCBIND_ENABLED="unknown"

if command -v systemctl >/dev/null 2>&1; then
  NFS_ACTIVE="$(systemctl is-active nfs-server 2>/dev/null | tr -d '[:space:]')"
  NFS_ENABLED="$(systemctl is-enabled nfs-server 2>/dev/null | tr -d '[:space:]')"
  RPCBIND_ACTIVE="$(systemctl is-active rpcbind 2>/dev/null | tr -d '[:space:]')"
  RPCBIND_ENABLED="$(systemctl is-enabled rpcbind 2>/dev/null | tr -d '[:space:]')"
else
  add_vuln "systemctl=not_found"
fi

EXPORT_LINES=""
OWNER=""
PERM=""

# 분기 2) /etc/exports 존재 여부에 따라 NFS 공유 설정 적용 여부를 판단
if [ ! -f "$TARGET_FILE" ]; then
  if [ "$NFS_ACTIVE" = "active" ] || [ "$NFS_ENABLED" = "enabled" ] || [ "$RPCBIND_ACTIVE" = "active" ] || [ "$RPCBIND_ENABLED" = "enabled" ]; then
    STATUS="FAIL"
    add_vuln "exports=not_found"
    add_vuln "nfs-server(active=${NFS_ACTIVE:-unknown},enabled=${NFS_ENABLED:-unknown})"
    add_vuln "rpcbind(active=${RPCBIND_ACTIVE:-unknown},enabled=${RPCBIND_ENABLED:-unknown})"
  else
    STATUS="PASS"
  fi

  DETAIL_CONTENT=$(
    printf "services:\n"
    printf "nfs-server: active=%s enabled=%s\n" "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}"
    printf "rpcbind: active=%s enabled=%s\n" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
    printf "exports:\n"
    printf "file=not_found\n"
  )
else
  # 분기 3) exports 파일의 소유자/권한(stat) 수집 성공 여부에 따라 추가 점검 수행
  OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null | tr -d '[:space:]')
  PERM=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null | tr -d '[:space:]')

  if [ -z "$OWNER" ] || [ -z "$PERM" ]; then
    STATUS="FAIL"
    add_vuln "exports_stat=failed"
  else
    if [ "$OWNER" != "root" ]; then
      add_vuln "owner=${OWNER}"
    fi
    if [ "$PERM" -gt 644 ] 2>/dev/null; then
      add_vuln "perm=${PERM}"
    fi
  fi

  EXPORT_LINES=$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$TARGET_FILE" 2>/dev/null || true)

  # 분기 4) exports 활성 라인 존재 여부에 따라 “미사용(비어있음)” 또는 “사용 중”으로 분기
  if [ -z "$EXPORT_LINES" ]; then
    if [ "$NFS_ACTIVE" = "active" ] || [ "$NFS_ENABLED" = "enabled" ] || [ "$RPCBIND_ACTIVE" = "active" ] || [ "$RPCBIND_ENABLED" = "enabled" ]; then
      STATUS="FAIL"
      add_vuln "exports=empty"
      add_vuln "nfs-server(active=${NFS_ACTIVE:-unknown},enabled=${NFS_ENABLED:-unknown})"
      add_vuln "rpcbind(active=${RPCBIND_ACTIVE:-unknown},enabled=${RPCBIND_ENABLED:-unknown})"
    fi

    DETAIL_CONTENT=$(
      printf "services:\n"
      printf "nfs-server: active=%s enabled=%s\n" "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}"
      printf "rpcbind: active=%s enabled=%s\n" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
      printf "exports:\n"
      printf "file=found\n"
      printf "owner=%s\n" "${OWNER:-unknown}"
      printf "perm=%s\n" "${PERM:-unknown}"
      printf "active_lines=empty\n"
    )
  else
    # 분기 5) 사용 중인 exports에서 접근 통제 관련 위험 설정(설정값)만 탐지
    if echo "$EXPORT_LINES" | grep -qE "([[:space:]]|^)\*([[:space:]]|$|\()"; then
      add_vuln "share_host=*"
    fi
    if echo "$EXPORT_LINES" | grep -qiE "no_root_squash"; then
      add_vuln "option=no_root_squash"
    fi
    ONLY_PATH_LINE=$(echo "$EXPORT_LINES" | awk '
      {
        line=$0;
        sub(/^[0-9]+:/,"",line);
        gsub(/^[ \t]+|[ \t]+$/,"",line);
        n=split(line,a,/[ \t]+/);
        if (n==1) print $0;
      }' | head -n 1)
    if [ -n "$ONLY_PATH_LINE" ]; then
      add_vuln "host_spec=missing"
    fi

    if [ "${#VULN_FLAGS[@]}" -gt 0 ]; then
      STATUS="FAIL"
    else
      STATUS="PASS"
    fi

    DETAIL_CONTENT=$(
      printf "services:\n"
      printf "nfs-server: active=%s enabled=%s\n" "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}"
      printf "rpcbind: active=%s enabled=%s\n" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
      printf "exports:\n"
      printf "file=found\n"
      printf "owner=%s\n" "${OWNER:-unknown}"
      printf "perm=%s\n" "${PERM:-unknown}"
      printf "active_lines(top5):\n"
      echo "$EXPORT_LINES" | head -n 5
    )
  fi
fi

# 분기 6) RAW_EVIDENCE.detail 첫 문장을 “설정값 기반”으로 재구성
# - PASS: 양호 요건에 해당하는 설정값을 한 문장으로
# - FAIL: 취약한 부분의 설정값만 한 문장으로
if [ "$STATUS" = "PASS" ]; then
  if [ ! -f "$TARGET_FILE" ]; then
    REASON_LINE="nfs-server(active=${NFS_ACTIVE:-unknown},enabled=${NFS_ENABLED:-unknown}), rpcbind(active=${RPCBIND_ACTIVE:-unknown},enabled=${RPCBIND_ENABLED:-unknown}), exports=not_found로 이 항목에 대해 양호합니다."
  else
    if [ -z "$EXPORT_LINES" ]; then
      REASON_LINE="nfs-server(active=${NFS_ACTIVE:-unknown},enabled=${NFS_ENABLED:-unknown}), rpcbind(active=${RPCBIND_ACTIVE:-unknown},enabled=${RPCBIND_ENABLED:-unknown}), exports=empty, owner=${OWNER:-unknown}, perm=${PERM:-unknown}로 이 항목에 대해 양호합니다."
    else
      REASON_LINE="owner=${OWNER:-unknown}, perm=${PERM:-unknown}, share_host!=*, option!=no_root_squash, host_spec=present로 이 항목에 대해 양호합니다."
    fi
  fi
else
  if [ "${#VULN_FLAGS[@]}" -gt 0 ]; then
    VULN_JOINED="$(printf "%s, " "${VULN_FLAGS[@]}")"
    VULN_JOINED="${VULN_JOINED%, }"
    REASON_LINE="${VULN_JOINED}로 이 항목에 대해 취약합니다."
  else
    REASON_LINE="판단에 필요한 설정값을 확인하지 못해 이 항목에 대해 취약합니다."
  fi
fi

# guide 키(자동 조치 위험 + 수동 조치 방법) 구성: 문장 단위 줄바꿈
GUIDE_LINE=$(
  printf "NFS 설정을 자동으로 변경하면 운영 중인 공유 경로와 접근 정책이 예기치 않게 바뀌어 서비스 장애 또는 접근 차단이 발생할 수 있어 수동 조치가 필요합니다.\n"
  printf "관리자가 직접 확인 후 /etc/exports에서 공유가 필요한 경로만 남기고 허용 호스트 또는 네트워크 대역만 지정하여 접근을 제한해 주시기 바랍니다.\n"
  printf "everyone(*) 공유가 있다면 이를 제거하고, no_root_squash가 있다면 제거하여 root_squash가 적용되도록 조치해 주시기 바랍니다.\n"
  printf "/etc/exports 파일 소유자는 root로, 권한은 644 이하(권장 644)로 설정해 주시기 바랍니다.\n"
  printf "NFS를 사용하지 않는다면 nfs-server 및 rpcbind 서비스를 중지하고 비활성화해 주시기 바랍니다."
)

# raw_evidence 구성
# - detail: 첫 줄(양호/취약 한 문장) + 다음 줄부터 현재 설정값(DETAIL_CONTENT)
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
