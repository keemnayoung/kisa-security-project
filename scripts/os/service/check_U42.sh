#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-42
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 RPC 서비스 비활성화
# @Description : 불필요한 RPC 서비스의 실행 여부 점검
# @Criteria_Good : 불필요한 RPC 서비스가 비활성화된 경우
# @Criteria_Bad : 불필요한 RPC 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-42"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="N/A"

# 불필요한 RPC 서비스
UNNEEDED_RPC_SERVICES=(
  "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd"
  "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad"
  "kcms_server" "cachefsd"
)

# 점검 명령
CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null ) || echo "inetd_conf_not_found";
( [ -d /etc/xinetd.d ] && for f in /etc/xinetd.d/*; do [ -f "$f" ] && (echo "### $f"; grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null); done | head -n 300 ) || echo "xinetd_dir_not_found";
(command -v systemctl >/dev/null 2>&1 && (
  systemctl list-unit-files --type=service 2>/dev/null | head -n 200;
  systemctl list-units --type=service --all 2>/dev/null | head -n 200
)) || echo "systemctl_not_found"
'

DETAIL_CONTENT=""
REASON_LINE=""

# 현재 설정값
INETD_FINDINGS=()
XINETD_FINDINGS=()
SYSTEMD_FINDINGS=()

# 취약한 설정
VULN_SETTINGS=()

# inetd 기반 점검: /etc/inetd.conf에서 불필요 서비스 라인이 주석 제외 상태로 존재하는지 확인
if [ -f "/etc/inetd.conf" ]; then
  for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
    HIT=$(grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*${svc}([[:space:]]|$)" | head -n 20)
    if [ -n "$HIT" ]; then
      INETD_FINDINGS+=("${svc}:\n${HIT}")
      VULN_SETTINGS+=("inetd(/etc/inetd.conf)에서 ${svc} 라인이 주석 제외로 존재")
    fi
  done
else
  INETD_FINDINGS+=("inetd_conf_not_found")
fi

# xinetd 기반 점검: /etc/xinetd.d/*에서 service <name> + disable=no 인 경우 취약
if [ -d "/etc/xinetd.d" ]; then
  while IFS= read -r conf; do
    [ -f "$conf" ] || continue
    for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*service[[:space:]]+${svc}([[:space:]]|$)"; then
        DIS_LINE=$(grep -nEv "^[[:space:]]*#" "$conf" 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=" | head -n 1)
        [ -z "$DIS_LINE" ] && DIS_LINE="disable_setting_not_found"
        XINETD_FINDINGS+=("file=${conf} service=${svc} ${DIS_LINE}")

        if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
          VULN_SETTINGS+=("xinetd(${conf})에서 ${svc} disable=no")
        fi
      fi
    done
  done < <(find /etc/xinetd.d -maxdepth 1 -type f 2>/dev/null | sort)

  if [ "${#XINETD_FINDINGS[@]}" -eq 0 ]; then
    XINETD_FINDINGS+=("no_unneeded_rpc_xinetd_service_blocks")
  fi
else
  XINETD_FINDINGS+=("xinetd_dir_not_found")
fi

# systemd 기반 점검: 불필요 서비스에 해당하는 유닛이 enabled 또는 active 인 경우 취약
if command -v systemctl >/dev/null 2>&1; then
  for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
    unit="${svc}.service"
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
      EN=$(systemctl is-enabled "$unit" 2>/dev/null || echo "unknown")
      AC=$(systemctl is-active "$unit" 2>/dev/null || echo "unknown")
      SYSTEMD_FINDINGS+=("${unit}: enabled=${EN}, active=${AC}")

      if [ "$EN" = "enabled" ] || [ "$AC" = "active" ]; then
        VULN_SETTINGS+=("systemd에서 ${unit} enabled=${EN} 또는 active=${AC}")
      fi
    fi
  done

  if [ "${#SYSTEMD_FINDINGS[@]}" -eq 0 ]; then
    SYSTEMD_FINDINGS+=("no_unneeded_rpc_systemd_units_found")
  fi
else
  SYSTEMD_FINDINGS+=("systemctl_not_found")
fi

# DETAIL_CONTENT 구성
DETAIL_CONTENT=$(
  printf "inetd_current_settings:\n"
  printf "%s\n\n" "${INETD_FINDINGS[@]}"
  printf "xinetd_current_settings:\n"
  printf "%s\n\n" "${XINETD_FINDINGS[@]}"
  printf "systemd_current_settings:\n"
  printf "%s\n" "${SYSTEMD_FINDINGS[@]}"
)

# 취약 가정 자동 조치
GUIDE_LINE=$(cat <<'EOF'
자동 조치: 
1) inetd 사용 시 /etc/inetd.conf에서 불필요 RPC 서비스 라인을 주석 처리하고(서비스명 기준) inetd를 재시작합니다.
2) xinetd 사용 시 /etc/xinetd.d/*에서 해당 service 블록의 disable 값을 yes로 변경하거나, disable 항목이 없다면 disable=yes를 삽입한 뒤 xinetd를 재시작합니다.
3) systemd 사용 시 해당 유닛이 존재하면 stop 후 disable 및 필요 시 mask 처리합니다.
주의사항: 
NFS 등에서 rpcbind/rpc.statd 계열이 의존될 수 있어, 자동으로 중지/비활성화하면 파일 공유/마운트/상태 동기화 기능에 영향이 생길 수 있습니다.
또한 /etc/xinetd.d 내 백업 파일을 같은 디렉터리에 남기면 점검 로직이 백업 파일까지 포함해 오탐(Fail)을 유발할 수 있으므로 백업은 별도 경로에 보관하는 방식이 안전합니다.
EOF
)

# 종합 판정 및 RAW_EVIDENCE.detail 문구 구성
if [ "${#VULN_SETTINGS[@]}" -gt 0 ]; then
  STATUS="FAIL"
  # 취약한 부분의 설정값만 “이유”로 노출(여러 개면 줄바꿈으로 나열)
  REASON_SETTINGS="inetd·xinetd·systemd에서 불필요 RPC 서비스가 활성 상태가 확인되어 이 항목에 대해 취약합니다."
  REASON_LINE="${REASON_SETTINGS}로 이 항목에 대해 취약합니다."
else
  STATUS="PASS"
  REASON_LINE="inetd·xinetd·systemd에서 불필요 RPC 서비스가 활성 상태(주석 제외 라인, disable=no, enabled/active)로 확인되지 않아 이 항목에 대해 양호합니다."
fi

# RAW_EVIDENCE 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리(따옴표, 줄바꿈)
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
