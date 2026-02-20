#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.2.0
# @Author: 권순형
# @Last Updated: 2026-02-17
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-64
# @Category    : 패치 관리
# @Platform    : Rocky Linux (RHEL 계열 우선)
# @Importance  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고사항 적용
# @Description : 시스템에서 최신 패치 적용 여부(EOL/보안업데이트/커널) 점검
# ============================================================================

# 기본 변수
ITEM_ID="U-64"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="/etc/os-release"

CHECK_COMMAND='cat /etc/os-release 2>/dev/null; uname -r; (command -v dnf >/dev/null && dnf -q check-update --refresh 2>/dev/null || true); (command -v dnf >/dev/null && dnf -q updateinfo list --security 2>/dev/null || true); (rpm -q kernel 2>/dev/null || true)'

# OS 정보 수집
OS_NAME="unknown"; OS_VERSION="unknown"; OS_ID="unknown"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_NAME="${NAME:-unknown}"
  OS_VERSION="${VERSION_ID:-unknown}"
  OS_ID="${ID:-unknown}"
fi

KERNEL_RUNNING="$(uname -r 2>/dev/null | tr -d ' ')"
EOL_STATUS="UNKNOWN"

# EOL 판별
case "$OS_ID" in
  rocky)  [[ "$OS_VERSION" =~ ^(8|9|10) ]] && EOL_STATUS="SUPPORTED" || EOL_STATUS="UNKNOWN" ;;
  centos) EOL_STATUS="EOL" ;;
  ubuntu) [[ "$OS_VERSION" =~ ^(14\.04|16\.04|18\.04)$ ]] && EOL_STATUS="EOL" || EOL_STATUS="SUPPORTED" ;;
  rhel)   [[ "$OS_VERSION" =~ ^(6|7)$ ]] && EOL_STATUS="EOL" || EOL_STATUS="SUPPORTED" ;;
  *)      EOL_STATUS="UNKNOWN" ;;
esac

# 패치/보안업데이트/커널 상태 수집
PKG_MGR="UNKNOWN"
UPDATES_EXIST="UNKNOWN"
SEC_UPDATES_EXIST="UNKNOWN"
KERNEL_LATEST_INSTALLED="unknown"
KERNEL_NEED_REBOOT="UNKNOWN"

if command -v dnf >/dev/null 2>&1; then
  PKG_MGR="DNF"

  dnf -q check-update --refresh >/dev/null 2>&1
  rc=$?
  [ $rc -eq 100 ] && UPDATES_EXIST="YES"
  [ $rc -eq 0 ] && UPDATES_EXIST="NO"

  if dnf -q updateinfo list --security >/dev/null 2>&1; then
    sec_out="$(dnf -q updateinfo list --security 2>/dev/null | awk 'NF{c++} END{print c+0}')"
    [ "$sec_out" -gt 0 ] && SEC_UPDATES_EXIST="YES" || SEC_UPDATES_EXIST="NO"
  fi

  KERNEL_LATEST_INSTALLED="$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -1 | tr -d ' ')"
  if [ -n "$KERNEL_LATEST_INSTALLED" ] && [ "$KERNEL_LATEST_INSTALLED" != "unknown" ] && [ -n "$KERNEL_RUNNING" ]; then
    [ "$KERNEL_RUNNING" = "$KERNEL_LATEST_INSTALLED" ] && KERNEL_NEED_REBOOT="NO" || KERNEL_NEED_REBOOT="YES"
  fi
fi

# 상태 판정
FAIL_CAUSE="NONE"
if [ "$EOL_STATUS" != "SUPPORTED" ]; then
  STATUS="FAIL"; FAIL_CAUSE="EOL"
elif [ "$SEC_UPDATES_EXIST" = "YES" ]; then
  STATUS="FAIL"; FAIL_CAUSE="SEC_UPDATES"
elif [ "$SEC_UPDATES_EXIST" = "UNKNOWN" ] && [ "$UPDATES_EXIST" = "YES" ]; then
  STATUS="FAIL"; FAIL_CAUSE="UPDATES"
elif [ "$KERNEL_NEED_REBOOT" = "YES" ]; then
  STATUS="FAIL"; FAIL_CAUSE="KERNEL_REBOOT"
else
  STATUS="PASS"; FAIL_CAUSE="NONE"
fi

# DETAIL_CONTENT 구성
DETAIL_CONTENT="os_name=${OS_NAME} os_id=${OS_ID} os_version=${OS_VERSION}"$'\n'
DETAIL_CONTENT+="kernel_running=${KERNEL_RUNNING:-unknown}"$'\n'
DETAIL_CONTENT+="eol_status=${EOL_STATUS}"$'\n'
DETAIL_CONTENT+="pkg_mgr=${PKG_MGR} updates_exist=${UPDATES_EXIST} security_updates_exist=${SEC_UPDATES_EXIST}"$'\n'
DETAIL_CONTENT+="kernel_latest_installed=${KERNEL_LATEST_INSTALLED:-unknown} kernel_need_reboot=${KERNEL_NEED_REBOOT}"

# reason 구성
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="eol_status=${EOL_STATUS}, security_updates_exist=${SEC_UPDATES_EXIST}, updates_exist=${UPDATES_EXIST}, kernel_need_reboot=${KERNEL_NEED_REBOOT}로 확인되어 이 항목에 대해 양호합니다."
else
  case "$FAIL_CAUSE" in
    EOL)
      REASON_LINE="eol_status=${EOL_STATUS}로 확인되어 이 항목에 대해 취약합니다."
      ;;
    SEC_UPDATES)
      REASON_LINE="security_updates_exist=${SEC_UPDATES_EXIST}로 확인되어 이 항목에 대해 취약합니다."
      ;;
    UPDATES)
      REASON_LINE="security_updates_exist=${SEC_UPDATES_EXIST}, updates_exist=${UPDATES_EXIST}로 확인되어 이 항목에 대해 취약합니다."
      ;;
    KERNEL_REBOOT)
      REASON_LINE="kernel_need_reboot=${KERNEL_NEED_REBOOT} (kernel_running=${KERNEL_RUNNING}, kernel_latest_installed=${KERNEL_LATEST_INSTALLED})로 확인되어 이 항목에 대해 취약합니다."
      ;;
    *)
      REASON_LINE="패치 상태 식별 값이 불충분하여 이 항목에 대해 취약합니다."
      ;;
  esac
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE="이 항목에 대해서 패치 적용 과정에서 서비스 중단, 의존성 변경, 커널 업데이트 후 재부팅이 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 서비스 영향도를 검토하고 점검 창을 확보한 뒤 벤더 권고 보안 패치를 적용하며 EOL인 경우 상위 OS 버전으로 업그레이드하고 커널 업데이트 적용을 위해 재부팅까지 수행해 주시기 바랍니다."

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

# JSON escape 처리(따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ITEM_ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
