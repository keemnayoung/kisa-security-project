#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-43
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NIS, NIS+ 점검
# @Description : 안전하지 않은 NIS 서비스의 비활성화, 안전한 NIS+ 서비스의 활성화 여부 점검
# @Criteria_Good : NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우
# @Criteria_Bad : NIS 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-43"
CATEGORY="서비스 관리"
TITLE="NIS, NIS+ 점검"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

NIS_UNITS=("ypserv.service" "ypbind.service" "ypxfrd.service" "rpc.yppasswdd.service" "rpc.ypupdated.service")

CHECK_COMMAND="systemctl list-units --type=service | grep -E 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated'; systemctl is-active/is-enabled <unit>"

ACTIVE_FOUND=""
ENABLED_FOUND=""
FOUND_ANY=0

# 분기 1) systemctl 사용 불가 시: 점검 자체 불가(ERROR)
if ! command -v systemctl >/dev/null 2>&1; then
  STATUS="ERROR"
  ACTIVE_FOUND="systemctl_not_found"
  ENABLED_FOUND="systemctl_not_found"
else
  # 분기 2) active(현재 실행) 탐지: list-units 기반(현재 떠있는 서비스 위주)
  ACTIVE_LIST="$(systemctl list-units --type=service 2>/dev/null | awk '{print $1}' | grep -E 'ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated' | tr '\n' ' ' | sed 's/[[:space:]]\+$//')"
  if [ -n "$ACTIVE_LIST" ]; then
    ACTIVE_FOUND="$ACTIVE_LIST"
    FOUND_ANY=1
  else
    ACTIVE_FOUND="none"
  fi

  # 분기 3) enabled(부팅 자동 시작) 탐지: is-enabled 기반(현재 꺼져있어도 enabled면 취약)
  for unit in "${NIS_UNITS[@]}"; do
    en_state="$(systemctl is-enabled "$unit" 2>/dev/null | tr -d '\r')"
    if [ "$en_state" = "enabled" ]; then
      ENABLED_FOUND+="${unit} "
      FOUND_ANY=1
    fi
  done
  ENABLED_FOUND="$(echo "$ENABLED_FOUND" | sed 's/[[:space:]]\+$//')"
  [ -z "$ENABLED_FOUND" ] && ENABLED_FOUND="none"

  # 분기 4) active 또는 enabled가 하나라도 있으면 FAIL
  if [ "$FOUND_ANY" -eq 1 ]; then
    STATUS="FAIL"
  else
    STATUS="PASS"
  fi
fi

# DETAIL_CONTENT: 양호/취약 무관하게 "현재 설정 값"만 출력
DETAIL_CONTENT="active: ${ACTIVE_FOUND}
enabled: ${ENABLED_FOUND}"

# detail의 "이유"는 가이드 문구 없이 실제 설정값만으로 자연스럽게 구성
DETAIL_PREFIX=""
if [ "$STATUS" = "PASS" ]; then
  DETAIL_PREFIX="active: none, enabled: none 로 설정되어 있어 이 항목에 대해 양호합니다."
elif [ "$STATUS" = "FAIL" ]; then
  # 취약 시에는 취약한 부분의 설정만 이유로 노출
  if [ "${ACTIVE_FOUND}" != "none" ] && [ "${ENABLED_FOUND}" != "none" ]; then
    DETAIL_PREFIX="active: ${ACTIVE_FOUND}, enabled: ${ENABLED_FOUND} 로 설정되어 있어 이 항목에 대해 취약합니다."
  elif [ "${ACTIVE_FOUND}" != "none" ]; then
    DETAIL_PREFIX="active: ${ACTIVE_FOUND} 로 설정되어 있어 이 항목에 대해 취약합니다."
  else
    DETAIL_PREFIX="enabled: ${ENABLED_FOUND} 로 설정되어 있어 이 항목에 대해 취약합니다."
  fi
else
  DETAIL_PREFIX="systemctl 사용 불가로 현재 설정 값을 확인하지 못해 이 항목에 대해 판단할 수 없습니다."
fi

# guide: 취약일 때를 가정한 "자동 조치 방법 + 주의사항" (조치 스크립트 로직 기반)
GUIDE_LINE="자동 조치: 
탐지된 NIS 관련 서비스 유닛에 대해 systemctl stop <unit> 으로 중지하고 systemctl disable <unit> 으로 부팅 자동 시작을 해제합니다.
조치 후 systemctl is-active/is-enabled 재점검으로 active/enabled 잔존 여부를 확인합니다.
주의사항: 
NIS를 실제로 사용하는 환경에서는 중지/비활성화 시 계정/인증 및 이름서비스(디렉터리/맵) 연동이 끊길 수 있어 로그인/권한 확인 등에 영향이 발생할 수 있으므로 사전에 사용 여부와 대체 서비스 적용 여부를 확인해야 합니다."

escape_json_str() {
  # 백슬래시 -> \\ , 줄바꿈 -> \n , 따옴표 -> \"
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${DETAIL_PREFIX}\n${DETAIL_CONTENT}")",
  "guide":"$(escape_json_str "$GUIDE_LINE")",
  "target_file":"$(escape_json_str "$TARGET_FILE")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# JSON 출력 직전 빈 줄(프로젝트 규칙)
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF
