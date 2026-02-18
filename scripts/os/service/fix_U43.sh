#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-43
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NIS, NIS+ 점검
# @Description : 안전하지 않은 NIS 서비스의 비활성화, 안전한 NIS+ 서비스의 활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정 분기점
ID="U-43"
CATEGORY="서비스 관리"
TITLE="NIS, NIS+ 점검"
IMPORTANCE="상"
TARGET_FILE="systemd(NIS related services)"
STATUS="PASS"
ACTION_LOG=""
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

NIS_UNITS=("ypserv.service" "ypbind.service" "ypxfrd.service" "rpc.yppasswdd.service" "rpc.ypupdated.service")
CHECK_COMMAND="systemctl is-active/is-enabled (NIS units)"

# 조치 수행 분기점
if ! command -v systemctl >/dev/null 2>&1; then
  STATUS="ERROR"
  ACTION_LOG="systemctl 명령을 사용할 수 없어 NIS 관련 서비스 조치를 수행하지 못했습니다."
else
  for unit in "${NIS_UNITS[@]}"; do
    en_state="$(systemctl is-enabled "$unit" 2>/dev/null | tr -d '\r')"
    ac_state="$(systemctl is-active "$unit" 2>/dev/null | tr -d '\r')"

    if [ "$ac_state" = "active" ]; then
      systemctl stop "$unit" >/dev/null 2>&1 || ACTION_LOG="${ACTION_LOG}${unit} 중지 실패; "
    fi

    if [ "$en_state" = "enabled" ]; then
      systemctl disable "$unit" >/dev/null 2>&1 || ACTION_LOG="${ACTION_LOG}${unit} 비활성화 실패; "
    fi
  done

  # 조치 후 상태 검증 및 수집 분기점
  AFTER_ACTIVE=""
  AFTER_ENABLED=""
  SUMMARY_DETAIL=""

  for unit in "${NIS_UNITS[@]}"; do
    ac_after="$(systemctl is-active "$unit" 2>/dev/null | tr -d '\r')"
    en_after="$(systemctl is-enabled "$unit" 2>/dev/null | tr -d '\r')"
    
    # 설정 값 정보 수집
    if [ -z "$ac_after" ]; then ac_after="not_found"; fi
    if [ -z "$en_after" ]; then en_after="not_found"; fi
    
    SUMMARY_DETAIL="${SUMMARY_DETAIL}${unit}: enabled=${en_after}, active=${ac_after}\n"

    if [ "$ac_after" = "active" ]; then AFTER_ACTIVE+="${unit} "; fi
    if [ "$en_after" = "enabled" ]; then AFTER_ENABLED+="${unit} "; fi
  done

  if [ -n "$AFTER_ACTIVE" ] || [ -n "$AFTER_ENABLED" ]; then
    STATUS="FAIL"
  else
    STATUS="PASS"
  fi
fi

# 최종 REASON_LINE 및 DETAIL_CONTENT 확정 분기점
REASON_LINE=""
DETAIL_CONTENT="$SUMMARY_DETAIL"

if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="NIS 관련 서비스를 모두 중지하고 비활성화하여 조치를 완료하여 이 항목에 대해 양호합니다."
elif [ "$STATUS" = "FAIL" ]; then
  REASON_LINE="일부 NIS 서비스가 여전히 활성화(enabled)되어 있거나 실행(active) 중인 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
else
  REASON_LINE="$ACTION_LOG"
fi

# 에러 로그가 있을 경우 DETAIL 하단에 추가
if [ -n "$ACTION_LOG" ]; then
  DETAIL_CONTENT="${DETAIL_CONTENT}[Error_Log] ${ACTION_LOG}"
fi

# 결과 데이터 구성 및 출력 분기점
json_escape() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command":"$(json_escape "$CHECK_COMMAND")",
  "detail":"$(json_escape "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(json_escape "$TARGET_FILE")"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

echo ""
cat << EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF