#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-41
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 automountd 제거
# @Description : automountd 서비스 데몬의 실행 여부 점검
# @Criteria_Good : automountd 서비스가 비활성화된 경우
# @Criteria_Bad :  automountd 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-41 불필요한 automountd 제거

# 기본 변수
ID="U-41"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="N/A"

# systemd 기반 autofs(service/socket) 상태 확인
CHECK_COMMAND='
(systemctl list-units --type=service --all 2>/dev/null | grep -E "^[[:space:]]*autofs\.service" || echo "autofs_service_not_listed");
(systemctl list-units --type=socket --all 2>/dev/null | grep -E "^[[:space:]]*autofs\.socket" || echo "autofs_socket_not_listed");
(systemctl is-active autofs.service 2>/dev/null || echo "autofs.service:unknown");
(systemctl is-enabled autofs.service 2>/dev/null || echo "autofs.service:unknown");
(systemctl is-active autofs.socket 2>/dev/null || echo "autofs.socket:unknown");
(systemctl is-enabled autofs.socket 2>/dev/null || echo "autofs.socket:unknown");
'

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE=""

# 실행 결과 수집
AUTOFS_SVC_ACTIVE="$(systemctl is-active autofs.service 2>/dev/null || echo unknown)"
AUTOFS_SVC_ENABLED="$(systemctl is-enabled autofs.service 2>/dev/null || echo unknown)"
AUTOFS_SOCK_ACTIVE="$(systemctl is-active autofs.socket 2>/dev/null || echo unknown)"
AUTOFS_SOCK_ENABLED="$(systemctl is-enabled autofs.socket 2>/dev/null || echo unknown)"

# DETAIL_CONTENT 구성
DETAIL_CONTENT="autofs.service: active=${AUTOFS_SVC_ACTIVE}, enabled=${AUTOFS_SVC_ENABLED}
autofs.socket: active=${AUTOFS_SOCK_ACTIVE}, enabled=${AUTOFS_SOCK_ENABLED}"

# 취약 가정 자동 조치
GUIDE_LINE="자동 조치:
autofs.service 및 autofs.socket에 대해 stop 후 disable을 적용하고, 필요 시 mask로 재활성화를 방지합니다.
주의사항: 
/etc/auto.* 또는 /etc/autofs* 구성에 의해 필요한 자동 마운트(NFS/Samba/특정 경로 자동 연결)가 중단될 수 있으므로 서비스 사용 여부를 먼저 확인해야 합니다.
기존 사용자 세션에서 자동 마운트에 의존하던 작업이 실패할 수 있으며, 적용 직후 관련 프로세스/업무 영향이 발생할 수 있으므로 운영 환경에서는 점검 창구 확보 후 적용하는 것이 안전합니다."

# 취약 판정: active 또는 enabled인 경우(재부팅/재기동 시 활성화 가능)
VULN=0
if [ "$AUTOFS_SVC_ACTIVE" = "active" ] || [ "$AUTOFS_SVC_ENABLED" = "enabled" ] || \
   [ "$AUTOFS_SOCK_ACTIVE" = "active" ] || [ "$AUTOFS_SOCK_ENABLED" = "enabled" ]; then
  VULN=1
fi

# 취약 판정
if [ "$VULN" -eq 1 ]; then
  STATUS="FAIL"
  BAD_PARTS=""
  if [ "$AUTOFS_SVC_ACTIVE" = "active" ] || [ "$AUTOFS_SVC_ENABLED" = "enabled" ]; then
    BAD_PARTS="autofs.service(active=${AUTOFS_SVC_ACTIVE}, enabled=${AUTOFS_SVC_ENABLED})"
  fi
  if [ "$AUTOFS_SOCK_ACTIVE" = "active" ] || [ "$AUTOFS_SOCK_ENABLED" = "enabled" ]; then
    if [ -n "$BAD_PARTS" ]; then
      BAD_PARTS="${BAD_PARTS} 및 autofs.socket(active=${AUTOFS_SOCK_ACTIVE}, enabled=${AUTOFS_SOCK_ENABLED})"
    else
      BAD_PARTS="autofs.socket(active=${AUTOFS_SOCK_ACTIVE}, enabled=${AUTOFS_SOCK_ENABLED})"
    fi
  fi
  REASON_LINE="${BAD_PARTS}로 설정되어 있어 이 항목에 대해 취약합니다."
else
  # 양호 판정
  STATUS="PASS"
  REASON_LINE="autofs.service(active=${AUTOFS_SVC_ACTIVE}, enabled=${AUTOFS_SVC_ENABLED}) 및 autofs.socket(active=${AUTOFS_SOCK_ACTIVE}, enabled=${AUTOFS_SOCK_ENABLED})로 설정되어 있어 이 항목에 대해 양호합니다."
fi

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
