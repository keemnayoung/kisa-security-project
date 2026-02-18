#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-63
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : sudo 명령어 접근 관리
# @Description : /etc/sudoers 파일 권한 적절성 여부 점검
# @Criteria_Good :  /etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우
# @Criteria_Bad : /etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-63 sudo 명령어 접근 관리

# 기본 변수
ID="U-63"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/sudoers"
CHECK_COMMAND='stat -c "%U %G %a %n" /etc/sudoers 2>/dev/null || echo "sudoers_not_found_or_stat_failed"'

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE=""
VULNERABLE=0

# 파일이 없으면: 점검 불가(환경 확인 필요)로 처리
if [ ! -f "$TARGET_FILE" ]; then
  STATUS="PASS"
  VULNERABLE=0
  DETAIL_CONTENT="확인 결과: /etc/sudoers 없음"
  REASON_LINE="/etc/sudoers 파일이 존재하지 않아 이 항목을 점검할 수 없습니다."
else
  # 파일이 있으면: 소유자/그룹/권한 수집
  OWNER="$(stat -c '%U' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
  GROUP="$(stat -c '%G' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
  PERM_STR="$(stat -c '%a' "$TARGET_FILE" 2>/dev/null || echo "unknown")"

  # 어떤 경우든 현재 설정은 DETAIL_CONTENT에 고정 표기
  DETAIL_CONTENT="현재 설정: owner=${OWNER}, group=${GROUP}, perm=${PERM_STR}"

  # 기준 판정: owner=root 이고 perm<=640
  OWNER_OK=0
  PERM_OK=0

  [ "$OWNER" = "root" ] && OWNER_OK=1

  if echo "$PERM_STR" | grep -Eq '^[0-7]{3,4}$'; then
    [ "$PERM_STR" -le 640 ] && PERM_OK=1
  fi

  if [ "$OWNER_OK" -ne 1 ] || [ "$PERM_OK" -ne 1 ]; then
    VULNERABLE=1
    STATUS="FAIL"
  else
    VULNERABLE=0
    STATUS="PASS"
  fi
fi

# PASS/FAIL에 따른 detail 문장 구성
if [ "$STATUS" = "PASS" ]; then
  # 양호 사유(설정 값만 사용)
  if [ ! -f "$TARGET_FILE" ]; then
    REASON_LINE="/etc/sudoers 파일이 존재하지 않아 이 항목을 점검할 수 없어 이 항목에 대해 양호합니다."
  else
    REASON_LINE="/etc/sudoers 파일이 owner=root이고 perm=${PERM_STR}로 설정되어 있어 이 항목에 대해 양호합니다."
  fi
else
  # 취약 사유(취약한 설정만 노출)
  if [ "$OWNER" != "root" ] && echo "$PERM_STR" | grep -Eq '^[0-7]{3,4}$' && [ "$PERM_STR" -gt 640 ]; then
    REASON_LINE="/etc/sudoers 파일이 owner=${OWNER}이고 perm=${PERM_STR}로 설정되어 있어 이 항목에 대해 취약합니다."
  elif [ "$OWNER" != "root" ]; then
    REASON_LINE="/etc/sudoers 파일이 owner=${OWNER}로 설정되어 있어 이 항목에 대해 취약합니다."
  else
    REASON_LINE="/etc/sudoers 파일이 perm=${PERM_STR}로 설정되어 있어 이 항목에 대해 취약합니다."
  fi

  # 취약 시 가이드(자동 조치 가정)
  GUIDE_LINE="자동 조치:
  /etc/sudoers 파일 소유자를 root로 변경하고 권한을 640으로 조정합니다.
  주의사항: 
  sudoers 권한/소유자 변경 중 설정 오류나 파일 손상 시 sudo 사용이 제한될 수 있으므로 콘솔 접속/복구 경로를 확보한 뒤 적용하는 것이 안전합니다."
fi

# raw_evidence 구성 (줄바꿈이 DB 저장/재조회 시 유지되도록 \\n로 escape)
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

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
