#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-22
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : /etc/services 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-22"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/services"
CHECK_COMMAND='[ -f /etc/services ] && stat -c "%U %a %n" /etc/services 2>/dev/null || echo "services_not_found_or_stat_failed"'

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE=""

# JSON escape 유틸 (역슬래시/따옴표/줄바꿈)
json_escape() {
  echo "$1" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | sed ':a;N;$!ba;s/\n/\\n/g'
}

# guide(취약 시 자동 조치 가정)
GUIDE_LINE="자동 조치: 
1) 파일 존재 여부 확인 후, 필요 시 백업을 생성합니다.
2) 소유자가 root/bin/sys가 아니면 root로 변경합니다. (예: chown root /etc/services)
3) 권한이 644를 초과하면 644로 변경합니다. (예: chmod 644 /etc/services)
4) 조치 후 소유자/권한을 재확인하여 기준 충족 여부를 검증합니다.
주의사항: 
/etc/services는 포트 매핑 정보가 포함된 파일이므로, 운영 환경에서 파일이 비정상적으로 변경되었거나 서비스가 특정 커스텀 매핑에 의존하는 경우 예기치 않은 서비스 연동 문제가 발생할 수 있어 조치 전 백업 및 변경 이력 확인이 권장됩니다."

# 분기 1) 파일 존재하지 않음
if [ ! -f "$TARGET_FILE" ]; then
  STATUS="FAIL"

  # FAIL 사유는 취약한 설정(상태)만 사용
  REASON_LINE="file_not_found로 확인되어 이 항목에 대해 취약합니다."

  # 현재 설정값(현 상태)만 출력
  DETAIL_CONTENT="file_exists=no
owner=N/A
perm=N/A
target_file=$TARGET_FILE"

else
  FILE_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
  FILE_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

  # 분기 2) stat 결과 확인 불가
  if [ -z "$FILE_OWNER" ] || [ -z "$FILE_PERM" ]; then
    STATUS="FAIL"

    REASON_LINE="stat_failed_or_no_output로 확인되어 이 항목에 대해 취약합니다."

    DETAIL_CONTENT="file_exists=yes
owner=unknown
perm=unknown
target_file=$TARGET_FILE"

  else
    # 현재 설정값(현 상태)만 출력 (양호/취약 무관)
    DETAIL_CONTENT="file_exists=yes
owner=$FILE_OWNER
perm=$FILE_PERM
target_file=$TARGET_FILE"

    # 분기 3) 기준 충족 여부 판단
    if [[ "$FILE_OWNER" =~ ^(root|bin|sys)$ ]] && [ "$FILE_PERM" -le 644 ]; then
      STATUS="PASS"
      REASON_LINE="owner=$FILE_OWNER perm=$FILE_PERM로 설정되어 이 항목에 대해 양호합니다."
    else
      STATUS="FAIL"
      BAD_PARTS=""
      if [[ ! "$FILE_OWNER" =~ ^(root|bin|sys)$ ]]; then
        BAD_PARTS="owner=$FILE_OWNER"
      fi
      if [ "$FILE_PERM" -gt 644 ]; then
        if [ -n "$BAD_PARTS" ]; then
          BAD_PARTS="$BAD_PARTS perm=$FILE_PERM"
        else
          BAD_PARTS="perm=$FILE_PERM"
        fi
      fi
      [ -z "$BAD_PARTS" ] && BAD_PARTS="owner=$FILE_OWNER perm=$FILE_PERM"
      REASON_LINE="$BAD_PARTS로 설정되어 이 항목에 대해 취약합니다."
    fi
  fi
fi

# raw_evidence 구성: detail은 (한 문장 이유) + \n + (현재 설정값)
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

RAW_EVIDENCE_ESCAPED=$(json_escape "$RAW_EVIDENCE")

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
