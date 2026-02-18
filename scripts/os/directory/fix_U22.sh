#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-22
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : /etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 초기화 분기점
ID="U-22"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/services"
CHECK_COMMAND="[ -f /etc/services ] && stat -c '%U %G %a %n' /etc/services 2>/dev/null || echo 'services_not_found_or_stat_failed'"

# 파일 존재 여부 확인 및 정보 수집 분기점
if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  # 파일 정보 수집 실패 시 처리 분기점
  if [ -z "$OWNER" ] || [ -z "$GROUP" ] || [ -z "$PERM" ]; then
    IS_SUCCESS=0
    REASON_LINE="파일 정보를 확인할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="stat_failed_or_no_output"
  else
    # 소유자 및 권한 조치 수행 분기점
    if [[ ! "$OWNER" =~ ^(root|bin|sys)$ ]]; then
      chown root "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    if [ -n "$PERM" ] && [ "$PERM" -gt 644 ]; then
      chmod 644 "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 조치 후 최종 상태 값 수집 분기점
    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    DETAIL_CONTENT="owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM"

    # 조치 결과에 따른 판정 및 REASON_LINE 생성 분기점
    if [[ "$AFTER_OWNER" =~ ^(root|bin|sys)$ ]] && [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -le 644 ]; then
      IS_SUCCESS=1
      REASON_LINE="소유자를 root(또는 관리 계정)로 변경하고 권한을 644 이하로 설정하여 조치를 완료하여 이 항목에 대해 양호합니다."
    else
      IS_SUCCESS=0
      REASON_LINE="관리자 외 쓰기 권한이 있거나 소유자가 허용된 계정이 아닌 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    fi
  fi
else
  # 대상 파일이 없을 경우 처리 분기점
  IS_SUCCESS=0
  REASON_LINE="대상 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="file_not_found"
fi

# RAW_EVIDENCE 작성을 위한 JSON 구조 생성 분기점
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 데이터 이스케이프 처리 분기점
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 JSON 결과 출력 분기점
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF