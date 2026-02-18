#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-29
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : /etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 초기화 분기점
ID="U-29"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/hosts.lpd"
CHECK_COMMAND="stat -c '%F %U %G %a %n' /etc/hosts.lpd 2>/dev/null"

# 파일 존재 여부 확인 및 정보 수집 분기점
if [ ! -e "$TARGET_FILE" ]; then
  IS_SUCCESS=1
  REASON_LINE="대상 파일이 존재하지 않아 조치를 완료하여 이 항목에 대해 양호합니다."
  DETAIL_CONTENT="상태: 파일 없음"
else
  # 파일 타입 확인 분기점
  FILE_TYPE=$(stat -c "%F" "$TARGET_FILE" 2>/dev/null)
  if [ -z "$FILE_TYPE" ]; then
    IS_SUCCESS=0
    REASON_LINE="파일 정보를 확인할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="stat_failed"
  elif [ "$FILE_TYPE" != "regular file" ]; then
    IS_SUCCESS=0
    REASON_LINE="일반 파일이 아닌 비정상적인 형태로 존재하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="type=$FILE_TYPE"
  else
    MODIFIED=0

    OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    # 조회 값 유효성 검사 분기점
    if [ -z "$OWNER" ] || [ -z "$GROUP" ] || [ -z "$PERM" ] || ! [[ "$PERM" =~ ^[0-9]+$ ]]; then
      IS_SUCCESS=0
      REASON_LINE="소유자나 권한 값을 확인할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
      DETAIL_CONTENT="owner=$OWNER group=$GROUP perm=$PERM"
    else
      # 소유자 및 권한 조치 수행 분기점
      if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
        chown root:root "$TARGET_FILE" 2>/dev/null
        MODIFIED=1
      fi

      if [ "$PERM" -gt 600 ]; then
        chmod 600 "$TARGET_FILE" 2>/dev/null
        MODIFIED=1
      fi

      # 조치 후 최종 상태 수집 분기점
      AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
      AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
      AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

      DETAIL_CONTENT="type=$FILE_TYPE
owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM"

      # 결과 판정 및 REASON_LINE 확정 분기점
      if [ -z "$AFTER_OWNER" ] || [ -z "$AFTER_GROUP" ] || [ -z "$AFTER_PERM" ] || ! [[ "$AFTER_PERM" =~ ^[0-9]+$ ]]; then
        IS_SUCCESS=0
        REASON_LINE="조치 후 상태 정보를 확인할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
      elif [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_GROUP" = "root" ] && [ "$AFTER_PERM" -le 600 ]; then
        IS_SUCCESS=1
        REASON_LINE="소유자를 root로 변경하고 권한을 600 이하로 설정하여 조치를 완료하여 이 항목에 대해 양호합니다."
      else
        IS_SUCCESS=0
        REASON_LINE="관리자 외 쓰기 권한이 있거나 소유자가 허용된 계정이 아닌 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
      fi
    fi
  fi
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