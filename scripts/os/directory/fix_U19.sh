#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-19
# @Category    : 파일 및 디렉토리 관리
# @Platform    : RHEL
# @Importance  : 상
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
# @Description : /etc/hosts 파일의 소유자가 root이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-19"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/hosts"
CHECK_COMMAND="stat -c '%U %G %a %n' /etc/hosts 2>/dev/null"

# 대상 파일 존재 여부 확인
if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  # 조치 전 파일 정보 수집
  BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  BEFORE_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  # 파일 정보 수집 실패 시 예외 처리
  if [ -z "$BEFORE_OWNER" ] || [ -z "$BEFORE_GROUP" ] || [ -z "$BEFORE_PERM" ]; then
    IS_SUCCESS=0
    REASON_LINE="파일 정보를 읽을 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="owner=${BEFORE_OWNER:-unknown}, group=${BEFORE_GROUP:-unknown}, perm=${BEFORE_PERM:-unknown}"
  else
    # 파일 소유자 및 그룹 변경 수행
    if [ "$BEFORE_OWNER" != "root" ] || [ "$BEFORE_GROUP" != "root" ]; then
      chown root:root "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 파일 권한 644 변경 수행
    if [ "$BEFORE_PERM" != "644" ]; then
      chmod 644 "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 조치 완료 후 최종 상태 정보 수집
    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    # 현재 설정된 최종 상태 값 구성
    DETAIL_CONTENT="owner=$AFTER_OWNER, group=$AFTER_GROUP, perm=$AFTER_PERM"

    # 최종 조치 결과 판정 및 메시지 생성
    if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_GROUP" = "root" ] && [ "$AFTER_PERM" = "644" ]; then
      IS_SUCCESS=1
      REASON_LINE="파일 소유자를 root로 변경하고 권한을 644로 조치를 완료하여 이 항목에 대해 양호합니다."
    else
      IS_SUCCESS=0
      REASON_LINE="소유자 권한 또는 파일 모드가 기준을 초과하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    fi
  fi
else
  # 파일이 존재하지 않는 경우 처리
  IS_SUCCESS=0
  REASON_LINE="대상 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="상태: 파일 없음"
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
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
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF