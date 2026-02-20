#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-18
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-18"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/shadow"
CHECK_COMMAND="stat -c '%U %G %a %n' /etc/shadow 2>/dev/null"

# 권한의 적절성 판정 함수
is_perm_ok() {
  local perm_raw="$1"
  [ -z "$perm_raw" ] && return 1

  local perm3 u g o
  perm3=$(printf "%03d" "$perm_raw" 2>/dev/null) || return 1
  u="${perm3:0:1}"
  g="${perm3:1:1}"
  o="${perm3:2:1}"

  if { [ "$u" = "4" ] || [ "$u" = "0" ]; } && [ "$g" = "0" ] && [ "$o" = "0" ]; then
    return 0
  fi
  return 1
}

# 조치 대상 파일 존재 여부 확인
if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  PERM_RAW=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  # 파일 정보 획득 성공 여부 확인
  if [ -z "$OWNER" ] || [ -z "$GROUP" ] || [ -z "$PERM_RAW" ]; then
    IS_SUCCESS=0
    REASON_LINE="파일 정보 확인 시 시스템 호출 오류가 발생한 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="상태: 정보를 읽을 수 없음"
  else
    PERM=$(printf "%03d" "$PERM_RAW" 2>/dev/null)

    # 파일 소유자 root 변경 수행
    if [ "$OWNER" != "root" ]; then
      chown root "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 파일 권한 400 이하 변경 수행
    if ! is_perm_ok "$PERM_RAW"; then
      chmod 400 "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM_RAW=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(printf "%03d" "$AFTER_PERM_RAW" 2>/dev/null)

    # 현재 설정된 최종 상태 값 수집
    DETAIL_CONTENT="owner=$AFTER_OWNER, group=$AFTER_GROUP, perm=$AFTER_PERM"

    # 최종 조치 결과 판정 및 메시지 구성
    if [ "$AFTER_OWNER" = "root" ] && is_perm_ok "$AFTER_PERM_RAW"; then
      IS_SUCCESS=1
      REASON_LINE="파일 소유자를 root로 변경하고 권한을 400으로 수정 완료하여 이 항목에 대해 양호합니다."
    else
      IS_SUCCESS=0
      REASON_LINE="소유자가 root가 아니거나 권한이 기준을 초과하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="대상 파일이 시스템에 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="상태: 파일 미존재"
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