#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-16
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : /etc/passwd 파일의 소유자를 root로 설정하고 권한을 644 이하로 변경
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-16"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND="stat -c '%U %G %a %n' /etc/passwd 2>/dev/null"
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/passwd"

ACTION_ERR_LOG=""

# 실행 권한 확인 분기점
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="명령 실행 권한이 부족합니다."
fi

# 대상 파일 존재 여부 확인 분기점
if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  BEFORE_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  # 조치 전 권한 형식 검증 분기점
  if ! echo "$BEFORE_PERM" | grep -Eq '^[0-7]{3,4}$'; then
    IS_SUCCESS=0
    REASON_LINE="기존 파일 권한 형식을 확인할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="owner=$BEFORE_OWNER, group=$BEFORE_GROUP, perm=$BEFORE_PERM"
  else
    BEFORE_PERM_DEC=$((8#$BEFORE_PERM))

    # 소유자 및 그룹 변경 수행 분기점
    if [ "$BEFORE_OWNER" != "root" ] || [ "$BEFORE_GROUP" != "root" ]; then
      if chown root:root "$TARGET_FILE" 2>/dev/null; then
        MODIFIED=1
      else
        ACTION_ERR_LOG="${ACTION_ERR_LOG} 소유자 변경 실패."
      fi
    fi

    # 파일 권한 변경 수행 분기점
    NEED_CHMOD=0
    [ $((BEFORE_PERM_DEC & 022)) -ne 0 ] && NEED_CHMOD=1
    [ $((BEFORE_PERM_DEC & 07000)) -ne 0 ] && NEED_CHMOD=1
    [ "$BEFORE_PERM" -gt 644 ] && NEED_CHMOD=1

    if [ "$NEED_CHMOD" -eq 1 ]; then
      if chmod 644 "$TARGET_FILE" 2>/dev/null; then
        MODIFIED=1
      else
        ACTION_ERR_LOG="${ACTION_ERR_LOG} 권한 변경 실패."
      fi
    fi

    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    # 조치 후 결과 검증 분기점
    if ! echo "$AFTER_PERM" | grep -Eq '^[0-7]{3,4}$'; then
      IS_SUCCESS=0
      REASON_LINE="조치 후 상태 값을 읽어올 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    else
      AFTER_PERM_DEC=$((8#$AFTER_PERM))
      OWNER_OK=0; GROUP_OK=0; WRITE_OK=0; SPECIAL_OK=0; LE_OK=0
      [ "$AFTER_OWNER" = "root" ] && OWNER_OK=1
      [ "$AFTER_GROUP" = "root" ] && GROUP_OK=1
      [ $((AFTER_PERM_DEC & 022)) -eq 0 ] && WRITE_OK=1
      [ $((AFTER_PERM_DEC & 07000)) -eq 0 ] && SPECIAL_OK=1
      [ "$AFTER_PERM" -le 644 ] && LE_OK=1

      # 최종 판정 및 메시지 구성 분기점
      if [ "$OWNER_OK" -eq 1 ] && [ "$GROUP_OK" -eq 1 ] && [ "$WRITE_OK" -eq 1 ] && [ "$SPECIAL_OK" -eq 1 ] && [ "$LE_OK" -eq 1 ]; then
        IS_SUCCESS=1
        REASON_LINE="파일 소유자와 그룹을 root로 변경하고 권한을 644로 조치를 완료하여 이 항목에 대해 양호합니다."
      else
        IS_SUCCESS=0
        REASON_LINE="소유자 권한 또는 파일 모드가 기준을 초과하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
      fi
    fi

    # 현재 설정 상태 값 출력
    DETAIL_CONTENT="owner=$AFTER_OWNER, group=$AFTER_GROUP, perm=$AFTER_PERM"
    if [ -n "$ACTION_ERR_LOG" ]; then
      DETAIL_CONTENT="$DETAIL_CONTENT (Note: $ACTION_ERR_LOG)"
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="/etc/passwd 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="파일 미존재"
fi

# RAW_EVIDENCE 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# 결과 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF