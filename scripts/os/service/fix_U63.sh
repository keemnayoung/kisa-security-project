#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-63
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : sudo 명령어 접근 관리
# @Description : /etc/sudoers 파일 권한 적절성 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정 분기점
ID="U-63"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0
TARGET_FILE="/etc/sudoers"
CHECK_COMMAND="stat -c '%U %G %a %n' /etc/sudoers 2>/dev/null || echo 'sudoers_not_found_or_stat_failed'"
REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""

# 유틸리티 함수 정의 분기점
append_err(){ [ -z "${1:-}" ] && return 0; ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }

json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g'
}

# 파일 존재 여부 확인 분기점
if [ ! -f "$TARGET_FILE" ]; then
  REASON_LINE="/etc/sudoers 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="file_status: not_found"
else
  # 현재 소유자 및 권한 정보 수집 분기점
  OWNER="$(stat -c '%U' "$TARGET_FILE" 2>/dev/null || true)"
  PERM="$(stat -c '%a' "$TARGET_FILE" 2>/dev/null || true)"

  if [ -z "$OWNER" ] || [ -z "$PERM" ] || ! echo "$PERM" | grep -Eq '^[0-7]{3,4}$'; then
    REASON_LINE="파일 시스템 정보 수집 권한이 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="file_info: permission_denied_or_stat_error"
  else
    # 소유자 및 권한 조치 적용 분기점
    if [ "$OWNER" != "root" ]; then
      chown root "$TARGET_FILE" >/dev/null 2>&1 || append_err "chown_failed"
    fi

    if [ "$PERM" -gt 440 ]; then
      chmod 440 "$TARGET_FILE" >/dev/null 2>&1 || append_err "chmod_failed"
    fi

    # 조치 결과 재수집 분기점
    AFTER_OWNER="$(stat -c '%U' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
    AFTER_GROUP="$(stat -c '%G' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
    AFTER_PERM="$(stat -c '%a' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
    DETAIL_CONTENT="owner=$AFTER_OWNER, group=$AFTER_GROUP, permissions=$AFTER_PERM"

    # 최종 판정 분기점
    if [ -n "$ACTION_ERR_LOG" ]; then
      REASON_LINE="파일 속성 변경 시 발생하는 권한 거부 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    elif [ "$AFTER_OWNER" = "root" ] && echo "$AFTER_PERM" | grep -Eq '^[0-7]{3,4}$' && [ "$AFTER_PERM" -le 440 ]; then
      IS_SUCCESS=1
      REASON_LINE="/etc/sudoers 파일의 소유자를 root로 변경하고 권한을 440 이하로 설정하여 조치를 완료하여 이 항목에 대해 양호합니다."
    else
      REASON_LINE="소유자 또는 권한이 보안 기준을 충족하지 못하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    fi
  fi
fi

# 결과 데이터 출력 분기점
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

echo ""
cat <<EOF
{
  "item_code": "$ID",
  "action_date": "$ACTION_DATE",
  "is_success": $IS_SUCCESS,
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF