#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-12
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 세션 종료 시간 설정
# @Description : 사용자 세션 방치로 인한 보안 사고 예방을 위해 TMOUT 설정 조치
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-12"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/profile"
CHECK_COMMAND="grep -nE '^[[:space:]]*TMOUT=' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null"

MODIFIED=0
OVERRIDE_REMOVED=0

# 조치 수행 및 타 파일의 우선 순위 설정 제거
if [ -f "$TARGET_FILE" ]; then
  for f in /etc/profile.d/*.sh /etc/bashrc; do
    [ -e "$f" ] || continue
    if grep -qE '^[[:space:]]*TMOUT[[:space:]]*=' "$f" 2>/dev/null; then
      sed -i '/^[[:space:]]*TMOUT[[:space:]]*=/Id' "$f" 2>/dev/null
      OVERRIDE_REMOVED=1
      MODIFIED=1
    fi
  done

  # /etc/profile 내 기존 설정 삭제 및 신규 값 주입
  if grep -qE 'TMOUT' "$TARGET_FILE" 2>/dev/null; then
    MODIFIED=1
  fi

  sed -i '/^[[:space:]]*TMOUT[[:space:]]*=/Id' "$TARGET_FILE" 2>/dev/null
  sed -i '/^[[:space:]]*export[[:space:]]\+TMOUT\b/Id' "$TARGET_FILE" 2>/dev/null
  sed -i '/^[[:space:]]*typeset[[:space:]]\+-x[[:space:]]\+TMOUT\b/Id' "$TARGET_FILE" 2>/dev/null

  {
    echo ""
    echo "TMOUT=600"
    echo "export TMOUT"
  } >> "$TARGET_FILE" 2>/dev/null

  # 조치 후 최종 상태 값 수집 분기점
  AFTER_TMOUT_LINES=$(grep -nEi '^[[:space:]]*TMOUT[[:space:]]*=' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | sed '/^[[:space:]]*$/d' | tail -n 10)
  AFTER_EXPORT_LINES=$(grep -nE '^[[:space:]]*(export[[:space:]]+TMOUT|typeset[[:space:]]+-x[[:space:]]+TMOUT)\b' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n 10)

  AFTER_VAL=$(grep -iE '^[[:space:]]*TMOUT[[:space:]]*=' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n 1 | sed 's/.*=[[:space:]]*//; s/[^0-9].*$//')
  [ -z "$AFTER_VAL" ] && AFTER_VAL="not_set"

  # DETAIL_CONTENT 구성
  DETAIL_CONTENT="tmout_value=$AFTER_VAL
tmout_lines=$AFTER_TMOUT_LINES
export_status=$([ -n "$AFTER_EXPORT_LINES" ] && echo "exported" || echo "not_exported")
override_removed=$([ "$OVERRIDE_REMOVED" -eq 1 ] && echo "yes" || echo "no")"

  # 최종 성공 여부 판정 및 REASON_LINE 구성
  if [ "$AFTER_VAL" = "600" ] && [ -n "$AFTER_EXPORT_LINES" ]; then
    IS_SUCCESS=1
    REASON_LINE="세션 종료 시간을 600초로 설정하고 환경변수 export를 적용하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    if [ "$AFTER_VAL" != "600" ]; then
      REASON_LINE="TMOUT 설정값이 600초로 반영되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    else
      REASON_LINE="export 설정이 정상적으로 적용되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="/etc/profile 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="target_file_missing"
fi

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

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