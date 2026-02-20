#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-21
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# @Description : /etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 초기화
ID="U-21"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

LOG_FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")

CHECK_COMMAND="for f in /etc/syslog.conf /etc/rsyslog.conf; do [ -f \"\$f\" ] && stat -c '%U %G %a %n' \"\$f\"; done 2>/dev/null"

FOUND=0
FAIL_FLAG=0
MODIFIED=0
DETAIL_CONTENT=""
TARGET_FILES_EXIST=""

# 시스템 내 존재하는 syslog 설정 파일을 확인, 소유자 및 권한 조치를 수행
for FILE in "${LOG_FILES[@]}"; do
  if [ -f "$FILE" ]; then
    FOUND=1
    TARGET_FILES_EXIST="${TARGET_FILES_EXIST}${FILE}"$'\n'

    OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    if ! [[ "$OWNER" =~ ^(root|bin|sys)$ ]]; then
      chown root "$FILE" 2>/dev/null
      MODIFIED=1
    fi

    if [ -n "$PERM" ] && [ "$PERM" -gt 640 ]; then
      chmod 640 "$FILE" 2>/dev/null
      MODIFIED=1
    fi
  fi
done

# 조치 결과 확인을 위해 현재 파일의 설정 상태를 수집, 성공 여부를 검증
for FILE in "${LOG_FILES[@]}"; do
  if [ -f "$FILE" ]; then
    AFTER_OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    DETAIL_CONTENT="${DETAIL_CONTENT}owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM
file=$FILE

"

    if { ! [[ "$AFTER_OWNER" =~ ^(root|bin|sys)$ ]]; } || { [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 640 ]; }; then
      FAIL_FLAG=1
    fi
  fi
done

# 실제 존재하는 파일 목록 기반 타겟 파일 변수를 구성
if [ -n "$TARGET_FILES_EXIST" ]; then
  TARGET_FILE="$(printf "%s" "$TARGET_FILES_EXIST" | sed 's/[[:space:]]*$//')"
else
  TARGET_FILE=$(printf "%s\n" "${LOG_FILES[@]}")
fi

if [ "$FOUND" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="대상 파일이 존재하지 않아 조치를 완료하여 이 항목에 대해 양호합니다."
  DETAIL_CONTENT="상태: 파일 없음"
else
  if [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="소유자를 root(또는 관리 계정)로 변경하고 권한을 640 이하로 설정하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="관리자 외 쓰기 권한이 있거나 소유자가 허용된 계정이 아닌 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
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