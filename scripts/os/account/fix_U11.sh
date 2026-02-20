#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-11
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 사용자 shell 점검
# @Description : 로그인이 필요하지 않은 시스템 계정에 로그인 제한 쉘(/sbin/nologin) 부여
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-11"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PASSWD_FILE="/etc/passwd"
TARGET_FILE="$PASSWD_FILE"

# 점검 명령
CHECK_COMMAND="awk -F: '(\$1==\"daemon\"||\$1==\"bin\"||\$1==\"sys\"||\$1==\"adm\"||\$1==\"listen\"||\$1==\"nobody\"||\$1==\"nobody4\"||\$1==\"noaccess\"||\$1==\"diag\"||\$1==\"operator\"||\$1==\"games\"||\$1==\"gopher\"){print \$1\":\"\$7}' /etc/passwd 2>/dev/null"

SYSTEM_ACCOUNTS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

MODIFIED=0
FAIL_FLAG=0

# 로그인 제한 쉘 유효성 검증 함수
ALLOWED_SHELLS=("/bin/false" "/sbin/nologin" "/usr/sbin/nologin")

is_allowed_shell() {
  local shell="$1"
  for s in "${ALLOWED_SHELLS[@]}"; do
    [ "$shell" = "$s" ] && return 0
  done
  return 1
}

# 시스템 환경에 맞는 로그인 제한 쉘 선택 함수
pick_target_shell() {
  if [ -x /sbin/nologin ]; then
    echo "/sbin/nologin"
  elif [ -x /usr/sbin/nologin ]; then
    echo "/usr/sbin/nologin"
  else
    echo "/bin/false"
  fi
}

TARGET_LOGIN_SHELL="$(pick_target_shell)"

# 조치 수행 및 시스템 계정 쉘 변경 분기점
if [ -f "$PASSWD_FILE" ]; then
  for acc in "${SYSTEM_ACCOUNTS[@]}"; do
    if id "$acc" >/dev/null 2>&1; then
      CURRENT_SHELL=$(awk -F: -v u="$acc" '$1==u {print $7}' "$PASSWD_FILE" 2>/dev/null | head -n 1)

      if [ -n "$CURRENT_SHELL" ] || [ -z "$CURRENT_SHELL" ]; then
        if ! is_allowed_shell "$CURRENT_SHELL"; then
          if usermod -s "$TARGET_LOGIN_SHELL" "$acc" >/dev/null 2>&1; then
            MODIFIED=1
          else
            FAIL_FLAG=1
          fi
        fi
      fi
    fi
  done

  # 조치 완료 후 상태 수집 및 결과 분석
  STILL_VULN_LIST=""
  AFTER_LIST=""

  for acc in "${SYSTEM_ACCOUNTS[@]}"; do
    if id "$acc" >/dev/null 2>&1; then
      SHELL_AFTER=$(awk -F: -v u="$acc" '$1==u {print $7}' "$PASSWD_FILE" 2>/dev/null | head -n 1)
      AFTER_LIST="${AFTER_LIST}${acc}:${SHELL_AFTER}
"
      if ! is_allowed_shell "$SHELL_AFTER"; then
        STILL_VULN_LIST="${STILL_VULN_LIST}${acc}:${SHELL_AFTER}
"
      fi
    fi
  done

  AFTER_LIST="$(echo "$AFTER_LIST" | sed '/^[[:space:]]*$/d')"
  STILL_VULN_LIST="$(echo "$STILL_VULN_LIST" | sed '/^[[:space:]]*$/d')"

  DETAIL_CONTENT="$AFTER_LIST"

  # 최종 성공 여부 판정 및 REASON_LINE 구성
  if [ -z "$STILL_VULN_LIST" ] && [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="로그인이 불필요한 시스템 계정에 로그인 제한 쉘(${TARGET_LOGIN_SHELL})을 부여하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="시스템 계정에 로그인 제한 쉘을 설정하는 과정에서 권한 문제나 usermod 명령어 오류가 발생한 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    if [ -n "$STILL_VULN_LIST" ]; then
      DETAIL_CONTENT="$STILL_VULN_LIST"
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="/etc/passwd 파일이 시스템에 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="대상 파일 미존재"
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