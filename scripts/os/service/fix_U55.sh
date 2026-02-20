#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-55
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : FTP 계정 shell 제한
# @Description : FTP 전용 계정(ftp)의 로그인 쉘을 제한(/sbin/nologin 또는 /bin/false)
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-55"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0
TARGET_FILE="/etc/passwd"
CHECK_COMMAND='(command -v getent >/dev/null 2>&1 && getent passwd ftp) || awk -F: '\''$1=="ftp"{print; exit}'\'' /etc/passwd 2>/dev/null || echo "ftp_account_not_found"'
REASON_LINE=""
DETAIL_CONTENT=""
ERR=""

# 유틸리티 함수 정의
json_escape() { echo -n "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g'; }

pick_lock_shell() {
  [ -x /sbin/nologin ] && echo /sbin/nologin && return
  [ -x /usr/sbin/nologin ] && echo /usr/sbin/nologin && return
  [ -x /bin/false ] && echo /bin/false && return
  echo ""
}

is_locked_shell() { case "$1" in /bin/false|/sbin/nologin|/usr/sbin/nologin) return 0;; *) return 1;; esac; }

get_ftp_entry() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd ftp 2>/dev/null
  else
    awk -F: '$1=="ftp"{print; exit}' "$TARGET_FILE" 2>/dev/null
  fi
}

get_ftp_shell() { echo "$1" | awk -F: '{print $7}'; }

# 권한 및 파일 존재 확인
if [ "$(id -u)" -ne 0 ]; then
  REASON_LINE="root 권한이 아니어서 ftp 계정의 로그인 쉘 제한을 적용할 수 없어 조치를 중단합니다."
  DETAIL_CONTENT="current_user: $(id -un)"
elif [ ! -f "$TARGET_FILE" ]; then
  REASON_LINE="/etc/passwd 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="target_file: missing"
else
  # ftp 계정 존재 여부 확인
  ENTRY="$(get_ftp_entry)"
  if [ -z "$ENTRY" ]; then
    IS_SUCCESS=1
    REASON_LINE="ftp 계정이 존재하지 않아 별도의 쉘 제한 설정 없이 조치를 완료하여 이 항목에 대해 양호합니다."
    DETAIL_CONTENT="ftp_account: not_found"
  else
    # 현재 쉘 상태 확인 및 조치 수행
    CUR_SHELL="$(get_ftp_shell "$ENTRY")"
    if is_locked_shell "$CUR_SHELL"; then
      IS_SUCCESS=1
      REASON_LINE="ftp 계정의 로그인 쉘이 이미 제한된 쉘로 설정되어 있어 조치를 완료하여 이 항목에 대해 양호합니다."
      DETAIL_CONTENT="ftp_account_info: $ENTRY"
    else
      # 조치 도구 및 환경 확인
      if ! command -v usermod >/dev/null 2>&1; then
        IS_SUCCESS=0
        REASON_LINE="usermod 명령어를 사용할 수 없는 환경적인 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
        DETAIL_CONTENT="ftp_account_info: $ENTRY"
      else
        LOCK_SHELL="$(pick_lock_shell)"
        if [ -z "$LOCK_SHELL" ]; then
          IS_SUCCESS=0
          REASON_LINE="시스템 내에 제한할 수 있는 쉘 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
          DETAIL_CONTENT="ftp_account_info: $ENTRY"
        else
          # 실제 조치 적용
          usermod -s "$LOCK_SHELL" ftp >/dev/null 2>&1 || ERR="usermod_execution_failed"
          AFTER_ENTRY="$(get_ftp_entry)"
          AFTER_SHELL="$(get_ftp_shell "$AFTER_ENTRY")"
          DETAIL_CONTENT="ftp_account_info: $AFTER_ENTRY"
          [ -n "$ERR" ] && DETAIL_CONTENT="$DETAIL_CONTENT\nerror_status: $ERR"

          if is_locked_shell "$AFTER_SHELL"; then
            IS_SUCCESS=1
            REASON_LINE="ftp 계정의 로그인 쉘을 접속이 제한된 쉘로 변경하여 조치를 완료하여 이 항목에 대해 양호합니다."
          else
            IS_SUCCESS=0
            REASON_LINE="계정 정보 수정 권한 문제 등의 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
          fi
        fi
      fi
    fi
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

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF