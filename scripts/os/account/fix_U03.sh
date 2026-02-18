#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-03
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 계정 잠금 임계값 설정
# @Description : 계정 탈취 공격 방지를 위해 로그인 실패 시 잠금 임계값 조치
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-03"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

CONF_FILE="/etc/security/faillock.conf"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

TARGET_FILE="$CONF_FILE, $PAM_SYSTEM_AUTH, $PAM_PASSWORD_AUTH"

CHECK_COMMAND="( command -v authselect >/dev/null 2>&1 && authselect current 2>/dev/null ); ( command -v authselect >/dev/null 2>&1 && authselect check 2>/dev/null ); ( [ -f /etc/security/faillock.conf ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/security/faillock.conf | grep -iE '^(deny|unlock_time)[[:space:]]*=' | tail -n 10 ); ( [ -f /etc/pam.d/system-auth ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/pam.d/system-auth | grep -E 'pam_faillock\\.so|pam_tally2\\.so|pam_tally\\.so' | tail -n 10 ); ( [ -f /etc/pam.d/password-auth ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/pam.d/password-auth | grep -E 'pam_faillock\\.so|pam_tally2\\.so|pam_tally\\.so' | tail -n 10 )"

# 설정 파일 내 파라미터 업데이트 함수 (기존 로직 유지)
set_param() {
  local file=$1
  local param=$2
  local val=$3

  if [ ! -f "$file" ]; then
    return 1
  fi

  if grep -qiE "^[[:space:]]*#?[[:space:]]*${param}[[:space:]]*=" "$file" 2>/dev/null; then
    sed -i -E "s|^[[:space:]]*#?[[:space:]]*${param}[[:space:]]*=.*|${param} = ${val}|I" "$file" 2>/dev/null
  else
    echo "${param} = ${val}" >> "$file"
  fi
  return 0
}

# PAM 파일 내 잠금 모듈 활성 여부 확인 함수 (기존 로직 유지)
pam_has_lock_module() {
  local file="$1"
  [ -f "$file" ] || return 1
  grep -iEv '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null \
    | grep -Eq 'pam_faillock\.so|pam_tally2\.so|pam_tally\.so'
}

# PAM 설정 파일에 pam_faillock 구문 강제 삽입 함수 (기존 로직 유지)
ensure_pam_faillock() {
  local file="$1"
  local stamp="$2"
  local tmp="${file}.tmp_${stamp}"

  [ -f "$file" ] || return 2
  if pam_has_lock_module "$file"; then
    return 0
  fi

  cp -p "$file" "${file}.bak_${stamp}" 2>/dev/null || return 3

  awk '
  BEGIN {
    preauth_done=0; authfail_done=0; account_done=0;
    saw_auth_unix=0; saw_account_unix=0;
  }
  {
    line=$0;
    if (line ~ /^[[:space:]]*auth[[:space:]].*pam_unix\.so/ && saw_auth_unix==0) {
      print "auth        required      pam_faillock.so preauth silent";
      preauth_done=1;
      print line;
      print "auth        [default=die] pam_faillock.so authfail";
      authfail_done=1;
      saw_auth_unix=1;
      next;
    }
    if (line ~ /^[[:space:]]*account[[:space:]].*pam_unix\.so/ && saw_account_unix==0) {
      print "account     required      pam_faillock.so";
      account_done=1;
      print line;
      saw_account_unix=1;
      next;
    }
    print line;
  }
  END {
    if (preauth_done==0) { print "auth        required      pam_faillock.so preauth silent"; }
    if (authfail_done==0) { print "auth        [default=die] pam_faillock.so authfail"; }
    if (account_done==0) { print "account     required      pam_faillock.so"; }
  }' "$file" > "$tmp" 2>/dev/null

  if [ ! -s "$tmp" ]; then
    rm -f "$tmp" 2>/dev/null
    return 4
  fi

  mv "$tmp" "$file" 2>/dev/null || return 5
  return 0
}

# 조치 전 상태 수집 및 백업 분기점
ACTION_LOG=""
DENY_BEFORE=""
UNLOCK_BEFORE=""
if [ -f "$CONF_FILE" ]; then
  DENY_BEFORE=$(grep -iE '^[[:space:]]*deny[[:space:]]*=' "$CONF_FILE" 2>/dev/null | tail -n 1 | sed 's/#.*$//' | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  UNLOCK_BEFORE=$(grep -iE '^[[:space:]]*unlock_time[[:space:]]*=' "$CONF_FILE" 2>/dev/null | tail -n 1 | sed 's/#.*$//' | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  BACKUP_FILE="${CONF_FILE}.bak_${ACTION_DATE//[: ]/_}"
  if cp -p "$CONF_FILE" "$BACKUP_FILE" 2>/dev/null; then
    ACTION_LOG="backup_created=$BACKUP_FILE"
  else
    ACTION_LOG="backup_failed"
  fi
else
  ACTION_LOG="conf_file_not_found_before"
fi

# 조치 수행 (authselect 및 PAM 직접 수정)
AUTHSELECT_RESULT="not_installed"
AUTHSELECT_WITH_FAILLOCK="unknown"
AUTHSELECT_CONFIGURED="unknown"
PAM_DIRECT_FIX="not_attempted"
STAMP="${ACTION_DATE//[: ]/_}"

if command -v authselect >/dev/null 2>&1; then
  authselect check >/dev/null 2>&1 && AUTHSELECT_CONFIGURED="yes" || AUTHSELECT_CONFIGURED="no"
  authselect current 2>/dev/null | grep -Eq 'with-faillock' && AUTHSELECT_WITH_FAILLOCK="enabled" || AUTHSELECT_WITH_FAILLOCK="disabled_or_unknown"
fi

if command -v authselect >/dev/null 2>&1 && [ "$AUTHSELECT_CONFIGURED" = "yes" ]; then
  authselect enable-feature with-faillock >/dev/null 2>&1
  EN_RC=$?
  authselect apply-changes >/dev/null 2>&1
  AP_RC=$?
  if [ $EN_RC -eq 0 ] && [ $AP_RC -eq 0 ]; then
    AUTHSELECT_RESULT="success"
  else
    AUTHSELECT_RESULT="failed(enable_rc=$EN_RC,apply_rc=$AP_RC)"
  fi
fi

if [ "$AUTHSELECT_CONFIGURED" = "no" ] || [ "$AUTHSELECT_RESULT" != "success" ]; then
  if [ "$AUTHSELECT_CONFIGURED" = "no" ]; then
    PAM_DIRECT_FIX="attempted"
    ensure_pam_faillock "$PAM_SYSTEM_AUTH" "$STAMP"
    SYS_RC=$?
    ensure_pam_faillock "$PAM_PASSWORD_AUTH" "$STAMP"
    PWD_RC=$?
    ACTION_LOG="${ACTION_LOG}\npam_direct_fix=attempted(system-auth_rc=$SYS_RC,password-auth_rc=$PWD_RC)"
  fi
fi

if [ ! -f "$CONF_FILE" ]; then
  mkdir -p /etc/security 2>/dev/null
  touch "$CONF_FILE" 2>/dev/null
fi

if [ -f "$CONF_FILE" ]; then
  set_param "$CONF_FILE" "deny" "10"
  set_param "$CONF_FILE" "unlock_time" "120"
fi

# 조치 후 최종 상태 수집 분기점
DENY_VAL=""
UNLOCK_VAL=""
if [ -f "$CONF_FILE" ]; then
  DENY_VAL=$(grep -iE '^[[:space:]]*deny[[:space:]]*=' "$CONF_FILE" 2>/dev/null | tail -n 1 | sed 's/#.*$//' | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  UNLOCK_VAL=$(grep -iE '^[[:space:]]*unlock_time[[:space:]]*=' "$CONF_FILE" 2>/dev/null | tail -n 1 | sed 's/#.*$//' | sed 's/[[:space:]]//g' | cut -d'=' -f2)
fi

PAM_MODULE_STATUS="not_applied"
PAM_SYSTEM_HAS="no"
PAM_PASSWORD_HAS="no"
pam_has_lock_module "$PAM_SYSTEM_AUTH" && PAM_SYSTEM_HAS="yes"
pam_has_lock_module "$PAM_PASSWORD_AUTH" && PAM_PASSWORD_HAS="yes"
[ "$PAM_SYSTEM_HAS" = "yes" ] || [ "$PAM_PASSWORD_HAS" = "yes" ] && PAM_MODULE_STATUS="applied"

# 모든 기존 항목을 유지한 DETAIL_CONTENT 구성
DETAIL_CONTENT="deny=$DENY_VAL
unlock_time=$UNLOCK_VAL
pam_module_status=$PAM_MODULE_STATUS
pam_system_auth_has_module=$PAM_SYSTEM_HAS
pam_password_auth_has_module=$PAM_PASSWORD_HAS
authselect_configured=$AUTHSELECT_CONFIGURED
authselect_with_faillock=$AUTHSELECT_WITH_FAILLOCK
authselect_result=$AUTHSELECT_RESULT
deny_before=$DENY_BEFORE
unlock_time_before=$UNLOCK_BEFORE
action_log=$ACTION_LOG"

# 최종 판정 및 REASON_LINE 구성 분기점
if [ -f "$CONF_FILE" ] && [ "$DENY_VAL" = "10" ] && [ "$UNLOCK_VAL" = "120" ] && [ "$PAM_MODULE_STATUS" = "applied" ]; then
  IS_SUCCESS=1
  REASON_LINE="계정 잠금 임계값을 10회로 제한하고 잠금 해제 시간을 120초로 설정한 뒤 PAM 모듈 설정을 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  if [ ! -f "$CONF_FILE" ]; then
    REASON_LINE="계정 잠금 설정 파일인 faillock.conf가 시스템에 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  elif [ "$PAM_MODULE_STATUS" != "applied" ]; then
    REASON_LINE="PAM 설정 파일에 계정 잠금 모듈이 정상적으로 삽입되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  else
    REASON_LINE="설정 파일의 임계값 또는 해제 시간 설정이 가이드 기준에 부합하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

# RAW_EVIDENCE 구성 및 JSON 이스케이프 (기존 방식 유지)
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

# 최종 결과 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF