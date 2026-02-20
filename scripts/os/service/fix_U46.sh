#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-46
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-46"
CATEGORY="서비스 관리"
TITLE="일반 사용자의 메일 서비스 실행 방지"
IMPORTANCE="상"
STATUS="PASS"
ACTION_LOG=""
TARGET_FILES=()

# 권한 판정 유틸리티 함수 정의
is_others_exec_on() {
  local p="$1"
  [[ "$p" =~ ^[0-9]{3,4}$ ]] || return 2
  local o=$(( p % 10 ))
  (( (o & 1) == 1 ))
}

add_target_file() {
  local f="$1"
  [ -n "$f" ] && TARGET_FILES+=("$f")
}

# Sendmail restrictqrun 설정 조치
SENDMAIL_CF=""
if command -v sendmail >/dev/null 2>&1; then
  [ -f /etc/mail/sendmail.cf ] && SENDMAIL_CF="/etc/mail/sendmail.cf"
  [ -z "$SENDMAIL_CF" ] && [ -f /etc/sendmail.cf ] && SENDMAIL_CF="/etc/sendmail.cf"

  if [ -n "$SENDMAIL_CF" ]; then
    add_target_file "$SENDMAIL_CF"
    PRIV_LINE="$(grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions([[:space:]]*=|[[:space:]]+)' "$SENDMAIL_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n 1)"

    if [ -z "$PRIV_LINE" ]; then
      echo "O PrivacyOptions=restrictqrun" >> "$SENDMAIL_CF"
    else
      if ! echo "$PRIV_LINE" | grep -qi 'restrictqrun'; then
        sed -i -r '/^[[:space:]]*(O[[:space:]]+)?PrivacyOptions[[:space:]]*=/I {
          /restrictqrun/I! s/[[:space:]]*$//;
          /restrictqrun/I! s/$/,restrictqrun/;
        }' "$SENDMAIL_CF"
      fi
    fi

    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart sendmail 2>/dev/null || true
    fi
  fi
fi

# Postfix postsuper 실행 권한 제거 조치
POSTSUPER="/usr/sbin/postsuper"
if [ -f "$POSTSUPER" ]; then
  add_target_file "$POSTSUPER"
  PERMS="$(stat -c '%a' "$POSTSUPER" 2>/dev/null)"
  if [ -n "$PERMS" ] && is_others_exec_on "$PERMS"; then
    chmod o-x "$POSTSUPER" 2>/dev/null || true
  fi
fi

# Exim exiqgrep 실행 권한 제거 조치
EXIQGREP="/usr/sbin/exiqgrep"
if [ -f "$EXIQGREP" ]; then
  add_target_file "$EXIQGREP"
  PERMS="$(stat -c '%a' "$EXIQGREP" 2>/dev/null)"
  if [ -n "$PERMS" ] && is_others_exec_on "$PERMS"; then
    chmod o-x "$EXIQGREP" 2>/dev/null || true
  fi
fi

# 조치 후 상태 검증 및 데이터 수집
VERIFY_FAIL=0
AFTER_LINES=""

if [ -n "$SENDMAIL_CF" ] && [ -f "$SENDMAIL_CF" ]; then
  AFTER_PRIV="$(grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions([[:space:]]*=|[[:space:]]+)' "$SENDMAIL_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n 1)"
  if echo "$AFTER_PRIV" | grep -qi 'restrictqrun'; then
    AFTER_LINES="${AFTER_LINES}sendmail_status: ${AFTER_PRIV}\n"
  else
    VERIFY_FAIL=1
    AFTER_LINES="${AFTER_LINES}sendmail_status: restrictqrun_not_found\n"
  fi
fi

if [ -f "$POSTSUPER" ]; then
  AFTER_P="$(stat -c '%a' "$POSTSUPER" 2>/dev/null)"
  if is_others_exec_on "$AFTER_P"; then
    VERIFY_FAIL=1
    AFTER_LINES="${AFTER_LINES}postfix_perms: ${AFTER_P} (unrestricted)\n"
  else
    AFTER_LINES="${AFTER_LINES}postfix_perms: ${AFTER_P}\n"
  fi
fi

if [ -f "$EXIQGREP" ]; then
  AFTER_E="$(stat -c '%a' "$EXIQGREP" 2>/dev/null)"
  if is_others_exec_on "$AFTER_E"; then
    VERIFY_FAIL=1
    AFTER_LINES="${AFTER_LINES}exim_perms: ${AFTER_E} (unrestricted)\n"
  else
    AFTER_LINES="${AFTER_LINES}exim_perms: ${AFTER_E}\n"
  fi
fi

# 최종 판정
REASON_LINE=""
DETAIL_CONTENT=""

if [ ${#TARGET_FILES[@]} -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스 관련 점검 대상이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대해 양호합니다."
  DETAIL_CONTENT="target_status: mail_service_not_found"
else
  if [ "$VERIFY_FAIL" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="일부 메일 서비스 설정에 restrictqrun이 누락되거나 바이너리 실행 권한이 남아 있는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  else
    STATUS="PASS"
    REASON_LINE="PrivacyOptions에 restrictqrun을 설정하고 관련 바이너리의 일반 사용자 실행 권한을 제거하여 조치를 완료하여 이 항목에 대해 양호합니다."
  fi
  DETAIL_CONTENT="$(printf "$AFTER_LINES")"
fi

# 결과 데이터 구성 및 출력
TARGET_FILE_FINAL="$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF' | tr '\n' ',' | sed 's/,$//')"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="(command -v sendmail >/dev/null 2>&1 && grep PrivacyOptions /etc/mail/sendmail.cf); (stat -c '%a %n' /usr/sbin/postsuper /usr/sbin/exiqgrep 2>/dev/null)"

json_escape() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

# raw_evidence 구성
RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(json_escape "$CHECK_COMMAND")",
  "detail":"$(json_escape "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(json_escape "$TARGET_FILE_FINAL")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF