#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-48
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : expn, vrfy 명령어 제한
# @Description : SMTP expn, vrfy 명령어를 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-48"
CATEGORY="서비스관리"
TITLE="expn, vrfy 명령어 제한"
IMPORTANCE="중"
STATUS="PASS"
ACTION_LOG=""
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
AFTER_LINES=()
TARGET_FILES=()

# 유틸리티 함수 정의
is_active() {
  systemctl is-active --quiet "$1" 2>/dev/null
}

add_target_file() {
  local f="$1"
  [ -f "$f" ] && TARGET_FILES+=("$f")
}

add_after_line() {
  local s="$1"
  [ -n "$s" ] && AFTER_LINES+=("$s")
}

# Sendmail 서비스 조치
SENDMAIL_CF="/etc/mail/sendmail.cf"
SENDMAIL_INSTALLED=0
if command -v sendmail >/dev/null 2>&1 || [ -f "$SENDMAIL_CF" ]; then
  SENDMAIL_INSTALLED=1
fi

if [ $SENDMAIL_INSTALLED -eq 1 ]; then
  if is_active "sendmail" || is_active "sm-mta"; then
    if [ -f "$SENDMAIL_CF" ]; then
      add_target_file "$SENDMAIL_CF"
      PRIV_LINE="$(grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null | tail -n 1)"
      PRIV_VAL="$(printf '%s' "$PRIV_LINE" | sed -E 's/^[0-9]+:[[:space:]]*O[[:space:]]+PrivacyOptions[[:space:]]*=?[[:space:]]*//I')"

      if ! echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*goaway([[:space:]]*,|$)' && \
         ! { echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*noexpn([[:space:]]*,|$)' && echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*novrfy([[:space:]]*,|$)'; }; then
        if grep -qiE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null; then
          sed -i -E '/^[[:space:]]*O[[:space:]]+PrivacyOptions/I{/goaway/I! s/[[:space:]]*=?[[:space:]]*(.*)$/=\1,goaway/}' "$SENDMAIL_CF"
        else
          echo "O PrivacyOptions=authwarnings,novrfy,noexpn,goaway" >> "$SENDMAIL_CF"
        fi
        systemctl restart sendmail 2>/dev/null || systemctl restart sm-mta 2>/dev/null || true
      fi
      AFTER_PRIV="$(grep -iE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null | tail -n 1)"
      add_after_line "sendmail_status: ${AFTER_PRIV:-privacyoptions_not_found}"
    else
      STATUS="FAIL"
    fi
  else
    add_after_line "sendmail_status: service_inactive"
  fi
fi

# Postfix 서비스 조치
POSTFIX_CF="/etc/postfix/main.cf"
POSTFIX_INSTALLED=0
if command -v postfix >/dev/null 2>&1 || [ -f "$POSTFIX_CF" ]; then
  POSTFIX_INSTALLED=1
fi

if [ $POSTFIX_INSTALLED -eq 1 ]; then
  if is_active "postfix"; then
    if [ -f "$POSTFIX_CF" ]; then
      add_target_file "$POSTFIX_CF"
      if grep -nEv '^[[:space:]]*#' "$POSTFIX_CF" 2>/dev/null | grep -qiE '^[[:space:]]*disable_vrfy_command[[:space:]]*='; then
        sed -i -E 's/^[[:space:]]*disable_vrfy_command[[:space:]]*=.*/disable_vrfy_command = yes/I' "$POSTFIX_CF"
      else
        echo "disable_vrfy_command = yes" >> "$POSTFIX_CF"
      fi
      systemctl reload postfix 2>/dev/null || true
      AFTER_POSTFIX="$(grep -iE '^[[:space:]]*disable_vrfy_command[[:space:]]*=' "$POSTFIX_CF" 2>/dev/null | tail -n 1)"
      add_after_line "postfix_status: ${AFTER_POSTFIX:-disable_vrfy_command_not_found}"
    else
      STATUS="FAIL"
    fi
  else
    add_after_line "postfix_status: service_inactive"
  fi
fi

# Exim 서비스 조치
EXIM_INSTALLED=0
if command -v exim >/dev/null 2>&1 || [ -f /etc/exim/exim.conf ] || [ -f /etc/exim4/exim4.conf ]; then
  EXIM_INSTALLED=1
fi

if [ $EXIM_INSTALLED -eq 1 ]; then
  if is_active "exim" || is_active "exim4"; then
    CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf")
    FOUND_CONF=0
    for conf in "${CONF_FILES[@]}"; do
      if [ -f "$conf" ]; then
        FOUND_CONF=1
        add_target_file "$conf"
        sed -i -E 's/^[[:space:]]*(acl_smtp_vrfy[[:space:]]*=[[:space:]]*accept\b)/#\1/I' "$conf"
        sed -i -E 's/^[[:space:]]*(acl_smtp_expn[[:space:]]*=[[:space:]]*accept\b)/#\1/I' "$conf"
        systemctl restart exim 2>/dev/null || systemctl restart exim4 2>/dev/null || true
        AFTER_EXIM="$(grep -iE '^[[:space:]]*#?[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=' "$conf" 2>/dev/null | tr '\n' ' ')"
        add_after_line "exim_status(${conf}): ${AFTER_EXIM:-acl_smtp_rules_not_found}"
      fi
    done
    [ $FOUND_CONF -eq 0 ] && STATUS="FAIL"
  else
    add_after_line "exim_status: service_inactive"
  fi
fi

# 조치 후 최종 검증 및 판정
FOUND_ACTIVE=0
VERIFY_FAIL=0

if [ $SENDMAIL_INSTALLED -eq 1 ] && (is_active "sendmail" || is_active "sm-mta"); then
  FOUND_ACTIVE=1
  [[ ! "$(grep -iE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null)" =~ (goaway|noexpn.*novrfy|novrfy.*noexpn) ]] && VERIFY_FAIL=1
fi
if [ $POSTFIX_INSTALLED -eq 1 ] && is_active "postfix"; then
  FOUND_ACTIVE=1
  ! grep -nEv '^[[:space:]]*#' "$POSTFIX_CF" 2>/dev/null | grep -qiE 'disable_vrfy_command[[:space:]]*=[[:space:]]*yes' && VERIFY_FAIL=1
fi
if [ $EXIM_INSTALLED -eq 1 ] && (is_active "exim" || is_active "exim4"); then
  FOUND_ACTIVE=1
  (grep -nEv '^[[:space:]]*#' /etc/exim/exim.conf 2>/dev/null | grep -qiE 'acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept' || \
   grep -nEv '^[[:space:]]*#' /etc/exim4/exim4.conf 2>/dev/null | grep -qiE 'acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept') && VERIFY_FAIL=1
fi

# REASON_LINE 및 DETAIL_CONTENT 구성
REASON_LINE=""
if [ $FOUND_ACTIVE -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스가 설치되어 있지 않거나 비활성화되어 있어 조치 없이도 이 항목에 대해 양호합니다."
elif [ "$VERIFY_FAIL" -eq 1 ] || [ "$STATUS" = "FAIL" ]; then
  STATUS="FAIL"
  REASON_LINE="SMTP 설정 파일에서 expn/vrfy 명령어를 제한하는 설정이 누락되었거나 적용되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
else
  STATUS="PASS"
  REASON_LINE="SMTP 설정 파일에 PrivacyOptions 또는 disable_vrfy_command 옵션을 설정하여 조치를 완료하여 이 항목에 대해 양호합니다."
fi

DETAIL_CONTENT="$(printf "%s\n" "${AFTER_LINES[@]}")"

# 결과 데이터 구성
TARGET_FILE_FINAL="$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF' | sort -u | tr '\n' ',' | sed 's/,$//')"
CHECK_COMMAND="grep -E 'PrivacyOptions|disable_vrfy_command|acl_smtp' (SMTP config files)"

json_escape() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

# raw_evidence 구성
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$(json_escape "$CHECK_COMMAND")",
  "detail": "$(json_escape "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file": "$(json_escape "${TARGET_FILE_FINAL:-N/A}")"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

echo ""
cat << EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF