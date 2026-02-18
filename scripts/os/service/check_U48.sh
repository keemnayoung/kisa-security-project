#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-48
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : expn, vrfy 명령어 제한
# @Description : SMTP 서비스 사용 시 expn, vrfy 명령어 사용 금지 설정 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn, novrfy 또는 goaway 옵션 추가 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-48"
CATEGORY="서비스 관리"
TITLE="expn, vrfy 명령어 제한"
IMPORTANCE="중"

STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='(systemctl is-active postfix 2>/dev/null; systemctl is-active sendmail 2>/dev/null; systemctl is-active sm-mta 2>/dev/null; systemctl is-active exim 2>/dev/null); (test -f /etc/mail/sendmail.cf && grep -inE "^[[:space:]]*O[[:space:]]+PrivacyOptions" /etc/mail/sendmail.cf); (test -f /etc/postfix/main.cf && grep -inE "^[[:space:]]*disable_vrfy_command[[:space:]]*=" /etc/postfix/main.cf); (test -f /etc/exim/exim.conf && grep -inE "^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=" /etc/exim/exim.conf); (test -f /etc/exim4/exim4.conf && grep -inE "^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=" /etc/exim4/exim4.conf)'

escape_json_str() {
  # 백슬래시/줄바꿈/따옴표를 JSON 문자열로 안전하게 변환
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

is_active() {
  systemctl is-active --quiet "$1" 2>/dev/null
}

add_file_hash() {
  local f="$1" h="NOT_FOUND"
  if [ -f "$f" ]; then
    h="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
    [ -z "$h" ] && h="HASH_ERROR"
  fi
  HASH_LINES+=("$f (hash=$h)")
}

FOUND_ANY=0
FOUND_ACTIVE=0
VULNERABLE=0

PASS_PARTS=()
FAIL_PARTS=()
TARGET_FILES=()
HASH_LINES=()

DETAIL_LINES=()
REASON_ONE_LINE=""
GUIDE_LINE="N/A"

SENDMAIL_CF="/etc/mail/sendmail.cf"
POSTFIX_CF="/etc/postfix/main.cf"
EXIM_CONF1="/etc/exim/exim.conf"
EXIM_CONF2="/etc/exim4/exim4.conf"

SENDMAIL_INSTALLED=0
POSTFIX_INSTALLED=0
EXIM_INSTALLED=0

SENDMAIL_ACTIVE="inactive"
POSTFIX_ACTIVE="inactive"
EXIM_ACTIVE="inactive"

SENDMAIL_AFTER="privacyoptions_not_found"
POSTFIX_AFTER="disable_vrfy_command_not_found"
EXIM_AFTER1="acl_smtp_rules_not_found"
EXIM_AFTER2="acl_smtp_rules_not_found"

# Sendmail 분기: 설치/활성/설정 존재 여부에 따라 판정 근거를 수집
if command -v sendmail >/dev/null 2>&1 || [ -f "$SENDMAIL_CF" ]; then
  SENDMAIL_INSTALLED=1
  FOUND_ANY=1
  if is_active "sendmail" || is_active "sm-mta"; then
    SENDMAIL_ACTIVE="active"
    FOUND_ACTIVE=1
    if [ -f "$SENDMAIL_CF" ]; then
      TARGET_FILES+=("$SENDMAIL_CF")
      add_file_hash "$SENDMAIL_CF"

      PRIV_LINE="$(grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null | tail -n 1)"
      PRIV_VAL="$(printf '%s' "$PRIV_LINE" | sed -E 's/^[0-9]+:[[:space:]]*O[[:space:]]+PrivacyOptions[[:space:]]*=?[[:space:]]*//I')"
      SENDMAIL_AFTER="${PRIV_LINE:-privacyoptions_not_found}"

      if echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*goaway([[:space:]]*,|$)'; then
        PASS_PARTS+=("sendmail.cf PrivacyOptions에 goaway가 설정됨")
      elif echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*noexpn([[:space:]]*,|$)' \
        && echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*novrfy([[:space:]]*,|$)'; then
        PASS_PARTS+=("sendmail.cf PrivacyOptions에 noexpn, novrfy가 설정됨")
      else
        VULNERABLE=1
        FAIL_PARTS+=("sendmail.cf PrivacyOptions에 goaway 또는 noexpn+novrfy가 없음")
      fi
    else
      VULNERABLE=1
      FAIL_PARTS+=("sendmail 서비스가 active인데 /etc/mail/sendmail.cf 파일을 확인할 수 없음")
    fi
  fi
fi

# Postfix 분기: 설치/활성/설정 존재 여부에 따라 판정 근거를 수집
if command -v postfix >/dev/null 2>&1 || [ -f "$POSTFIX_CF" ]; then
  POSTFIX_INSTALLED=1
  FOUND_ANY=1
  if is_active "postfix"; then
    POSTFIX_ACTIVE="active"
    FOUND_ACTIVE=1
    if [ -f "$POSTFIX_CF" ]; then
      TARGET_FILES+=("$POSTFIX_CF")
      add_file_hash "$POSTFIX_CF"

      # 현재 설정(활성 라인 우선)
      POSTFIX_LINE="$(grep -nEv '^[[:space:]]*#' "$POSTFIX_CF" 2>/dev/null | grep -inE '^[[:space:]]*disable_vrfy_command[[:space:]]*=' | tail -n 1)"
      [ -z "$POSTFIX_LINE" ] && POSTFIX_LINE="$(grep -inE '^[[:space:]]*disable_vrfy_command[[:space:]]*=' "$POSTFIX_CF" 2>/dev/null | tail -n 1)"
      POSTFIX_AFTER="${POSTFIX_LINE:-disable_vrfy_command_not_found}"

      if grep -nEv '^[[:space:]]*#' "$POSTFIX_CF" 2>/dev/null | grep -qiE '^[[:space:]]*disable_vrfy_command[[:space:]]*=[[:space:]]*yes\b'; then
        PASS_PARTS+=("main.cf disable_vrfy_command=yes로 설정됨")
      else
        VULNERABLE=1
        FAIL_PARTS+=("main.cf에서 disable_vrfy_command=yes가 아니거나 설정이 없음")
      fi
    else
      VULNERABLE=1
      FAIL_PARTS+=("postfix 서비스가 active인데 /etc/postfix/main.cf 파일을 확인할 수 없음")
    fi
  fi
fi

# Exim 분기: 설치/활성/설정 존재 여부에 따라 판정 근거를 수집
if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1 || [ -f "$EXIM_CONF1" ] || [ -f "$EXIM_CONF2" ]; then
  EXIM_INSTALLED=1
  FOUND_ANY=1
  if is_active "exim" || is_active "exim4"; then
    EXIM_ACTIVE="active"
    FOUND_ACTIVE=1

    FOUND_CONF=0
    for conf in "$EXIM_CONF1" "$EXIM_CONF2"; do
      if [ -f "$conf" ]; then
        FOUND_CONF=1
        TARGET_FILES+=("$conf")
        add_file_hash "$conf"

        if grep -nEv '^[[:space:]]*#' "$conf" 2>/dev/null | grep -qiE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept\b'; then
          VULNERABLE=1
          FAIL_PARTS+=("$(basename "$conf")에서 acl_smtp_vrfy/acl_smtp_expn=accept이 활성 상태로 존재")
        else
          PASS_PARTS+=("$(basename "$conf")에서 acl_smtp_vrfy/acl_smtp_expn=accept이 활성 상태로 존재하지 않음")
        fi

        AFTER_ACL="$(grep -inE '^[[:space:]]*#?[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=' "$conf" 2>/dev/null | tail -n 5)"
        [ -z "$AFTER_ACL" ] && AFTER_ACL="acl_smtp_rules_not_found"
        if [ "$conf" = "$EXIM_CONF1" ]; then
          EXIM_AFTER1="$AFTER_ACL"
        else
          EXIM_AFTER2="$AFTER_ACL"
        fi
      fi
    done

    if [ $FOUND_CONF -eq 0 ]; then
      VULNERABLE=1
      FAIL_PARTS+=("exim 서비스가 active인데 설정 파일(/etc/exim/exim.conf, /etc/exim4/exim4.conf)을 확인할 수 없음")
    fi
  fi
fi

TARGET_FILE="$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF' | sort -u)"
[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

HASH_SUMMARY="$(printf "%s\n" "${HASH_LINES[@]}" | awk 'NF' | sort -u)"
[ -z "$HASH_SUMMARY" ] && HASH_SUMMARY="N/A"

# 최종 판정 분기: 미설치/미사용(active 없음)/active 존재 시 설정 충족 여부로 PASS/FAIL 결정
if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_ONE_LINE="메일 서비스가 설치되어 있지 않아 이 항목에 대해 양호합니다."
elif [ $FOUND_ACTIVE -eq 0 ]; then
  STATUS="PASS"
  REASON_ONE_LINE="메일 서비스가 비활성 상태로 설정되어 있어 이 항목에 대해 양호합니다."
else
  if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    VULN_BRIEF="$(printf "%s\n" "${FAIL_PARTS[@]}" | awk 'NF' | head -n 1)"
    [ -z "$VULN_BRIEF" ] && VULN_BRIEF="expn/vrfy 제한 설정이 미흡함"
    REASON_ONE_LINE="${VULN_BRIEF}로 설정되어 있어 이 항목에 대해 취약합니다."

    GUIDE_LINE="자동 조치: 
    Postfix는 /etc/postfix/main.cf에 disable_vrfy_command = yes를 추가/수정한 뒤 reload를 수행합니다.
    Sendmail은 /etc/mail/sendmail.cf의 PrivacyOptions에 goaway(또는 noexpn,novrfy)를 반영한 뒤 서비스를 재시작합니다.
    Exim은 acl_smtp_vrfy/acl_smtp_expn의 accept 허용 설정을 제거(또는 주석 처리)한 뒤 서비스를 재시작합니다.
    주의사항:
    설정 파일 변경 및 reload/restart 과정에서 순간적인 메일 처리 지연이 발생할 수 있으며 운영 정책(계정 검증/ACL 흐름)과 충돌할 수 있으니 적용 전 백업과 사전 테스트가 필요합니다."
  else
    STATUS="PASS"
    OK_BRIEF="$(printf "%s\n" "${PASS_PARTS[@]}" | awk 'NF' | head -n 1)"
    [ -z "$OK_BRIEF" ] && OK_BRIEF="expn/vrfy 제한 설정이 적용됨"
    REASON_ONE_LINE="${OK_BRIEF}로 설정되어 있어 이 항목에 대해 양호합니다."
  fi
fi

# DETAIL_CONTENT: 양호/취약과 무관하게 현재 설정 값(및 상태/대상 파일/해시)을 모두 표시
DETAIL_LINES="$(cat <<EOF
현재 서비스 상태: postfix=${POSTFIX_ACTIVE}, sendmail=${SENDMAIL_ACTIVE}, exim=${EXIM_ACTIVE}
현재 설정 값: postfix(main.cf) ${POSTFIX_AFTER}
현재 설정 값: sendmail(sendmail.cf) ${SENDMAIL_AFTER}
현재 설정 값: exim(exim.conf) ${EXIM_AFTER1}
현재 설정 값: exim4(exim4.conf) ${EXIM_AFTER2}
대상 파일/해시: ${HASH_SUMMARY}
EOF
)"

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_ONE_LINE}\n${DETAIL_LINES}")",
  "guide":"$(escape_json_str "$GUIDE_LINE")",
  "target_file":"$(escape_json_str "$TARGET_FILE")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF
