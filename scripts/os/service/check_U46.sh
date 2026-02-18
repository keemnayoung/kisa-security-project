#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-46
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-46"
CATEGORY="서비스 관리"
TITLE="일반 사용자의 메일 서비스 실행 방지"
IMPORTANCE="상"

STATUS="PASS"
VULNERABLE=0

TARGET_FILES=()
FILE_HASH="NOT_FOUND"

DETAIL_CONTENT=""
REASON_SUMMARY=""
GUIDE_LINE="N/A"

SENDMAIL_CF=""
POSTSUPER="/usr/sbin/postsuper"
EXIQGREP="/usr/sbin/exiqgrep"

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

append_line() {
  local var_name="$1"
  local line="$2"
  if [ -z "${!var_name}" ]; then
    printf -v "$var_name" "%s" "$line"
  else
    printf -v "$var_name" "%s\n%s" "${!var_name}" "$line"
  fi
}

append_summary() {
  local part="$1"
  [ -z "$part" ] && return 0
  if [ -z "$REASON_SUMMARY" ]; then
    REASON_SUMMARY="$part"
  else
    REASON_SUMMARY="${REASON_SUMMARY}, ${part}"
  fi
}

# Sendmail 분기: 설치 여부 → 설정 파일 존재 여부 → PrivacyOptions 값 확인
if command -v sendmail >/dev/null 2>&1; then
  [ -f /etc/mail/sendmail.cf ] && SENDMAIL_CF="/etc/mail/sendmail.cf"
  [ -z "$SENDMAIL_CF" ] && [ -f /etc/sendmail.cf ] && SENDMAIL_CF="/etc/sendmail.cf"

  if [ -n "$SENDMAIL_CF" ]; then
    add_target_file "$SENDMAIL_CF"
    PRIV_LINE="$(grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions([[:space:]]*=|[[:space:]]+)' "$SENDMAIL_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n 1)"

    if [ -z "$PRIV_LINE" ]; then
      VULNERABLE=1
      append_line DETAIL_CONTENT "sendmail: ${SENDMAIL_CF} PrivacyOptions=NOT_FOUND"
      append_summary "sendmail PrivacyOptions=NOT_FOUND"
    else
      append_line DETAIL_CONTENT "sendmail: ${SENDMAIL_CF} PrivacyOptions=${PRIV_LINE}"
      if echo "$PRIV_LINE" | grep -qi 'restrictqrun'; then
        append_summary "sendmail restrictqrun=ON"
      else
        VULNERABLE=1
        append_summary "sendmail restrictqrun=OFF"
      fi
    fi
  else
    append_line DETAIL_CONTENT "sendmail: installed sendmail_cf=NOT_FOUND"
    append_summary "sendmail_cf=NOT_FOUND"
  fi
else
  append_line DETAIL_CONTENT "sendmail: not_installed"
fi

# Postfix 분기: postsuper 존재 여부 → 파일 존재 여부 → 권한(o+x) 확인
if command -v postsuper >/dev/null 2>&1; then
  if [ -f "$POSTSUPER" ]; then
    add_target_file "$POSTSUPER"
    P_PERMS="$(stat -c '%a' "$POSTSUPER" 2>/dev/null)"
    if [ -z "$P_PERMS" ]; then
      VULNERABLE=1
      append_line DETAIL_CONTENT "postfix: ${POSTSUPER} perms=STAT_FAIL"
      append_summary "postsuper perms=STAT_FAIL"
    else
      append_line DETAIL_CONTENT "postfix: ${POSTSUPER} perms=${P_PERMS}"
      if is_others_exec_on "$P_PERMS"; then
        VULNERABLE=1
        append_summary "postsuper o+x=ON(${P_PERMS})"
      else
        append_summary "postsuper o+x=OFF(${P_PERMS})"
      fi
    fi
  else
    append_line DETAIL_CONTENT "postfix: postsuper_found file=NOT_FOUND(${POSTSUPER})"
    append_summary "postsuper_file=NOT_FOUND"
  fi
else
  append_line DETAIL_CONTENT "postfix: not_installed"
fi

# Exim 분기: exiqgrep 파일 존재 여부 → 권한(o+x) 확인
if [ -f "$EXIQGREP" ]; then
  add_target_file "$EXIQGREP"
  E_PERMS="$(stat -c '%a' "$EXIQGREP" 2>/dev/null)"
  if [ -z "$E_PERMS" ]; then
    VULNERABLE=1
    append_line DETAIL_CONTENT "exim: ${EXIQGREP} perms=STAT_FAIL"
    append_summary "exiqgrep perms=STAT_FAIL"
  else
    append_line DETAIL_CONTENT "exim: ${EXIQGREP} perms=${E_PERMS}"
    if is_others_exec_on "$E_PERMS"; then
      VULNERABLE=1
      append_summary "exiqgrep o+x=ON(${E_PERMS})"
    else
      append_summary "exiqgrep o+x=OFF(${E_PERMS})"
    fi
  fi
else
  append_line DETAIL_CONTENT "exim: exiqgrep=NOT_FOUND"
fi

TARGET_FILE="$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF')"
REP_FILE="$(printf "%s\n" "${TARGET_FILES[@]}" | head -n 1)"

if [ -n "$REP_FILE" ] && [ -f "$REP_FILE" ]; then
  FILE_HASH="$(sha256sum "$REP_FILE" 2>/dev/null | awk '{print $1}')"
  [ -z "$FILE_HASH" ] && FILE_HASH="HASH_ERROR"
else
  FILE_HASH="NOT_FOUND"
fi

# 판정 분기: 점검 대상이 없으면 PASS 처리
if [ ${#TARGET_FILES[@]} -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스 관련 설정/바이너리가 발견되지 않아 이 항목에 대해 양호합니다."
  GUIDE_LINE="N/A"
else
  if [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="${REASON_SUMMARY}로 이 항목에 대해 취약합니다."
    GUIDE_LINE="자동 조치:
    sendmail의 sendmail.cf에서 PrivacyOptions에 restrictqrun을 포함하도록 반영하고 sendmail 서비스를 재시작합니다.
    /usr/sbin/postsuper 및 /usr/sbin/exiqgrep의 others 실행 권한(o+x)을 제거합니다.
    주의사항: 
    메일 큐 관련 운영 작업(큐 실행/관리)을 일반 계정에서 수행하던 환경에서는 작업 흐름이 변경될 수 있습니다.
    sendmail 재시작 시 짧은 서비스 재시작 구간이 발생할 수 있어 운영 시간대 적용은 피하는 것이 안전합니다."
  else
    STATUS="PASS"
    REASON_LINE="${REASON_SUMMARY}로 이 항목에 대해 양호합니다."
    GUIDE_LINE="N/A"
  fi
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND="$(cat <<'EOF'
(command -v sendmail >/dev/null 2>&1 && (grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null | grep -v '^#' || grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions' /etc/sendmail.cf 2>/dev/null | grep -v '^#'));
(command -v postsuper >/dev/null 2>&1 && stat -c '%a %n' /usr/sbin/postsuper 2>/dev/null);
(test -f /usr/sbin/exiqgrep && stat -c '%a %n' /usr/sbin/exiqgrep 2>/dev/null)
EOF
)"

escape_json_str() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}\n(대상 파일)\n${TARGET_FILE}\n(대표 해시)\n${REP_FILE} (sha256=${FILE_HASH})")",
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
