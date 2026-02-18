#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-02
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 패스워드 복잡성 설정
# @Description : 패스워드 복잡성 및 유효기간 설정 여부 점검
# @Criteria_Good : 패스워드 최소 길이, 복잡성, 유효기간 정책이 기준에 적합한 경우
# @Criteria_Bad : 패스워드 정책이 설정되어 있지 않거나 기준 미달인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-02"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

PW_CONF="/etc/security/pwquality.conf"
PWH_CONF="/etc/security/pwhistory.conf"
LOGIN_DEFS="/etc/login.defs"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

TARGET_FILE="$PW_CONF $PWH_CONF $LOGIN_DEFS $PAM_SYSTEM_AUTH $PAM_PASSWORD_AUTH"

CHECK_COMMAND='
# pwquality.conf
grep -iv "^[[:space:]]*#" /etc/security/pwquality.conf 2>/dev/null | egrep -i "^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)[[:space:]]*="; \
grep -n "^[[:space:]]*enforce_for_root[[:space:]]*$" /etc/security/pwquality.conf 2>/dev/null; \
# pwhistory.conf
grep -iv "^[[:space:]]*#" /etc/security/pwhistory.conf 2>/dev/null | egrep -i "^(remember|file)[[:space:]]*="; \
grep -n "^[[:space:]]*enforce_for_root[[:space:]]*$" /etc/security/pwhistory.conf 2>/dev/null; \
# login.defs
grep -E "^[[:space:]]*PASS_(MAX|MIN)_DAYS[[:space:]]+" /etc/login.defs 2>/dev/null; \
# PAM
grep -nE "^[[:space:]]*password[[:space:]]+.*pam_(pwquality|pwhistory|unix)\.so" /etc/pam.d/system-auth 2>/dev/null; \
grep -nE "^[[:space:]]*password[[:space:]]+.*pam_(pwquality|pwhistory|unix)\.so" /etc/pam.d/password-auth 2>/dev/null; \
# 대상 계정(예외 처리)
awk -F: '\''{print $1":"$3":"$7}'\'' /etc/passwd 2>/dev/null | egrep "^(root:|[^:]+:[0-9]+:)" | head -n 50; \
awk -F: '\''{print $1":"$2}'\'' /etc/shadow 2>/dev/null | head -n 50
'

REASON_LINE=""
DETAIL_CONTENT=""
STATUS_FAIL="N"

DETAIL_LINES=""
VULN_SUMMARY=""

get_kv_val_last() {
  local file="$1"
  local key="$2"
  grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
    | grep -E "^[[:space:]]*${key}[[:space:]]*=" \
    | tail -n 1 \
    | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}'
}

has_standalone_token() {
  local file="$1"
  local token="$2"
  grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
    | grep -Eq "^[[:space:]]*${token}[[:space:]]*$"
}

pam_has_module() {
  local file="$1"
  local module="$2"
  grep -Ev '^[[:space:]]*#' "$file" 2>/dev/null \
    | grep -Eq "^[[:space:]]*password[[:space:]]+.*${module}([[:space:]]|$)"
}

pam_get_line_text_first() {
  local file="$1"
  local module="$2"
  grep -Ev '^[[:space:]]*#' "$file" 2>/dev/null \
    | grep -E "^[[:space:]]*password[[:space:]]+.*${module}([[:space:]]|$)" \
    | head -n 1
}

pam_get_line_no_first() {
  local file="$1"
  local module="$2"
  grep -nEv '^[[:space:]]*#' "$file" 2>/dev/null \
    | grep -nE "^[[:space:]]*password[[:space:]]+.*${module}([[:space:]]|$)" \
    | head -n 1 \
    | awk -F: '{print $1}'
}

pam_order_ok() {
  local file="$1"
  local m1="$2"
  local m2="$3"
  local uline m1line m2line
  uline="$(pam_get_line_no_first "$file" "pam_unix\.so")"
  m1line="$(pam_get_line_no_first "$file" "$m1")"
  m2line="$(pam_get_line_no_first "$file" "$m2")"
  if [ -z "$uline" ]; then
    echo "UNKNOWN"; return 0
  fi
  if [ -n "$m1line" ] && [ "$m1line" -gt "$uline" ] 2>/dev/null; then
    echo "NO"; return 0
  fi
  if [ -n "$m2line" ] && [ "$m2line" -gt "$uline" ] 2>/dev/null; then
    echo "NO"; return 0
  fi
  echo "YES"
}

json_escape_multiline() {
  echo -e "$1" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | sed ':a;N;$!ba;s/\n/\\n/g'
}

append_summary() {
  local s="$1"
  [ -z "$s" ] && return 0
  if [ -n "$VULN_SUMMARY" ]; then
    VULN_SUMMARY="${VULN_SUMMARY}; ${s}"
  else
    VULN_SUMMARY="${s}"
  fi
}

# 대상/제외 계정은 정책 적용 범위를 확인하기 위해 수집합니다.
SUBJECT_USERS=""
EXCLUDED_USERS=""
if [ -r /etc/passwd ] && [ -r /etc/shadow ]; then
  while IFS=: read -r user _ uid _ _ _ shell; do
    if [ "$user" != "root" ] && [ "$uid" -lt 1000 ] 2>/dev/null; then
      continue
    fi
    case "$shell" in
      */nologin|*/false|"")
        EXCLUDED_USERS+="${user}(non_login_shell:${shell}), "
        continue
        ;;
    esac
    spw="$(awk -F: -v u="$user" '$1==u{print $2}' /etc/shadow 2>/dev/null)"
    if [ -z "$spw" ]; then
      EXCLUDED_USERS+="${user}(shadow_not_found), "
      continue
    fi
    case "$spw" in
      "!"*|"!!"*|"*"|"*LK*"|"")
        EXCLUDED_USERS+="${user}(locked_or_no_password), "
        continue
        ;;
    esac
    SUBJECT_USERS+="${user}, "
  done < /etc/passwd
  SUBJECT_USERS="$(echo "$SUBJECT_USERS" | sed 's/, $//')"
  EXCLUDED_USERS="$(echo "$EXCLUDED_USERS" | sed 's/, $//')"
else
  SUBJECT_USERS="unknown(passwd_or_shadow_unreadable)"
  EXCLUDED_USERS="unknown(passwd_or_shadow_unreadable)"
fi

# pwquality.conf 설정을 수집하고 기준 충족 여부를 판정합니다.
PWQ_OK="N"
MINLEN_VAL=""; MINCLASS_VAL=""; DCREDIT_VAL=""; UCREDIT_VAL=""; LCREDIT_VAL=""; OCREDIT_VAL=""; PWQ_ENFORCE="N"
if [ -f "$PW_CONF" ]; then
  MINLEN_VAL="$(get_kv_val_last "$PW_CONF" "minlen")"
  MINCLASS_VAL="$(get_kv_val_last "$PW_CONF" "minclass")"
  DCREDIT_VAL="$(get_kv_val_last "$PW_CONF" "dcredit")"
  UCREDIT_VAL="$(get_kv_val_last "$PW_CONF" "ucredit")"
  LCREDIT_VAL="$(get_kv_val_last "$PW_CONF" "lcredit")"
  OCREDIT_VAL="$(get_kv_val_last "$PW_CONF" "ocredit")"
  has_standalone_token "$PW_CONF" "enforce_for_root" && PWQ_ENFORCE="Y"

  if [ -n "$MINLEN_VAL" ] && [ "$MINLEN_VAL" -ge 8 ] 2>/dev/null \
     && [ "$DCREDIT_VAL" = "-1" ] && [ "$UCREDIT_VAL" = "-1" ] && [ "$LCREDIT_VAL" = "-1" ] && [ "$OCREDIT_VAL" = "-1" ] \
     && [ "$PWQ_ENFORCE" = "Y" ]; then
    PWQ_OK="Y"
  else
    STATUS_FAIL="Y"
    append_summary "pwquality.conf(minlen=${MINLEN_VAL:-not_set}, dcredit=${DCREDIT_VAL:-not_set}, ucredit=${UCREDIT_VAL:-not_set}, lcredit=${LCREDIT_VAL:-not_set}, ocredit=${OCREDIT_VAL:-not_set}, enforce_for_root=${PWQ_ENFORCE})"
  fi
else
  STATUS_FAIL="Y"
  append_summary "pwquality.conf(file_not_found)"
fi

# pwhistory.conf 설정을 수집하고 기준 충족 여부를 판정합니다.
PWH_OK="N"
REMEMBER_VAL=""; OPASSWD_FILE_VAL=""; PWH_ENFORCE="N"
if [ -f "$PWH_CONF" ]; then
  REMEMBER_VAL="$(get_kv_val_last "$PWH_CONF" "remember")"
  OPASSWD_FILE_VAL="$(get_kv_val_last "$PWH_CONF" "file")"
  has_standalone_token "$PWH_CONF" "enforce_for_root" && PWH_ENFORCE="Y"

  if [ -n "$REMEMBER_VAL" ] && [ "$REMEMBER_VAL" -ge 4 ] 2>/dev/null \
     && [ "$OPASSWD_FILE_VAL" = "/etc/security/opasswd" ] \
     && [ "$PWH_ENFORCE" = "Y" ]; then
    PWH_OK="Y"
  else
    STATUS_FAIL="Y"
    append_summary "pwhistory.conf(remember=${REMEMBER_VAL:-not_set}, file=${OPASSWD_FILE_VAL:-not_set}, enforce_for_root=${PWH_ENFORCE})"
  fi
else
  STATUS_FAIL="Y"
  append_summary "pwhistory.conf(file_not_found)"
fi

# login.defs 설정을 수집하고 기준 충족 여부를 판정합니다.
MAX_DAYS_VAL=""; MIN_DAYS_VAL=""
if [ -f "$LOGIN_DEFS" ]; then
  MAX_DAYS_VAL="$(grep -E '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+' "$LOGIN_DEFS" 2>/dev/null | awk '{print $2}' | tail -n 1)"
  MIN_DAYS_VAL="$(grep -E '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$LOGIN_DEFS" 2>/dev/null | awk '{print $2}' | tail -n 1)"

  ok_login="Y"
  [ -z "$MAX_DAYS_VAL" ] && ok_login="N"
  [ -n "$MAX_DAYS_VAL" ] && [ "$MAX_DAYS_VAL" -gt 90 ] 2>/dev/null && ok_login="N"
  [ -z "$MIN_DAYS_VAL" ] && ok_login="N"
  [ -n "$MIN_DAYS_VAL" ] && [ "$MIN_DAYS_VAL" -lt 1 ] 2>/dev/null && ok_login="N"

  if [ "$ok_login" != "Y" ]; then
    STATUS_FAIL="Y"
    append_summary "login.defs(PASS_MAX_DAYS=${MAX_DAYS_VAL:-not_set}, PASS_MIN_DAYS=${MIN_DAYS_VAL:-not_set})"
  fi
else
  STATUS_FAIL="Y"
  append_summary "login.defs(file_not_found)"
fi

# PAM 적용 여부와 모듈 순서를 판정합니다.
PAM_FILES=("$PAM_SYSTEM_AUTH" "$PAM_PASSWORD_AUTH")
PAM_PWQ_OK="N"
PAM_PWH_OK="N"
PAM_ORDER_OK_ALL="Y"
PAM_FOUND_ANY="N"
PAM_PWQ_LINE_1=""
PAM_PWH_LINE_1=""
PAM_ORDER_UNKNOWN="N"

for pf in "${PAM_FILES[@]}"; do
  if [ -f "$pf" ]; then
    PAM_FOUND_ANY="Y"

    if pam_has_module "$pf" "pam_pwquality\.so"; then
      PAM_PWQ_OK="Y"
      [ -z "$PAM_PWQ_LINE_1" ] && PAM_PWQ_LINE_1="$(pam_get_line_text_first "$pf" "pam_pwquality\.so")"
    fi
    if pam_has_module "$pf" "pam_pwhistory\.so"; then
      PAM_PWH_OK="Y"
      [ -z "$PAM_PWH_LINE_1" ] && PAM_PWH_LINE_1="$(pam_get_line_text_first "$pf" "pam_pwhistory\.so")"
    fi

    order_res="$(pam_order_ok "$pf" "pam_pwquality\.so" "pam_pwhistory\.so")"
    if [ "$order_res" = "NO" ]; then
      PAM_ORDER_OK_ALL="N"
    elif [ "$order_res" = "UNKNOWN" ]; then
      PAM_ORDER_UNKNOWN="Y"
    fi
  fi
done

if [ "$PAM_FOUND_ANY" = "N" ]; then
  STATUS_FAIL="Y"
  append_summary "pam(files_not_found)"
else
  if [ "$PAM_ORDER_OK_ALL" = "N" ]; then
    STATUS_FAIL="Y"
    append_summary "pam(order_ok=N)"
  fi
  if [ "$PAM_PWQ_OK" != "Y" ] && [ "$PWQ_OK" != "Y" ]; then
    STATUS_FAIL="Y"
    append_summary "pam(pwquality_present=N)"
  fi
  if [ "$PAM_PWH_OK" != "Y" ] && [ "$PWH_OK" != "Y" ]; then
    STATUS_FAIL="Y"
    append_summary "pam(pwhistory_present=N)"
  fi
fi

# DETAIL_CONTENT는 양호/취약과 관계없이 현재 설정값을 모두 출력합니다.
DETAIL_LINES+="pwquality.conf(minlen=${MINLEN_VAL:-not_set}, minclass=${MINCLASS_VAL:-not_set}, dcredit=${DCREDIT_VAL:-not_set}, ucredit=${UCREDIT_VAL:-not_set}, lcredit=${LCREDIT_VAL:-not_set}, ocredit=${OCREDIT_VAL:-not_set}, enforce_for_root=${PWQ_ENFORCE})"$'\n'
DETAIL_LINES+="pwhistory.conf(remember=${REMEMBER_VAL:-not_set}, file=${OPASSWD_FILE_VAL:-not_set}, enforce_for_root=${PWH_ENFORCE})"$'\n'
DETAIL_LINES+="login.defs(PASS_MAX_DAYS=${MAX_DAYS_VAL:-not_set}, PASS_MIN_DAYS=${MIN_DAYS_VAL:-not_set})"$'\n'
DETAIL_LINES+="pam(pwquality_present=${PAM_PWQ_OK}, pwhistory_present=${PAM_PWH_OK}, order_ok=${PAM_ORDER_OK_ALL}, order_check=${PAM_ORDER_UNKNOWN:+UNKNOWN}${PAM_ORDER_UNKNOWN:+" "}${PAM_ORDER_UNKNOWN:-YES})"$'\n'
DETAIL_LINES+="pam_line_pwquality=${PAM_PWQ_LINE_1:-not_found}"$'\n'
DETAIL_LINES+="pam_line_pwhistory=${PAM_PWH_LINE_1:-not_found}"$'\n'
DETAIL_LINES+="accounts(subject_users=${SUBJECT_USERS:-none}, excluded_users=${EXCLUDED_USERS:-none})"$'\n'

DETAIL_CONTENT="$(printf "%s" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

# 최종 상태에 따라 reason(한 문장)과 detail(첫 줄 reason + 다음 줄부터 DETAIL_CONTENT)를 구성합니다.
if [ "$STATUS_FAIL" = "Y" ]; then
  STATUS="FAIL"
  if [ -z "$VULN_SUMMARY" ]; then
    VULN_SUMMARY="settings_not_verified"
  fi
  REASON_LINE="${VULN_SUMMARY}로 설정되어 있어 이 항목에 대해 취약합니다."
else
  STATUS="PASS"
  REASON_LINE="pwquality.conf(minlen=${MINLEN_VAL:-not_set}, dcredit=${DCREDIT_VAL:-not_set}, ucredit=${UCREDIT_VAL:-not_set}, lcredit=${LCREDIT_VAL:-not_set}, ocredit=${OCREDIT_VAL:-not_set}, enforce_for_root=${PWQ_ENFORCE}), pwhistory.conf(remember=${REMEMBER_VAL:-not_set}, file=${OPASSWD_FILE_VAL:-not_set}, enforce_for_root=${PWH_ENFORCE}), login.defs(PASS_MAX_DAYS=${MAX_DAYS_VAL:-not_set}, PASS_MIN_DAYS=${MIN_DAYS_VAL:-not_set}), pam(pwquality_present=${PAM_PWQ_OK}, pwhistory_present=${PAM_PWH_OK}, order_ok=${PAM_ORDER_OK_ALL})로 설정되어 있어 이 항목에 대해 양호합니다."
fi

# 취약 시 자동 조치를 가정한 가이드와 주의사항을 제공합니다(양호 시에도 동일 형식 유지).
GUIDE_LINE=$(cat <<'EOF'
자동 조치: /etc/security/pwquality.conf에 minlen=8, minclass=3, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1 및 enforce_for_root를 설정합니다.
/etc/security/pwhistory.conf에 remember=4, file=/etc/security/opasswd 및 enforce_for_root를 설정합니다.
/etc/login.defs에 PASS_MAX_DAYS=90 및 PASS_MIN_DAYS=1을 설정합니다.
/etc/pam.d/system-auth 및 /etc/pam.d/password-auth에서 pam_pwquality.so와 pam_pwhistory.so 적용 여부를 확인하고 pam_unix.so 위에 위치하도록 정리합니다.
주의사항: 
정책 강화로 인해 사용자가 비밀번호 변경 시 조건을 충족하지 못하면 변경이 실패할 수 있습니다.
서비스 계정/운영 절차가 단순 비밀번호 규칙을 전제로 하는 경우 인증 실패가 발생할 수 있습니다.
authselect로 PAM이 관리되는 환경에서는 파일 직접 수정이 재적용 과정에서 덮어써져 변경이 유지되지 않을 수 있습니다.
EOF
)

COMMAND_ONE_LINE="$(echo "$CHECK_COMMAND" | sed ':a;N;$!ba;s/\n/ /g' | sed 's/[[:space:]]\+/ /g' | sed 's/^ *//;s/ *$//')"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$COMMAND_ONE_LINE",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape_multiline "$RAW_EVIDENCE")"

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
