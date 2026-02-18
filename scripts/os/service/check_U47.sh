#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-47
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 스팸 메일 릴레이 제한
# @Description : SMTP 서버의 릴레이 기능 제한 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-47"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE=""

CHECK_COMMAND=$(cat <<'EOF'
( command -v sendmail >/dev/null 2>&1 && sendmail -d0 < /dev/null 2>/dev/null );
( [ -f /etc/mail/sendmail.cf ] && grep -inE "promiscuous_relay|Relaying denied" /etc/mail/sendmail.cf 2>/dev/null );
( command -v postconf >/dev/null 2>&1 && postconf -n 2>/dev/null );
( [ -f /etc/postfix/main.cf ] && grep -nE "^(mynetworks|smtpd_(relay|recipient)_restrictions)[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null );
( command -v exim >/dev/null 2>&1 && exim -bV 2>/dev/null );
( command -v exim4 >/dev/null 2>&1 && exim4 -bV 2>/dev/null );
( grep -nE "relay_from_hosts|accept[[:space:]]+hosts[[:space:]]*=.*\\+relay_from_hosts" /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/update-exim4.conf.conf 2>/dev/null );
EOF
)

FOUND_ANY=0
VULNERABLE=0

DETAIL_LINES=""
REASON_SNIPPET=""

append_detail() {
  local line="$1"
  [ -z "$line" ] && return 0
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

add_target_file() {
  local f="$1"
  [ -z "$f" ] && return 0
  if [ -z "$TARGET_FILE" ]; then
    TARGET_FILE="$f"
  else
    TARGET_FILE="${TARGET_FILE}, $f"
  fi
}

contains_open_all_network() {
  echo "$1" | grep -qE '(^|[[:space:],])0\.0\.0\.0/0($|[[:space:],])|(^|[[:space:],])::/0($|[[:space:],])|(^|[[:space:],])0/0($|[[:space:],])'
}

pick_val_from_kv_line() {
  echo "$1" | sed -E 's/^[0-9]+://; s/^[[:space:]]*[^=]+=[[:space:]]*//'
}

set_reason_once() {
  # 가장 핵심 1개만 reason에 넣기 위해 최초 1회만 세팅
  local snippet="$1"
  [ -z "$snippet" ] && return 0
  if [ -z "$REASON_SNIPPET" ]; then
    REASON_SNIPPET="$snippet"
  fi
}

json_escape() {
  echo "$1" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

if command -v sendmail >/dev/null 2>&1; then
  FOUND_ANY=1

  SM_CF="/etc/mail/sendmail.cf"
  SM_MC="/etc/mail/sendmail.mc"
  SM_ACCESS="/etc/mail/access"
  SM_ACCESS_DB="/etc/mail/access.db"

  add_target_file "$SM_CF"
  [ -f "$SM_MC" ] && add_target_file "$SM_MC"
  add_target_file "$SM_ACCESS"
  add_target_file "$SM_ACCESS_DB"

  SM_VER_RAW="$(sendmail -d0 < /dev/null 2>/dev/null | grep -i 'Version' | head -n1)"
  SM_VER="$(echo "$SM_VER_RAW" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
  [ -z "$SM_VER" ] && SM_VER="unknown"
  append_detail "[sendmail] version=${SM_VER}"

  if [ ! -f "$SM_CF" ]; then
    VULNERABLE=1
    set_reason_once "sendmail.cf=NOT_FOUND"
    append_detail "[sendmail] sendmail.cf=NOT_FOUND"
  else
    if grep -q "promiscuous_relay" "$SM_CF" 2>/dev/null; then
      VULNERABLE=1
      set_reason_once "promiscuous_relay=FOUND"
      append_detail "[sendmail] $(grep -n "promiscuous_relay" "$SM_CF" 2>/dev/null | head -n 3)"
    else
      append_detail "[sendmail] promiscuous_relay=NOT_FOUND"
    fi

    if grep -q "Relaying denied" "$SM_CF" 2>/dev/null; then
      append_detail "[sendmail] Relaying denied=FOUND"
    else
      append_detail "[sendmail] Relaying denied=NOT_FOUND"
    fi
  fi

  if [ -f "$SM_MC" ] && grep -qE 'FEATURE\(\s*`promiscuous_relay`\s*\)' "$SM_MC" 2>/dev/null; then
    VULNERABLE=1
    set_reason_once "promiscuous_relay=FOUND"
    append_detail "[sendmail] $(grep -nE 'FEATURE\(\s*`promiscuous_relay`\s*\)' "$SM_MC" 2>/dev/null | head -n 3)"
  fi

  if [ -f "$SM_ACCESS" ]; then
    append_detail "[sendmail] access=FOUND"
    append_detail "[sendmail] access_tail:\n$(tail -n 20 "$SM_ACCESS" 2>/dev/null)"
  else
    append_detail "[sendmail] access=NOT_FOUND"
  fi

  if [ -f "$SM_ACCESS_DB" ]; then
    append_detail "[sendmail] access.db=FOUND"
  else
    append_detail "[sendmail] access.db=NOT_FOUND"
  fi
fi

if command -v postconf >/dev/null 2>&1 || command -v postfix >/dev/null 2>&1; then
  FOUND_ANY=1

  PF_MAIN="/etc/postfix/main.cf"
  add_target_file "$PF_MAIN"

  PF_EFFECTIVE=""
  if command -v postconf >/dev/null 2>&1; then
    PF_EFFECTIVE="$(postconf -n 2>/dev/null)"
  fi

  get_pf_param() {
    local key="$1"
    local line=""
    if [ -n "$PF_EFFECTIVE" ]; then
      line="$(echo "$PF_EFFECTIVE" | grep -E "^${key}[[:space:]]*=" | head -n1)"
      [ -n "$line" ] && { echo "$line"; return 0; }
    fi
    if [ -f "$PF_MAIN" ]; then
      line="$(grep -nE "^[[:space:]]*${key}[[:space:]]*=" "$PF_MAIN" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"
      [ -n "$line" ] && { echo "$line"; return 0; }
    fi
    echo ""
  }

  PF_MYNETWORKS_LINE="$(get_pf_param "mynetworks")"
  PF_RELAY_LINE="$(get_pf_param "smtpd_relay_restrictions")"
  PF_RCPT_LINE="$(get_pf_param "smtpd_recipient_restrictions")"

  if [ -n "$PF_MYNETWORKS_LINE" ]; then
    PF_MY_VAL="$(pick_val_from_kv_line "$PF_MYNETWORKS_LINE")"
    append_detail "[postfix] mynetworks=${PF_MY_VAL}"

    if contains_open_all_network "$PF_MYNETWORKS_LINE"; then
      VULNERABLE=1
      set_reason_once "mynetworks=${PF_MY_VAL}"
    fi
  else
    append_detail "[postfix] mynetworks=NOT_SET"
  fi

  FOUND_REJECT="N"
  echo "$PF_RELAY_LINE $PF_RCPT_LINE" | grep -q "reject_unauth_destination" && FOUND_REJECT="Y"

  if [ "$FOUND_REJECT" = "Y" ]; then
    append_detail "[postfix] reject_unauth_destination=FOUND"
    # PASS 이유는 가능한 한 짧게 1개만: 보호 핵심 신호
    [ $VULNERABLE -eq 0 ] && set_reason_once "reject_unauth_destination=FOUND"
  else
    VULNERABLE=1
    set_reason_once "reject_unauth_destination=NOT_FOUND"
    append_detail "[postfix] reject_unauth_destination=NOT_FOUND"
  fi

  [ -n "$PF_RELAY_LINE" ] && append_detail "[postfix] smtpd_relay_restrictions=$(pick_val_from_kv_line "$PF_RELAY_LINE")"
  [ -n "$PF_RCPT_LINE" ] && append_detail "[postfix] smtpd_recipient_restrictions=$(pick_val_from_kv_line "$PF_RCPT_LINE")"
fi

EXIM_CMD=""
command -v exim >/dev/null 2>&1 && EXIM_CMD="exim"
[ -z "$EXIM_CMD" ] && command -v exim4 >/dev/null 2>&1 && EXIM_CMD="exim4"

if [ -n "$EXIM_CMD" ]; then
  FOUND_ANY=1

  CONF_FILES=(
    "/etc/exim/exim.conf"
    "/etc/exim4/exim4.conf"
    "/etc/exim4/update-exim4.conf.conf"
  )

  FOUND_CONF="N"
  for conf in "${CONF_FILES[@]}"; do
    if [ -f "$conf" ]; then
      FOUND_CONF="Y"
      add_target_file "$conf"

      RELAY_LINE="$(grep -v '^[[:space:]]*#' "$conf" 2>/dev/null | grep -E '^[[:space:]]*relay_from_hosts[[:space:]]*=' | head -n1)"
      append_detail "[exim] config=${conf}"

      if [ -n "$RELAY_LINE" ]; then
        EXIM_VAL="$(pick_val_from_kv_line "$RELAY_LINE")"
        append_detail "[exim] relay_from_hosts=${EXIM_VAL}"

        echo "$RELAY_LINE" | grep -qE '(^|[[:space:]=,])\*($|[[:space:],])|0\.0\.0\.0/0|::/0|0/0' && {
          VULNERABLE=1
          set_reason_once "relay_from_hosts=${EXIM_VAL}"
        }
      else
        append_detail "[exim] relay_from_hosts=NOT_SET"
      fi

      if grep -qE 'accept[[:space:]]+hosts[[:space:]]*=[[:space:]]*\+relay_from_hosts' "$conf" 2>/dev/null; then
        append_detail "[exim] acl_accept_hosts_plus_relay_from_hosts=FOUND"
      else
        append_detail "[exim] acl_accept_hosts_plus_relay_from_hosts=NOT_FOUND"
      fi

      break
    fi
  done

  if [ "$FOUND_CONF" = "N" ]; then
    VULNERABLE=1
    set_reason_once "exim_config=NOT_FOUND"
    append_detail "[exim] config_file=NOT_FOUND"
  fi
fi

DETAIL_CONTENT="$DETAIL_LINES"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_SNIPPET="mail_service=NOT_INSTALLED"
else
  if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    [ -z "$REASON_SNIPPET" ] && REASON_SNIPPET="relay_control=INSUFFICIENT"
  else
    STATUS="PASS"
    [ -z "$REASON_SNIPPET" ] && REASON_SNIPPET="relay_control=RESTRICTED"
  fi
fi

if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="${REASON_SNIPPET}로 이 항목에 대해 양호합니다."
else
  REASON_LINE="${REASON_SNIPPET}로 이 항목에 대해 취약합니다."
fi

GUIDE_LINE=$'이 항목은 자동 조치 시 허용 릴레이 대상(네트워크/호스트) 오판으로 메일 발송/수신 장애가 발생할 수 있어 수동 조치가 필요합니다.
관리자가 서비스 사용 여부와 허용 대상 범위를 확인한 뒤 설정을 조치해 주시기 바랍니다.
Sendmail은 promiscuous_relay를 제거하고 access/access.db에 허용 대상을 RELAY/REJECT로 구성한 후 적용하십시오.
Postfix는 mynetworks를 내부망으로 제한하고 smtpd_(relay/recipient)_restrictions에 reject_unauth_destination를 포함한 뒤 재적용하십시오.
Exim은 relay_from_hosts 허용 범위를 내부망으로 제한하고 ACL 정책을 함께 점검한 뒤 재적용하십시오.'

[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/mail/sendmail.cf, /etc/mail/sendmail.mc, /etc/mail/access, /etc/mail/access.db, /etc/postfix/main.cf, /etc/exim/exim.conf, /etc/exim4/exim4.conf, /etc/exim4/update-exim4.conf.conf"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
