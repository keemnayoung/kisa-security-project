#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-62
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 로그인 시 경고 메시지 설정
# @Description : 서버 및 서비스에 로그온 시 불필요한 정보 차단 설정 및 불법적인 사용에 대한 경고 메시지 출력 여부 점검
# @Criteria_Good : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정된 경우
# @Criteria_Bad : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정되어 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-62"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/issue, /etc/motd, /etc/issue.net, /etc/ssh/sshd_config, (서비스별 설정파일)"
CHECK_COMMAND='
ls -l /etc/issue /etc/issue.net /etc/motd 2>/dev/null;
wc -c /etc/issue /etc/issue.net /etc/motd 2>/dev/null;
grep -nEi "^[[:space:]]*Banner[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null;
systemctl is-active sshd 2>/dev/null;
systemctl is-active vsftpd proftpd postfix sendmail exim named 2>/dev/null;
grep -nEi "^[[:space:]]*ftpd_banner[[:space:]]*=" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null;
grep -nEi "^[[:space:]]*DisplayLogin[[:space:]]+" /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null;
grep -nEi "^[[:space:]]*smtpd_banner[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null;
grep -nEi "^[[:space:]]*SmtpGreetingMessage" /etc/mail/sendmail.cf 2>/dev/null;
grep -nEi "^[[:space:]]*smtp_banner[[:space:]]*=" /etc/exim/exim.conf /etc/exim4/exim4.conf 2>/dev/null;
grep -nEi "^[[:space:]]*version[[:space:]]+" /etc/named.conf /etc/bind/named.conf.options 2>/dev/null;
( [ -f /etc/xinetd.d/telnet ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/xinetd.d/telnet | head -n 80 ) 2>/dev/null;
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/inetd.conf | grep -nEi "^[[:space:]]*telnet([[:space:]]|$)" ) 2>/dev/null
'

DETAIL_LINES=""
BAD_LINES=""
PASS_SUMMARY=""
VULN=0

append_all(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\\n}$1"; }
append_bad(){ [ -n "${1:-}" ] && BAD_LINES="${BAD_LINES}${BAD_LINES:+, }$1"; }
append_pass(){ [ -n "${1:-}" ] && PASS_SUMMARY="${PASS_SUMMARY}${PASS_SUMMARY:+, }$1"; }

has_content() { # 공백/주석 제외 실내용 존재 여부
  [ -f "$1" ] || return 1
  grep -Ev '^[[:space:]]*$|^[[:space:]]*#' "$1" 2>/dev/null | tr -d '[:space:]' | grep -q .
}

svc_active(){ command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$1" 2>/dev/null; }

grep_uc_last(){ # uncommented last match
  local f="$1" r="$2"
  [ -f "$f" ] || return 1
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | grep -Ei "$r" | tail -n 1
}

# 로컬(서버) 경고 문구 확인
LOCAL_OK=0
if has_content /etc/issue; then append_all "[server] /etc/issue=HAS_WARNING_MESSAGE"; append_pass "/etc/issue=HAS_WARNING_MESSAGE"; LOCAL_OK=1
else append_all "[server] /etc/issue=EMPTY_OR_NOT_FOUND"; VULN=1; append_bad "/etc/issue=EMPTY_OR_NOT_FOUND"; fi

if has_content /etc/motd; then append_all "[server] /etc/motd=HAS_WARNING_MESSAGE"; append_pass "/etc/motd=HAS_WARNING_MESSAGE"; LOCAL_OK=1
else append_all "[server] /etc/motd=EMPTY_OR_NOT_FOUND"; VULN=1; append_bad "/etc/motd=EMPTY_OR_NOT_FOUND"; fi

[ "$LOCAL_OK" -eq 1 ] || { VULN=1; append_all "[result] local_warning=NOT_SET"; append_bad "local_warning=NOT_SET"; }

# SSH 사용 시 Banner 설정 확인
if svc_active sshd; then
  BLINE="$(grep_uc_last /etc/ssh/sshd_config '^[[:space:]]*Banner[[:space:]]+')"
  if [ -z "${BLINE:-}" ]; then
    VULN=1; append_all "[ssh] sshd_active=Y, Banner=NOT_SET"; append_bad "sshd_active=Y,Banner=NOT_SET"
  elif echo "$BLINE" | grep -qiE '^[[:space:]]*Banner[[:space:]]+none([[:space:]]|$)'; then
    VULN=1; append_all "[ssh] sshd_active=Y, Banner=none"; append_bad "sshd_active=Y,Banner=none"
  else
    append_all "[ssh] sshd_active=Y, $BLINE"; append_pass "sshd_active=Y,$(echo "$BLINE" | tr -s ' ')"
  fi
else
  append_all "[ssh] sshd_active=N"; append_pass "sshd_active=N"
fi

# Telnet 사용 여부 판단 후 /etc/issue.net 확인
TELNET_USED=0
if [ -f /etc/xinetd.d/telnet ] && grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/xinetd.d/telnet 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then TELNET_USED=1; fi
if [ -f /etc/inetd.conf ] && grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -qiE '^[[:space:]]*telnet([[:space:]]|$)'; then TELNET_USED=1; fi

if [ "$TELNET_USED" -eq 1 ]; then
  if has_content /etc/issue.net; then
    append_all "[telnet] used=Y, /etc/issue.net=HAS_WARNING_MESSAGE"; append_pass "telnet_used=Y,/etc/issue.net=HAS_WARNING_MESSAGE"
  else
    VULN=1; append_all "[telnet] used=Y, /etc/issue.net=EMPTY_OR_NOT_FOUND"; append_bad "telnet_used=Y,/etc/issue.net=EMPTY_OR_NOT_FOUND"
  fi
else
  append_all "[telnet] used=N"; append_pass "telnet_used=N"
fi

# FTP 배너 확인(서비스가 active일 때만)
if svc_active vsftpd; then
  VCONF=""; [ -f /etc/vsftpd.conf ] && VCONF="/etc/vsftpd.conf"; [ -z "$VCONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VCONF="/etc/vsftpd/vsftpd.conf"
  VLINE="$( [ -n "$VCONF" ] && grep_uc_last "$VCONF" '^[[:space:]]*ftpd_banner[[:space:]]*=' )"
  if [ -n "${VLINE:-}" ]; then append_all "[ftp] vsftpd_active=Y, $VCONF: $VLINE"; append_pass "vsftpd_active=Y,$(echo "$VLINE" | tr -s ' ')"
  else VULN=1; append_all "[ftp] vsftpd_active=Y, ftpd_banner=NOT_SET($VCONF)"; append_bad "vsftpd_active=Y,ftpd_banner=NOT_SET"; fi
else
  append_all "[ftp] vsftpd_active=N"; append_pass "vsftpd_active=N"
fi

if svc_active proftpd; then
  PCONF=""; [ -f /etc/proftpd.conf ] && PCONF="/etc/proftpd.conf"; [ -z "$PCONF" ] && [ -f /etc/proftpd/proftpd.conf ] && PCONF="/etc/proftpd/proftpd.conf"
  DLINE="$( [ -n "$PCONF" ] && grep_uc_last "$PCONF" '^[[:space:]]*DisplayLogin[[:space:]]+' )"
  if [ -n "${DLINE:-}" ]; then
    MSGF="$(echo "$DLINE" | awk '{print $2}' | tr -d '"')"
    if [ -n "${MSGF:-}" ] && has_content "$MSGF"; then
      append_all "[ftp] proftpd_active=Y, $PCONF: $DLINE (message_has_content=Y)"
      append_pass "proftpd_active=Y,$(echo "$DLINE" | tr -s ' '),message_has_content=Y"
    else
      VULN=1; append_all "[ftp] proftpd_active=Y, DisplayLogin_file_empty_or_not_found: ${MSGF:-unknown}"
      append_bad "proftpd_active=Y,DisplayLogin_file_empty_or_not_found:${MSGF:-unknown}"
    fi
  else
    VULN=1; append_all "[ftp] proftpd_active=Y, DisplayLogin=NOT_SET($PCONF)"
    append_bad "proftpd_active=Y,DisplayLogin=NOT_SET"
  fi
else
  append_all "[ftp] proftpd_active=N"; append_pass "proftpd_active=N"
fi

# SMTP 배너 확인(서비스가 active일 때만)
if svc_active postfix; then
  PLINE="$(grep_uc_last /etc/postfix/main.cf '^[[:space:]]*smtpd_banner[[:space:]]*=')"
  if [ -n "${PLINE:-}" ]; then append_all "[smtp] postfix_active=Y, /etc/postfix/main.cf: $PLINE"; append_pass "postfix_active=Y,$(echo "$PLINE" | tr -s ' ')"
  else VULN=1; append_all "[smtp] postfix_active=Y, smtpd_banner=NOT_SET(/etc/postfix/main.cf)"; append_bad "postfix_active=Y,smtpd_banner=NOT_SET"; fi
else
  append_all "[smtp] postfix_active=N"; append_pass "postfix_active=N"
fi

if svc_active sendmail; then
  SLINE="$(grep_uc_last /etc/mail/sendmail.cf '^[[:space:]]*O[[:space:]]+SmtpGreetingMessage|^[[:space:]]*SmtpGreetingMessage')"
  if [ -n "${SLINE:-}" ]; then append_all "[smtp] sendmail_active=Y, /etc/mail/sendmail.cf: $SLINE"; append_pass "sendmail_active=Y,$(echo "$SLINE" | tr -s ' ')"
  else VULN=1; append_all "[smtp] sendmail_active=Y, SmtpGreetingMessage=NOT_SET(/etc/mail/sendmail.cf)"; append_bad "sendmail_active=Y,SmtpGreetingMessage=NOT_SET"; fi
else
  append_all "[smtp] sendmail_active=N"; append_pass "sendmail_active=N"
fi

if svc_active exim; then
  ECONF=""; [ -f /etc/exim/exim.conf ] && ECONF="/etc/exim/exim.conf"; [ -z "$ECONF" ] && [ -f /etc/exim4/exim4.conf ] && ECONF="/etc/exim4/exim4.conf"
  ELINE="$( [ -n "$ECONF" ] && grep_uc_last "$ECONF" '^[[:space:]]*smtp_banner[[:space:]]*=')"
  if [ -n "${ELINE:-}" ]; then append_all "[smtp] exim_active=Y, $ECONF: $ELINE"; append_pass "exim_active=Y,$(echo "$ELINE" | tr -s ' ')"
  else VULN=1; append_all "[smtp] exim_active=Y, smtp_banner=NOT_SET($ECONF)"; append_bad "exim_active=Y,smtp_banner=NOT_SET"; fi
else
  append_all "[smtp] exim_active=N"; append_pass "exim_active=N"
fi

# DNS(version) 확인(서비스가 active일 때만)
if svc_active named; then
  NCONF=""; [ -f /etc/named.conf ] && NCONF="/etc/named.conf"; [ -z "$NCONF" ] && [ -f /etc/bind/named.conf.options ] && NCONF="/etc/bind/named.conf.options"
  NLINE="$( [ -n "$NCONF" ] && grep_uc_last "$NCONF" '^[[:space:]]*version[[:space:]]+' )"
  if [ -n "${NLINE:-}" ]; then append_all "[dns] named_active=Y, $NCONF: $NLINE"; append_pass "named_active=Y,$(echo "$NLINE" | tr -s ' ')"
  else VULN=1; append_all "[dns] named_active=Y, version=NOT_SET($NCONF)"; append_bad "named_active=Y,version=NOT_SET"; fi
else
  append_all "[dns] named_active=N"; append_pass "named_active=N"
fi

# 판정 문장(1문장) — 건수 기반 요약
BAD_COUNT=0
[ -n "$BAD_LINES" ] && BAD_COUNT=$(echo "$BAD_LINES" | tr ',' '\n' | wc -l)

if [ "$VULN" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="서버 경고 메시지와 활성 서비스 배너가 정상적으로 설정되어 있어 이 항목에 대해 양호합니다."
else
  STATUS="FAIL"
  REASON_LINE="경고 메시지 미설정 항목 ${BAD_COUNT}건이 발견되어 이 항목에 대해 취약합니다."
fi

DETAIL_CONTENT="$DETAIL_LINES"
[ -n "$DETAIL_CONTENT" ] || DETAIL_CONTENT="none"

# 자동 조치 가이드(문장별 줄바꿈)
GUIDE_LINE="자동 조치: 
/etc/issue, /etc/motd, /etc/issue.net 파일이 없거나 비어 있으면 경고 문구를 작성하고 root:root, 644로 설정합니다.
sshd가 활성 상태이면 /etc/ssh/sshd_config에 Banner /etc/issue.net을 적용한 뒤 sshd를 재시작합니다.
FTP/SMTP/DNS는 해당 서비스가 활성 상태일 때만 설정파일에 배너(또는 version) 값을 일반 문구로 설정하고 서비스를 재시작합니다.
주의사항: 
서비스 재시작으로 기존 세션이 끊기거나 일시 중단될 수 있습니다.
기존 조직 표준 배너 문구를 덮어쓸 수 있으므로 사전 백업/승인이 필요합니다.
설정 파일 문법 오류가 발생하면 서비스가 기동 실패할 수 있으니 적용 후 설정 검증 및 재기동 결과를 확인해야 합니다."

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

# JSON 저장을 위한 escape 처리 (백슬래시/따옴표/줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
