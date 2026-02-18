#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-56
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스 접근 제어(ftpusers/user_list/<Limit LOGIN>) 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-56"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='
command -v vsftpd proftpd 2>/dev/null;
systemctl is-active vsftpd proftpd 2>/dev/null;
grep -nE "^(userlist_enable|userlist_file|ftpusers|UseFtpUsers|<Limit[[:space:]]+LOGIN>)" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null;
ls -l /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null;
grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/inetd.conf /etc/xinetd.d/ftp 2>/dev/null | head -n 50
' | tr '\n' ' '

VULN=0
FTP_IN_USE=0
DETAIL_LINES=""

PASS_REASON_PARTS=""
FAIL_REASON_PARTS=""

append_detail() { [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\n}$1"; }
add_target() { [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

add_pass_reason(){ [ -n "${1:-}" ] && PASS_REASON_PARTS="${PASS_REASON_PARTS}${PASS_REASON_PARTS:+, }$1"; }
add_fail_reason(){ [ -n "${1:-}" ] && FAIL_REASON_PARTS="${FAIL_REASON_PARTS}${FAIL_REASON_PARTS:+, }$1"; }

noncomment_grep() { # $1=file $2=regex
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$1" 2>/dev/null | grep -qE "$2"
}

perm_ok_640() { # $1=perm(3~4digits)
  local p="$1"
  [ -z "$p" ] && return 1
  [[ "$p" =~ ^[0-7]{3,4}$ ]] || return 1
  [ ${#p} -eq 4 ] && p="${p:1}"
  [ "$p" -le 640 ]
}

check_list_file() { # $1=path $2=label
  local f="$1" label="$2"
  if [ ! -f "$f" ]; then
    VULN=1
    append_detail "[$label] path=$f exists=no"
    add_fail_reason "$label path=$f exists=no"
    return
  fi

  local owner perm lines
  owner="$(stat -c '%U' "$f" 2>/dev/null || echo unknown)"
  perm="$(stat -c '%a' "$f" 2>/dev/null || echo unknown)"
  lines="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | wc -l | tr -d ' ')"

  append_detail "[$label] path=$f exists=yes owner=$owner perm=$perm noncomment_lines=$lines"

  local bad=""
  [ "$owner" = "root" ] || bad="${bad}${bad:+; }owner=$owner"
  perm_ok_640 "$perm" || bad="${bad}${bad:+; }perm=$perm"
  [ "${lines:-0}" -ge 1 ] || bad="${bad}${bad:+; }noncomment_lines=${lines:-0}"

  if [ -n "$bad" ]; then
    VULN=1
    add_fail_reason "$label $bad"
  else
    add_pass_reason "$label path=$f owner=root perm=$perm noncomment_lines=$lines"
  fi
}

get_limit_login_rule() { # $1=conf
  sed -n '/<Limit[[:space:]]\+LOGIN>/,/<\/Limit>/p' "$1" 2>/dev/null \
    | grep -iE 'AllowUser|DenyUser|Allow[[:space:]]+from|Deny[[:space:]]+from' \
    | head -n 1
}

# 분기: vsftpd/proftpd 설정 파일 위치 탐색
VSFTPD_CONF=""
[ -f /etc/vsftpd.conf ] && VSFTPD_CONF="/etc/vsftpd.conf"
[ -z "$VSFTPD_CONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"

PROFTPD_CONF=""
[ -f /etc/proftpd/proftpd.conf ] && PROFTPD_CONF="/etc/proftpd/proftpd.conf"
[ -z "$PROFTPD_CONF" ] && [ -f /etc/proftpd.conf ] && PROFTPD_CONF="/etc/proftpd.conf"

# 분기: inetd/xinetd 기반 FTP 활성 여부 단서 확인
INETD_FTP=0
[ -f /etc/inetd.conf ] && noncomment_grep /etc/inetd.conf '^[[:space:]]*ftp([[:space:]]|$)' && INETD_FTP=1

XINETD_FTP=0
[ -f /etc/xinetd.d/ftp ] && noncomment_grep /etc/xinetd.d/ftp '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' && XINETD_FTP=1

# 분기: FTP 사용 여부 최소 판정
if systemctl is-active --quiet vsftpd 2>/dev/null || [ -n "$VSFTPD_CONF" ] || \
   systemctl is-active --quiet proftpd 2>/dev/null || [ -n "$PROFTPD_CONF" ] || \
   [ "$INETD_FTP" -eq 1 ] || [ "$XINETD_FTP" -eq 1 ]; then
  FTP_IN_USE=1
fi

# 분기: vsftpd 점검(사용 중이면 적용 경로 결정)
if [ "$FTP_IN_USE" -eq 1 ] && ( command -v vsftpd >/dev/null 2>&1 || [ -n "$VSFTPD_CONF" ] || systemctl is-active --quiet vsftpd 2>/dev/null ); then
  add_target "${VSFTPD_CONF:-/etc/vsftpd.conf(/etc/vsftpd/vsftpd.conf)}"

  if [ -n "$VSFTPD_CONF" ] && [ -f "$VSFTPD_CONF" ]; then
    UL_EN="$(grep -Ei '^[[:space:]]*userlist_enable[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}')"
    UL_FILE="$(grep -Ei '^[[:space:]]*userlist_file[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk -F= '{gsub(/^[[:space:]]*/,"",$2); print $2}')"
    [ -z "$UL_EN" ] && UL_EN="(not_set)"

    append_detail "[vsftpd] conf=$VSFTPD_CONF userlist_enable=$UL_EN"

    if [ "$UL_EN" = "yes" ]; then
      [ -z "$UL_FILE" ] && UL_FILE="/etc/vsftpd.user_list"
      [ ! -f "$UL_FILE" ] && UL_FILE="/etc/vsftpd/user_list"
      add_target "$UL_FILE"
      check_list_file "$UL_FILE" "vsftpd_user_list"
    else
      FU="/etc/vsftpd.ftpusers"
      [ ! -f "$FU" ] && FU="/etc/vsftpd/ftpusers"
      [ ! -f "$FU" ] && FU="/etc/ftpusers"
      add_target "$FU"
      check_list_file "$FU" "vsftpd_ftpusers"
    fi
  else
    VULN=1
    append_detail "[vsftpd] conf=not_found"
    add_fail_reason "vsftpd conf=not_found"
  fi
fi

# 분기: proftpd 점검(UseFtpUsers 설정에 따라 점검 경로 결정)
if [ "$FTP_IN_USE" -eq 1 ] && ( command -v proftpd >/dev/null 2>&1 || [ -n "$PROFTPD_CONF" ] || systemctl is-active --quiet proftpd 2>/dev/null ); then
  add_target "${PROFTPD_CONF:-/etc/proftpd/proftpd.conf(/etc/proftpd.conf)}"

  if [ -n "$PROFTPD_CONF" ] && [ -f "$PROFTPD_CONF" ]; then
    USE="$(grep -Ei '^[[:space:]]*UseFtpUsers[[:space:]]+' "$PROFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
    [ -z "$USE" ] && USE="on"
    append_detail "[proftpd] conf=$PROFTPD_CONF UseFtpUsers=$USE"

    if [ "$USE" = "off" ]; then
      rule="$(get_limit_login_rule "$PROFTPD_CONF")"
      if [ -n "$rule" ]; then
        append_detail "[proftpd] limit_login_rule=$(echo "$rule" | tr -s ' ')"
        add_pass_reason "proftpd <Limit LOGIN> rule=$(echo "$rule" | tr -s ' ')"
      else
        VULN=1
        append_detail "[proftpd] limit_login_rule=not_found"
        add_fail_reason "proftpd <Limit LOGIN> rule=not_found"
      fi
    else
      FU="/etc/ftpusers"
      [ ! -f "$FU" ] && FU="/etc/ftpd/ftpusers"
      add_target "$FU"
      check_list_file "$FU" "proftpd_ftpusers"
    fi
  else
    VULN=1
    append_detail "[proftpd] conf=not_found"
    add_fail_reason "proftpd conf=not_found"
  fi
fi

# 분기: inetd/xinetd 기반 FTP가 있으면 ftpusers 점검
if [ "$INETD_FTP" -eq 1 ] || [ "$XINETD_FTP" -eq 1 ]; then
  FTP_IN_USE=1
  [ "$INETD_FTP" -eq 1 ] && add_target "/etc/inetd.conf" && append_detail "[inetd] ftp_service=enabled"
  [ "$XINETD_FTP" -eq 1 ] && add_target "/etc/xinetd.d/ftp" && append_detail "[xinetd] ftp_service=enabled"

  FU="/etc/ftpusers"
  [ ! -f "$FU" ] && FU="/etc/ftpd/ftpusers"
  add_target "$FU"
  check_list_file "$FU" "ftpd_ftpusers"
fi

# 분기: 최종 판정 및 reason/detail 문장 구성
if [ "$FTP_IN_USE" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="FTP 서비스가 비활성화되어 이 항목에 대해 양호합니다."
  DETAIL_CONTENT="ftp_in_use=0"
  add_pass_reason "ftp_in_use=0"
else
  DETAIL_CONTENT="${DETAIL_LINES:-none}"

  if [ "$VULN" -eq 1 ]; then
    STATUS="FAIL"
    [ -z "$FAIL_REASON_PARTS" ] && FAIL_REASON_PARTS="접근제어 설정값 확인 불가"
    REASON_LINE="${FAIL_REASON_PARTS}로 이 항목에 대해 취약합니다."
  else
    STATUS="PASS"
    [ -z "$PASS_REASON_PARTS" ] && PASS_REASON_PARTS="접근제어 설정값이 확인됨"
    REASON_LINE="${PASS_REASON_PARTS}로 이 항목에 대해 양호합니다."
  fi
fi

[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

GUIDE_LINE=$(cat <<'EOF'
자동 조치로 허용 IP/호스트 또는 허용 사용자 정책이 임의로 변경되면 정상 업무 접속이 차단되거나 예외 접속이 허용되어 서비스 장애 및 운영 정책 위반 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 FTP 접근을 허용할 IP/호스트 또는 허용 사용자만 남기도록 접근 제어를 설정하고, vsftpd는 userlist_enable/userlist_file 또는 ftpusers를, proftpd는 UseFtpUsers 또는 <Limit LOGIN> 규칙을 정책에 맞게 구성해 주시기 바랍니다.
차단/허용 목록 파일은 root 소유 및 권한 640 이하로 설정하고, 적용 후 FTP 서비스를 재시작해 주시기 바랍니다.
EOF
)

# raw_evidence 구성(각 값은 줄바꿈으로 문장 구분)
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

# escape 처리(따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history JSON 출력(직전 echo "" 필수)
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
