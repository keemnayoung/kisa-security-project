#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-57
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : Ftpusers 파일 설정
# @Description : FTP 서비스에 root 계정 접근 제한 설정 여부 점검
# @Criteria_Good : root 계정 접속을 차단한 경우
# @Criteria_Bad : root 계정 접속을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-57"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='command -v vsftpd proftpd 2>/dev/null; systemctl is-active vsftpd proftpd 2>/dev/null; grep -nE "^[[:space:]]*(userlist_enable|userlist_deny|userlist_file)[[:space:]]*=" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*(UseFtpUsers|RootLogin)[[:space:]]+" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*root[[:space:]]*$" /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
VULN=0
FTP_FOUND=0
DETAIL_LINES=""

VS_REASON_OK=""
PF_REASON_OK=""
VULN_REASON=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\\n}$1"; }
add_file(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }
upper(){ echo "${1:-}" | tr '[:lower:]' '[:upper:]'; }

has_root_line(){
  local f="$1"
  [ -f "$f" ] || return 2
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | grep -qE '^[[:space:]]*root[[:space:]]*$'
}

vs_kv(){
  local conf="$1" key="$2"
  grep -iE "^[[:space:]]*${key}[[:space:]]*=" "$conf" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 \
    | sed -E 's/.*=[[:space:]]*//; s/[[:space:]]*$//'
}

set_vuln_reason_once(){
  [ -z "$VULN_REASON" ] && VULN_REASON="$1"
}

VS_CONF=""
[ -f /etc/vsftpd.conf ] && VS_CONF="/etc/vsftpd.conf"
[ -z "$VS_CONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VS_CONF="/etc/vsftpd/vsftpd.conf"

if command -v vsftpd >/dev/null 2>&1 || [ -n "$VS_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
  FTP_FOUND=1
  if [ -n "$VS_CONF" ] && [ -f "$VS_CONF" ]; then
    add_file "$VS_CONF"
    ULE="$(vs_kv "$VS_CONF" userlist_enable)"; ULD="$(vs_kv "$VS_CONF" userlist_deny)"; ULF="$(vs_kv "$VS_CONF" userlist_file)"
    ULE="${ULE:-not_set}"; ULD="${ULD:-not_set}"; ULF="${ULF:-not_set}"
    add_detail "[vsftpd] conf=$VS_CONF userlist_enable=$ULE userlist_deny=$ULD userlist_file=$ULF"

    if [ "$(upper "$ULE")" = "YES" ]; then
      LIST_FILE="$ULF"
      if [ "$LIST_FILE" = "not_set" ] || [ -z "$LIST_FILE" ]; then
        LIST_FILE="/etc/vsftpd.user_list"; [ ! -f "$LIST_FILE" ] && LIST_FILE="/etc/vsftpd/user_list"
      fi
      add_file "$LIST_FILE"

      if [ "$(upper "$ULD")" = "NO" ]; then
        if has_root_line "$LIST_FILE"; then
          VULN=1
          set_vuln_reason_once "vsftpd에서 userlist_enable=YES, userlist_deny=NO이고 ${LIST_FILE}에 root가 존재하여 root FTP 접속이 허용될 수 있어 이 항목에 대해 취약합니다."
          add_detail "[vsftpd] userlist_deny=NO(whitelist) & root PRESENT -> root FTP login may be allowed"
        else
          [ -z "$VS_REASON_OK" ] && VS_REASON_OK="userlist_enable=YES, userlist_deny=NO이고 ${LIST_FILE}에 root가 없어 root FTP 접속이 차단되어"
          add_detail "[vsftpd] userlist_deny=NO(whitelist) & root ABSENT -> root FTP login blocked"
        fi
      else
        if has_root_line "$LIST_FILE"; then
          [ -z "$VS_REASON_OK" ] && VS_REASON_OK="userlist_enable=YES, userlist_deny=$(upper "$ULD")이고 ${LIST_FILE}에 root가 존재하여 root FTP 접속이 차단되어"
          add_detail "[vsftpd] userlist_deny!=NO(blacklist) & root PRESENT -> root FTP login blocked"
        else
          VULN=1
          set_vuln_reason_once "vsftpd에서 userlist_enable=YES, userlist_deny=$(upper "$ULD")인데 ${LIST_FILE}에 root가 없어 root FTP 접속이 허용될 수 있어 이 항목에 대해 취약합니다."
          add_detail "[vsftpd] userlist_deny!=NO(blacklist) & root ABSENT -> root FTP login may be allowed"
        fi
      fi
    else
      F="/etc/vsftpd.ftpusers"; [ ! -f "$F" ] && F="/etc/vsftpd/ftpusers"; [ ! -f "$F" ] && F="/etc/ftpusers"
      add_file "$F"
      if has_root_line "$F"; then
        [ -z "$VS_REASON_OK" ] && VS_REASON_OK="userlist_enable=$(upper "$ULE")이고 ${F}에 root가 존재하여 root FTP 접속이 차단되어"
        add_detail "[vsftpd] ftpusers has root -> root FTP login blocked"
      else
        VULN=1
        set_vuln_reason_once "vsftpd에서 userlist_enable=$(upper "$ULE")인데 ${F}에서 root 차단을 확인할 수 없어 root FTP 접속이 허용될 수 있어 이 항목에 대해 취약합니다."
        add_detail "[vsftpd] ftpusers missing root(or file missing) -> root FTP login may be allowed"
      fi
    fi
  else
    VULN=1
    set_vuln_reason_once "vsftpd가 감지되었으나 설정 파일을 찾지 못해 root 차단 설정을 확인할 수 없어 이 항목에 대해 취약합니다."
    add_detail "[vsftpd] detected but config NOT_FOUND -> cannot verify root block policy"
  fi
fi

PF_CONF=""
[ -f /etc/proftpd/proftpd.conf ] && PF_CONF="/etc/proftpd/proftpd.conf"
[ -z "$PF_CONF" ] && [ -f /etc/proftpd.conf ] && PF_CONF="/etc/proftpd.conf"

if command -v proftpd >/dev/null 2>&1 || [ -n "$PF_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
  FTP_FOUND=1
  if [ -n "$PF_CONF" ] && [ -f "$PF_CONF" ]; then
    add_file "$PF_CONF"
    USE="$(grep -Ei '^[[:space:]]*UseFtpUsers[[:space:]]+' "$PF_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
    USE="${USE:-on}"
    add_detail "[proftpd] conf=$PF_CONF UseFtpUsers=$USE"

    if [ "$USE" = "off" ]; then
      RL="$(grep -Ei '^[[:space:]]*RootLogin[[:space:]]+' "$PF_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
      RL="${RL:-not_set}"
      add_detail "[proftpd] RootLogin=$RL"
      if [ "$RL" = "off" ]; then
        [ -z "$PF_REASON_OK" ] && PF_REASON_OK="UseFtpUsers=off이고 RootLogin=off로 설정되어 root FTP 접속이 차단되어"
        add_detail "[proftpd] RootLogin off -> root FTP login blocked"
      else
        VULN=1
        set_vuln_reason_once "proftpd에서 UseFtpUsers=off인데 RootLogin=off가 아니어서 root FTP 접속이 허용될 수 있어 이 항목에 대해 취약합니다."
        add_detail "[proftpd] UseFtpUsers off but RootLogin off NOT set -> root FTP login may be allowed"
      fi
    else
      FU="/etc/ftpusers"; [ ! -f "$FU" ] && FU="/etc/ftpd/ftpusers"
      add_file "$FU"
      if has_root_line "$FU"; then
        [ -z "$PF_REASON_OK" ] && PF_REASON_OK="UseFtpUsers=${USE}이고 ${FU}에 root가 존재하여 root FTP 접속이 차단되어"
        add_detail "[proftpd] ftpusers has root -> root FTP login blocked"
      else
        VULN=1
        set_vuln_reason_once "proftpd에서 UseFtpUsers=${USE}인데 ${FU}에서 root 차단을 확인할 수 없어 root FTP 접속이 허용될 수 있어 이 항목에 대해 취약합니다."
        add_detail "[proftpd] ftpusers missing root(or file missing) -> root FTP login may be allowed"
      fi
    fi
  else
    VULN=1
    set_vuln_reason_once "proftpd가 감지되었으나 설정 파일을 찾지 못해 root 차단 설정을 확인할 수 없어 이 항목에 대해 취약합니다."
    add_detail "[proftpd] detected but config NOT_FOUND -> cannot verify root block policy"
  fi
fi

if [ "$FTP_FOUND" -eq 0 ]; then
  if [ -f /etc/ftpusers ] || [ -f /etc/ftpd/ftpusers ]; then
    FU="/etc/ftpusers"; [ ! -f "$FU" ] && FU="/etc/ftpd/ftpusers"
    add_file "$FU"
    if has_root_line "$FU"; then
      STATUS="PASS"
      REASON_LINE="${FU}에 root가 존재하여 root FTP 접속이 차단되어 이 항목에 대해 양호합니다."
      DETAIL_CONTENT="[fallback] ftp_service=not_detected, root_blocked=Y, file=$FU"
    else
      STATUS="FAIL"
      REASON_LINE="${FU}에서 root 차단을 확인할 수 없어 root FTP 접속이 허용될 수 있어 이 항목에 대해 취약합니다."
      DETAIL_CONTENT="[fallback] ftp_service=not_detected, root_blocked=NOT_CONFIRMED, file=$FU"
    fi
  else
    STATUS="PASS"
    REASON_LINE="FTP 서비스가 확인되지 않아 점검 대상이 제한적이어서 이 항목에 대해 양호합니다."
    DETAIL_CONTENT="ftp_service=not_detected"
  fi
else
  DETAIL_CONTENT="${DETAIL_LINES:-none}"
  if [ "$VULN" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="${VULN_REASON:-root 차단 설정을 확인할 수 없어 root FTP 접속이 허용될 수 있어 이 항목에 대해 취약합니다.}"
  else
    STATUS="PASS"
    if [ -n "$VS_REASON_OK" ] && [ -n "$PF_REASON_OK" ]; then
      REASON_LINE="vsftpd는 ${VS_REASON_OK} 있으며 proftpd는 ${PF_REASON_OK} 있어 이 항목에 대해 양호합니다."
    elif [ -n "$VS_REASON_OK" ]; then
      REASON_LINE="vsftpd는 ${VS_REASON_OK} 있어 이 항목에 대해 양호합니다."
    elif [ -n "$PF_REASON_OK" ]; then
      REASON_LINE="proftpd는 ${PF_REASON_OK} 있어 이 항목에 대해 양호합니다."
    else
      REASON_LINE="root FTP 접속 차단 설정이 확인되어 이 항목에 대해 양호합니다."
    fi
  fi
fi

[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/ftpusers, /etc/ftpd/ftpusers, /etc/vsftpd.user_list, /etc/vsftpd/user_list, /etc/vsftpd.ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf, /etc/proftpd/proftpd.conf, /etc/proftpd.conf"

GUIDE_LINE=$(cat <<'EOF'
자동 조치:
vsftpd는 userlist_enable/userlist_deny/userlist_file 동작에 맞춰 차단 목록(ftpusers 또는 user_list)에 root를 추가하거나 화이트리스트 모드에서는 root를 목록에서 제거합니다.
proftpd는 UseFtpUsers 사용 시 /etc/ftpusers에 root 차단을 적용하고, UseFtpUsers=off인 경우 RootLogin off를 설정 파일에 반영합니다.
주의사항:
FTP를 실제 운영 중인 서버에서는 차단 목록 변경이 계정 정책 및 운영 절차에 영향을 줄 수 있고 서비스 재시작이 연결을 끊을 수 있으므로 적용 전 점검 창구 및 서비스 영향도를 확인해야 합니다.
EOF
)

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# escape 처리(따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
