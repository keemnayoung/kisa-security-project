#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-62
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 로그인 시 경고 메시지 설정
# @Description : 서버 및 서비스에 로그온 시 불필요한 정보 차단 설정 및 불법적인 사용에 대한 경고 메시지 출력 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-62"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0
TARGET_FILE="/etc/motd /etc/issue /etc/issue.net /etc/ssh/sshd_config"
CHECK_COMMAND='(ls -l /etc/motd /etc/issue /etc/issue.net 2>/dev/null || true); (sed -n "1,10p" /etc/motd 2>/dev/null || echo "motd_not_found"); (sed -n "1,10p" /etc/issue 2>/dev/null || echo "issue_not_found"); (sed -n "1,10p" /etc/issue.net 2>/dev/null || echo "issue_net_not_found"); (grep -inE "^[[:space:]]*Banner[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null || echo "sshd_banner_not_set")'
REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""

# 유틸리티 함수 정의
append_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
append_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }
json_escape(){ echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g'; }
svc_active(){ command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$1" 2>/dev/null; }

WARNING_MSG='***************************************************************
* WARNING: Unauthorized access to this system is prohibited.  *
* All activities are monitored and logged.                     *
***************************************************************'

ensure_file(){ 
  local f="$1"
  if [ -f "$f" ]; then
    local c; c="$(tr -d '[:space:]' < "$f" 2>/dev/null || true)"
    [ -n "$c" ] || { printf "%s\n" "$WARNING_MSG" > "$f" 2>/dev/null || return 1; }
  else
    printf "%s\n" "$WARNING_MSG" > "$f" 2>/dev/null || return 1
  fi
  chown root:root "$f" 2>/dev/null || true
  chmod 644 "$f" 2>/dev/null || true
  return 0
}

set_kv_file(){ 
  local f="$1" key_re="$2" new_line="$3"
  [ -f "$f" ] || return 1
  if grep -Eq "$key_re" "$f" 2>/dev/null; then
    sed -i -E "s/$key_re.*/$new_line/" "$f" 2>/dev/null || return 1
  else
    printf "\n%s\n" "$new_line" >> "$f" 2>/dev/null || return 1
  fi
  return 0
}

fail_now(){
  IS_SUCCESS=0
  [ -n "${1:-}" ] && append_detail "$1"
}

# 권한 확인
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 설정 파일을 수정할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="current_user: $(id -un)"
else
  IS_SUCCESS=1

  # OS 배너(motd, issue, issue.net) 조치
  for f in /etc/motd /etc/issue /etc/issue.net; do
    if ensure_file "$f"; then
      append_detail "banner_file_status($f): warning_message_applied"
    else
      fail_now "banner_file_status($f): write_permission_denied"
      append_err "write_failed:$f"
    fi
  done

  # SSH 서비스 배너 설정
  SSHD_CONF="/etc/ssh/sshd_config"
  if svc_active sshd; then
    if [ -f "$SSHD_CONF" ]; then
      sed -i -E '/^[[:space:]]*Banner[[:space:]]+/Id' "$SSHD_CONF" 2>/dev/null || true
      printf "\nBanner /etc/issue.net\n" >> "$SSHD_CONF" 2>/dev/null || { fail_now "ssh_banner_status: config_write_failed"; append_err "sshd_config_write_failed"; }
      if command -v systemctl >/dev/null 2>&1 && systemctl restart sshd >/dev/null 2>&1; then
        append_detail "ssh_banner_setting: Banner /etc/issue.net"
        append_detail "ssh_service_restart: success"
      else
        fail_now "ssh_service_restart: failed"
        append_err "sshd_restart_failed"
      fi
    else
      fail_now "ssh_config_file: not_found"
    fi
  else
    append_detail "ssh_service_status: inactive(skipped)"
  fi

  # 활성 네트워크 서비스(Mail, FTP, DNS) 배너 조치
  if svc_active postfix && [ -f /etc/postfix/main.cf ]; then
    set_kv_file /etc/postfix/main.cf '^[[:space:]]*smtpd_banner[[:space:]]*=' 'smtpd_banner = ESMTP' >/dev/null 2>&1
    systemctl restart postfix >/dev/null 2>&1 || true
    append_detail "postfix_banner: $(grep -E '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n 1)"
  fi

  if svc_active vsftpd; then
    VCONF=""; [ -f /etc/vsftpd.conf ] && VCONF=/etc/vsftpd.conf; [ -z "$VCONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VCONF=/etc/vsftpd/vsftpd.conf
    if [ -n "$VCONF" ]; then
      set_kv_file "$VCONF" '^[[:space:]]*ftpd_banner[[:space:]]*=' 'ftpd_banner=Welcome' >/dev/null 2>&1
      systemctl restart vsftpd >/dev/null 2>&1 || true
      append_detail "vsftpd_banner: $(grep -E '^[[:space:]]*ftpd_banner[[:space:]]*=' "$VCONF" 2>/dev/null | tail -n 1)"
    fi
  fi

  if svc_active named && [ -f /etc/named.conf ]; then
    if ! grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/named.conf 2>/dev/null | grep -qE '^[[:space:]]*version[[:space:]]+"[^"]*";'; then
      sed -i -E '/^[[:space:]]*options[[:space:]]*\{/{n; s/^/    version "not currently available";\n/; }' /etc/named.conf 2>/dev/null || true
      systemctl restart named >/dev/null 2>&1 || true
    fi
    append_detail "bind_version_masking: $(grep -E '^[[:space:]]*version[[:space:]]+' /etc/named.conf 2>/dev/null | tail -n 1 | xargs)"
  fi

  # 최종 판정
  if [ "$IS_SUCCESS" -eq 1 ]; then
    REASON_LINE="서버 접속 배너 파일과 활성 서비스의 Banner 설정을 적용하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    REASON_LINE="설정 파일 수정 권한 문제나 서비스 재시작 실패 등의 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

# 결과 데이터 출력
[ -n "$ACTION_ERR_LOG" ] && append_detail "[Error_Log]\n$ACTION_ERR_LOG"
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n${DETAIL_CONTENT:-none}",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF