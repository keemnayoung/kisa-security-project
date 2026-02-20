#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-54
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 암호화되지 않는 FTP 서비스 비활성화
# @Description : 암호화되지 않은 FTP 서비스 비활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-54"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/{ftp,proftp,vsftp}, systemd:{vsftpd,proftpd,pure-ftpd}.service"
ACTION_ERR_LOG=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
add_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }

backup_if_file(){
  local f="$1"
  [ -f "$f" ] || return 0
  cp -a "$f" "${f}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || return 1
  return 0
}

# 권한 확인 및 조치 수행
if [ "$(id -u)" -ne 0 ]; then
  REASON_LINE="root 권한이 아니어서 암호화되지 않은 FTP 서비스 비활성화를 적용할 수 없어 조치를 중단합니다."
  add_err "(주의) root 권한이 아니면 설정 파일 수정 및 서비스 중지/비활성화가 실패할 수 있습니다."
else
  # 1) inetd 기반 설정 조치
  if [ -f /etc/inetd.conf ]; then
    if grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*ftp([[:space:]]|$)'; then
      backup_if_file /etc/inetd.conf || add_err "/etc/inetd.conf 백업 실패"
      sed -i 's/^[[:space:]]*ftp/# ftp/' /etc/inetd.conf 2>/dev/null || add_err "/etc/inetd.conf ftp 주석 처리 실패"
      if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -qi '^inetd\.service'; then
        systemctl restart inetd >/dev/null 2>&1 || add_err "inetd 재시작 실패"
      fi
    fi
  fi

  # 2) xinetd 기반 설정 조치
  if [ -d /etc/xinetd.d ]; then
    XCH=0
    for f in /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp; do
      [ -f "$f" ] || continue
      if grep -vi '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
        backup_if_file "$f" || add_err "$f 백업 실패"
        sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]\b/\1yes/' "$f" 2>/dev/null || add_err "$f disable=yes 변경 실패"
        XCH=1
      fi
    done
    if [ "$XCH" -eq 1 ] && command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -qi '^xinetd\.service'; then
      systemctl restart xinetd >/dev/null 2>&1 || add_err "xinetd 재시작 실패"
    fi
  fi

  # 3) systemd 기반 서비스 조치
  if command -v systemctl >/dev/null 2>&1; then
    for s in vsftpd proftpd pure-ftpd; do
      if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.service"; then
        systemctl stop "$s" >/dev/null 2>&1 || true
        systemctl disable "$s" >/dev/null 2>&1 || true
        systemctl mask "$s" >/dev/null 2>&1 || true
      fi
    done
  fi

  # 조치 후 최종 상태 데이터 수집 및 검증
  FTP_ACTIVE=0

  # inetd 상태 확인
  if [ -f /etc/inetd.conf ]; then
    inetd_val=$(grep -E "^[[:space:]]*#?ftp([[:space:]]|$)" /etc/inetd.conf | head -n 1 | awk '{$1=$1;print}')
    add_detail "inetd_status: ${inetd_val:-no_ftp_line}"
    grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*ftp([[:space:]]|$)' && FTP_ACTIVE=1
  else
    add_detail "inetd_status: file_not_found"
  fi

  # xinetd 상태 확인
  if [ -d /etc/xinetd.d ]; then
    xinetd_val=$(grep -riE "^[[:space:]]*disable" /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp 2>/dev/null | awk '{$1=$1;print}' | tr '\n' ' ')
    add_detail "xinetd_status: ${xinetd_val:-no_ftp_configs}"
    grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b' /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp 2>/dev/null && FTP_ACTIVE=1
  else
    add_detail "xinetd_status: dir_not_found"
  fi

  # systemd 상태 확인
  if command -v systemctl >/dev/null 2>&1; then
    for s in vsftpd proftpd pure-ftpd; do
      if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.service"; then
        ac=$(systemctl is-active "$s" 2>/dev/null)
        en=$(systemctl is-enabled "$s" 2>/dev/null)
        add_detail "systemd_status($s): active=$ac, enabled=$en"
        { [ "$ac" = "active" ] || [ "$en" = "enabled" ]; } && FTP_ACTIVE=1
      fi
    done
  fi

  # 최종 판정
  if [ "$FTP_ACTIVE" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="모든 FTP 서비스 경로(inetd/xinetd/systemd)에서 비활성화 및 마스킹 설정을 적용하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="설정 파일 수정 실패 또는 서비스 프로세스 종료 거부 등의 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

# 출력 데이터 구성
[ -n "$ACTION_ERR_LOG" ] && add_detail "[Error_Log]\n$ACTION_ERR_LOG"
CHECK_COMMAND="grep ftp /etc/inetd.conf; grep disable /etc/xinetd.d/ftp; systemctl is-active vsftpd"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n${DETAIL_CONTENT:-none}",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF