#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-53
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 정보 노출 제한
# @Description : FTP 서비스 정보 노출 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-53"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="N/A"
ACTION_ERR_LOG=""
SAFE_BANNER="Welcome to FTP service"
SAFE_BANNER_FILE="/etc/vsftpd/banner.txt"

# 유틸리티 함수 정의
add_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
add_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE/N\/A/}${TARGET_FILE:+, }$1"; TARGET_FILE="${TARGET_FILE#, }"; }

backup_file(){
  local f="$1" b="${1}.bak_$(date +%Y%m%d_%H%M%S)"
  cp -a "$f" "$b" 2>/dev/null || return 1
  add_target "$b"
  return 0
}

restart_if_possible(){
  local svc="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${svc}\.service[[:space:]]" || return 0
  systemctl restart "${svc}.service" >/dev/null 2>&1 || return 1
  return 0
}

set_or_append_kv(){
  local f="$1" k="$2" v="$3"
  if grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -qE "^[[:space:]]*${k}[[:space:]]*="; then
    sed -i -E "s|^[[:space:]]*${k}[[:space:]]*=.*$|${k}=${v}|g" "$f" 2>/dev/null || return 1
  else
    echo "${k}=${v}" >> "$f" 2>/dev/null || return 1
  fi
  return 0
}

set_serverident_off(){
  local f="$1"
  if grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE '^[[:space:]]*ServerIdent([[:space:]]|$)'; then
    sed -i -E 's|^[[:space:]]*ServerIdent[[:space:]]+.*$|ServerIdent off|gI' "$f" 2>/dev/null || return 1
  else
    echo "ServerIdent off" >> "$f" 2>/dev/null || return 1
  fi
  return 0
}

# 권한 확인 및 조치 수행
if [ "$(id -u)" -ne 0 ]; then
  REASON_LINE="root 권한이 아니어서 FTP 서비스 정보 노출 제한 설정을 적용할 수 없어 조치를 중단합니다."
  add_err "(주의) root 권한이 아니면 설정 파일 수정 및 서비스 재시작이 실패할 수 있습니다."
else
  FAIL=0
  MOD=0

  # vsftpd 설정 조치
  if command -v vsftpd >/dev/null 2>&1; then
    VS_CONF=""
    [ -f /etc/vsftpd.conf ] && VS_CONF="/etc/vsftpd.conf"
    [ -z "$VS_CONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VS_CONF="/etc/vsftpd/vsftpd.conf"

    if [ -z "$VS_CONF" ]; then
      FAIL=1
      add_detail "vsftpd_conf: installed_but_conf_not_found"
    else
      add_target "$VS_CONF"
      backup_file "$VS_CONF" || { FAIL=1; add_err "vsftpd 설정 파일 백업 실패"; }
      mkdir -p "$(dirname "$SAFE_BANNER_FILE")" 2>/dev/null
      echo "$SAFE_BANNER" > "$SAFE_BANNER_FILE" 2>/dev/null || { FAIL=1; add_err "vsftpd 배너 파일 생성 실패"; }
      add_target "$SAFE_BANNER_FILE"
      set_or_append_kv "$VS_CONF" "banner_file" "$SAFE_BANNER_FILE" || FAIL=1
      set_or_append_kv "$VS_CONF" "ftpd_banner" "$SAFE_BANNER" || FAIL=1
      MOD=1
      restart_if_possible vsftpd || add_err "vsftpd 재시작 실패"
      
      # 조치 후 상태 수집
      bf_val=$(grep -v '^#' "$VS_CONF" 2>/dev/null | grep 'banner_file=' | cut -d= -f2)
      fb_val=$(grep -v '^#' "$VS_CONF" 2>/dev/null | grep 'ftpd_banner=' | cut -d= -f2)
      bt_val=$(head -n 1 "$SAFE_BANNER_FILE" 2>/dev/null)
      add_detail "vsftpd_banner_file: ${bf_val:-not_set}"
      add_detail "vsftpd_ftpd_banner: ${fb_val:-not_set}"
      add_detail "vsftpd_banner_content: ${bt_val:-empty}"
    fi
  else
    add_detail "vsftpd: not_installed"
  fi

  # proftpd 설정 조치
  if command -v proftpd >/dev/null 2>&1; then
    PF_CONF=""
    [ -f /etc/proftpd/proftpd.conf ] && PF_CONF="/etc/proftpd/proftpd.conf"
    [ -z "$PF_CONF" ] && [ -f /etc/proftpd.conf ] && PF_CONF="/etc/proftpd.conf"

    if [ -z "$PF_CONF" ]; then
      FAIL=1
      add_detail "proftpd_conf: installed_but_conf_not_found"
    else
      add_target "$PF_CONF"
      backup_file "$PF_CONF" || { FAIL=1; add_err "proftpd 설정 파일 백업 실패"; }
      set_serverident_off "$PF_CONF" || FAIL=1
      MOD=1
      restart_if_possible proftpd || add_err "proftpd 재시작 실패"

      # 조치 후 상태 수집
      si_val=$(grep -v '^#' "$PF_CONF" 2>/dev/null | grep -i 'ServerIdent' | awk '{$1=$1;print}')
      add_detail "proftpd_serverident: ${si_val:-not_set}"
    fi
  else
    add_detail "proftpd: not_installed"
  fi

  # 최종 판정
  if ! command -v vsftpd >/dev/null 2>&1 && ! command -v proftpd >/dev/null 2>&1; then
    IS_SUCCESS=1
    REASON_LINE="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 변경 없이도 조치가 완료되어 이 항목에 대해 양호합니다."
  elif [ "$FAIL" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="FTP 설정 파일의 배너 문구와 서버 식별 옵션을 제품 정보가 노출되지 않도록 설정하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="설정 파일의 배너 옵션 수정 시 발생하는 권한 오류 또는 파일 부재 등의 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

# 출력 데이터 구성
[ -n "$ACTION_ERR_LOG" ] && add_detail "[Error_Log]\n$ACTION_ERR_LOG"
CHECK_COMMAND='(vsftpd -v); (proftpd -v); grep -E "banner_file|ftpd_banner|ServerIdent" /etc/vsftpd.conf /etc/proftpd.conf'

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
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF