#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: Codex
# @Last Updated: 2026-02-14
# ============================================================================
# [취약 환경 설정 스크립트 - Rocky Linux 9.7]
# @Check_ID : U-57
# @Category : 서비스 관리
# @Title : Ftpusers 파일 설정 (root FTP 차단 미설정 유도)
# @Description :
#   - 테스트 VM 전용. 운영 환경 절대 실행 금지.
#   - U-57 점검(check) 스크립트가 FAIL 되도록 vsftpd 설정/차단목록에서 root를 제거합니다.
#   - 원복은 restore_U57_rocky9.sh를 사용하세요(이 스크립트가 백업을 생성합니다).
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo -e "${RED}[오류] root 권한으로 실행해야 합니다.${NC}"
  exit 1
fi

echo -e "${RED}======================================================================${NC}"
echo -e "${RED}  경고: 이 스크립트는 시스템을 의도적으로 취약하게 설정합니다.${NC}"
echo -e "${RED}  Rocky Linux 9.7 테스트 VM/컨테이너에서만 실행하세요.${NC}"
echo -e "${RED}======================================================================${NC}"
echo ""
read -r -p "계속하시겠습니까? (yes/no): " CONFIRM
if [ "${CONFIRM}" != "yes" ]; then
  echo "취소되었습니다."
  exit 1
fi

ts="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/var/backups/kisa_u57_${ts}"
LOG_FILE="/var/log/kisa_u57_vuln_${ts}.log"
mkdir -p "$BACKUP_DIR"
touch "$LOG_FILE"

log() {
  echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
  echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

backup_file() {
  local f="$1"
  if [ -f "$f" ]; then
    mkdir -p "${BACKUP_DIR}$(dirname "$f")"
    cp -a "$f" "${BACKUP_DIR}${f}"
    log "백업: $f -> ${BACKUP_DIR}${f}"
  fi
}

set_kv() {
  # set_kv <file> <key> <value>
  local file="$1"
  local key="$2"
  local val="$3"
  [ -f "$file" ] || touch "$file"
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key}=${val}|g" "$file"
  else
    echo "${key}=${val}" >>"$file"
  fi
}

remove_root_line() {
  local f="$1"
  [ -f "$f" ] || return 0
  # 주석/공백 상관없이 root 단독 라인 제거
  sed -i -E '/^[[:space:]]*#?[[:space:]]*root[[:space:]]*$/d' "$f"
}

log "U-57 취약 환경 설정 시작"
log "백업 디렉터리: $BACKUP_DIR"
log "로그 파일: $LOG_FILE"

log "vsftpd 설치/활성화(없으면 설치)"
dnf -y install vsftpd >>"$LOG_FILE" 2>&1 || warn "dnf install vsftpd 실패(계속 진행)"

VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
if [ ! -f "$VSFTPD_CONF" ]; then
  VSFTPD_CONF="/etc/vsftpd.conf"
fi
backup_file "$VSFTPD_CONF"

log "vsftpd 설정: userlist_enable=NO 로 ftpusers 경로를 사용하도록 설정"
[ -f "$VSFTPD_CONF" ] || touch "$VSFTPD_CONF"
set_kv "$VSFTPD_CONF" "userlist_enable" "NO"

log "U-57 취약화: 차단 목록(ftpusers/user_list 등)에서 root 제거"
for f in \
  /etc/ftpusers \
  /etc/ftpd/ftpusers \
  /etc/vsftpd.ftpusers \
  /etc/vsftpd/ftpusers \
  /etc/vsftpd.user_list \
  /etc/vsftpd/user_list
do
  backup_file "$f"
  [ -f "$f" ] || continue
  remove_root_line "$f"
done

# 파일이 없으면 생성해 두되 root는 넣지 않음 (취약 상태 유지)
mkdir -p /etc/vsftpd
touch /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list

log "vsftpd 재시작"
systemctl enable --now vsftpd >>"$LOG_FILE" 2>&1 || warn "systemctl enable --now vsftpd 실패"
systemctl restart vsftpd >>"$LOG_FILE" 2>&1 || warn "systemctl restart vsftpd 실패"

cat >"${BACKUP_DIR}/README.txt" <<EOF
This backup was created by: scripts/unix/3_service/setup_vulnerable_U57_rocky9.sh
Date: $(date '+%Y-%m-%d %H:%M:%S')

Restore:
  sudo scripts/unix/3_service/restore_U57_rocky9.sh "${BACKUP_DIR}"
EOF

log "완료: U-57 FAIL 유도용 취약환경을 구성했습니다."
log "원복: sudo scripts/unix/3_service/restore_U57_rocky9.sh \"${BACKUP_DIR}\""

