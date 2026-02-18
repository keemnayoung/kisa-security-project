#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: Codex
# @Last Updated: 2026-02-14
# ============================================================================
# [원복 스크립트 - Rocky Linux 9.7]
# @Check_ID : U-57
# @Description :
#   - setup_vulnerable_U57_rocky9.sh가 만든 백업 디렉터리를 받아 원복합니다.
#   - 테스트 VM 전용.
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

BACKUP_DIR="${1:-}"
if [ -z "$BACKUP_DIR" ]; then
  echo "사용법: $0 <BACKUP_DIR>"
  echo "예: sudo $0 /var/backups/kisa_u57_20260214_123456"
  exit 2
fi

if [ ! -d "$BACKUP_DIR" ]; then
  echo -e "${RED}[오류] 백업 디렉터리를 찾을 수 없습니다: $BACKUP_DIR${NC}"
  exit 2
fi

log() {
  echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
  echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

echo -e "${YELLOW}이 작업은 U-57 관련 설정 파일을 백업 상태로 원복합니다.${NC}"
read -r -p "계속하시겠습니까? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "취소되었습니다."
  exit 1
fi

log "원복 시작: $BACKUP_DIR"

# 백업 디렉터리 구조는 /var/backups/kisa_u57_xxx/etc/... 형태
if [ -d "${BACKUP_DIR}/etc" ]; then
  # /etc 아래만 복원
  cp -a "${BACKUP_DIR}/etc/." /etc/
  log "/etc 복원 완료"
else
  warn "백업에 etc 디렉터리가 없습니다. (복원할 파일이 없을 수 있습니다)"
fi

log "vsftpd/proftpd 재시작(설치되어 있으면)"
if systemctl list-unit-files 2>/dev/null | grep -q '^vsftpd\.service'; then
  systemctl restart vsftpd 2>/dev/null || warn "vsftpd 재시작 실패"
fi
if systemctl list-unit-files 2>/dev/null | grep -q '^proftpd\.service'; then
  systemctl restart proftpd 2>/dev/null || warn "proftpd 재시작 실패"
fi

log "완료"

