#!/bin/bash
# ============================================================================
# Rocky Linux MySQL 취약 환경 구성 (D-01,02,03,04,06,07,08,10,11,21,25 FAIL 유도)
# 주의: 테스트/교육 환경 전용. 운영 서버에서 사용 금지.
# ============================================================================

set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "[ERROR] root 권한으로 실행하세요. (sudo)"
  exit 1
fi

log() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }

MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-qwer1234!AA}"
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
VENDOR_LATEST_VERSION_FAIL="${VENDOR_LATEST_VERSION_FAIL:-8.0.99}"

# 비밀번호 정책(validate_password) 충돌 방지를 위해 기본값은 정책 통과형으로 사용
ROOT_REMOTE_PASSWORD="${ROOT_REMOTE_PASSWORD:-RootRemote1!Aa}"
GUEST_PASSWORD="${GUEST_PASSWORD:-GuestPass1!Aa}"
TEST_PASSWORD="${TEST_PASSWORD:-TestPass1!Aa}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPass1!Aa}"

MYSQL_BASE=(mysql --protocol=TCP -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" -u"${MYSQL_USER}" -N -s -B)
export MYSQL_PWD="${MYSQL_PASSWORD}"

run_mysql() {
  local sql="$1"
  "${MYSQL_BASE[@]}" -e "$sql"
}

ensure_mysql_up() {
  if ! systemctl is-active --quiet mysqld; then
    log "mysqld 비활성 상태 -> 시작"
    systemctl enable --now mysqld
  fi

  for _ in {1..30}; do
    if mysqladmin --protocol=TCP -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" -u"${MYSQL_USER}" ping >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  return 1
}

log "MySQL 기동 확인"
if ! ensure_mysql_up; then
  echo "[ERROR] MySQL 접속 실패. 계정/비밀번호/서비스 상태를 확인하세요."
  exit 1
fi

log "기본 취약 DB/계정 생성"
run_mysql "CREATE DATABASE IF NOT EXISTS vuln_db;"

# D-01, D-10 유도: root 원격 계정 생성/활성
run_mysql "CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${ROOT_REMOTE_PASSWORD}';"
run_mysql "ALTER USER 'root'@'%' ACCOUNT UNLOCK;"

# D-02, D-06, D-08, D-10, D-11, D-21 유도용 계정
run_mysql "CREATE USER IF NOT EXISTS 'guest'@'%' IDENTIFIED BY '${GUEST_PASSWORD}';"
run_mysql "CREATE USER IF NOT EXISTS 'guest'@'10.0.0.%' IDENTIFIED BY '${GUEST_PASSWORD}';"
run_mysql "CREATE USER IF NOT EXISTS 'guest'@'192.168.0.%' IDENTIFIED BY '${GUEST_PASSWORD}';"
run_mysql "CREATE USER IF NOT EXISTS 'test'@'%' IDENTIFIED BY '${TEST_PASSWORD}';"
run_mysql "CREATE USER IF NOT EXISTS 'admin'@'%' IDENTIFIED BY '${ADMIN_PASSWORD}';"

# D-08 유도: SHA-256 미만 플러그인 계정
if run_mysql "ALTER USER 'test'@'%' IDENTIFIED WITH mysql_native_password BY '${TEST_PASSWORD}';" >/dev/null 2>&1; then
  log "D-08 유도: test@% -> mysql_native_password 적용"
else
  warn "mysql_native_password 적용 실패(환경 제약). D-08은 다른 계정 상태에 따라 FAIL 여부 확인 필요"
fi

# D-03 유도: 약한 정책/사용기간 미설정
run_mysql "SET GLOBAL default_password_lifetime=0;"
run_mysql "INSTALL COMPONENT 'file://component_validate_password';" >/dev/null 2>&1 || true
run_mysql "SET GLOBAL validate_password.policy='LOW';" >/dev/null 2>&1 || true
run_mysql "SET GLOBAL validate_password.length=4;" >/dev/null 2>&1 || true
run_mysql "SET GLOBAL validate_password.mixed_case_count=0;" >/dev/null 2>&1 || true
run_mysql "SET GLOBAL validate_password.number_count=0;" >/dev/null 2>&1 || true
run_mysql "SET GLOBAL validate_password.special_char_count=0;" >/dev/null 2>&1 || true

# D-04 유도: 비인가 계정에 관리자급 권한 부여(PROCESS)
run_mysql "GRANT PROCESS ON *.* TO 'guest'@'%';"

# D-11 유도: 일반 계정에 mysql 시스템 스키마 권한 부여
run_mysql "GRANT SELECT ON mysql.* TO 'guest'@'%';"

# D-21 유도: 일반 계정 GRANT OPTION 부여
run_mysql "GRANT SELECT ON vuln_db.* TO 'guest'@'%' WITH GRANT OPTION;"

# D-10 유도: 원격 계정 활성 유지
run_mysql "ALTER USER 'guest'@'%' ACCOUNT UNLOCK;"
run_mysql "ALTER USER 'test'@'%' ACCOUNT UNLOCK;"
run_mysql "ALTER USER 'admin'@'%' ACCOUNT UNLOCK;"

run_mysql "FLUSH PRIVILEGES;"

# D-07 유도: root 소유 'mysqld' 이름 더미 프로세스 생성
if pgrep -x mysqld -u root >/dev/null 2>&1; then
  log "이미 root 소유 mysqld 프로세스 존재"
else
  ln -sf /bin/sleep /tmp/mysqld
  nohup /tmp/mysqld 999999 >/tmp/root_mysqld_dummy.log 2>&1 &
  sleep 1
  if pgrep -x mysqld -u root >/dev/null 2>&1; then
    log "D-07 유도: root mysqld 더미 프로세스 생성 완료"
  else
    warn "root mysqld 더미 프로세스 생성 실패. D-07 FAIL 미유도 가능"
  fi
fi

# D-25 유도: 점검 기준 버전 상향(실제 버전보다 높게)
# run_audit/run_fix에서 MYSQL_ENV_FILE=/tmp/security_project_mysql_fix.env를 사용하므로 여기에 기록
cat > /tmp/security_project_mysql_fix.env <<ENVEOF
MYSQL_USER=${MYSQL_USER}
MYSQL_PASSWORD='${MYSQL_PASSWORD}'
VENDOR_LATEST_VERSION=${VENDOR_LATEST_VERSION_FAIL}
ENVEOF
chmod 600 /tmp/security_project_mysql_fix.env
log "D-25 유도용 /tmp/security_project_mysql_fix.env 생성 완료 (VENDOR_LATEST_VERSION=${VENDOR_LATEST_VERSION_FAIL})"

cat <<'OUT'

[DONE] 취약 환경 구성 완료
- 목표: D-01, D-02, D-03, D-04, D-06, D-07, D-08, D-10, D-11, D-21, D-25 FAIL 유도
- 참고:
  1) D-07 FAIL은 root 소유 더미 프로세스(/tmp/mysqld)에 의존
  2) D-25 FAIL은 VENDOR_LATEST_VERSION 값을 현재 버전보다 높게 둔 상태
  3) 메인 서버 playbook에서 env를 다시 덮어쓰면 D-25 결과가 달라질 수 있음
OUT
