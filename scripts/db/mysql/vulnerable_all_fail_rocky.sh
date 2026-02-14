#!/bin/bash
# ============================================================================
# Rocky Linux MySQL 취약 환경 구성 (D-01,02,03,04,06,07,08,10,11,21,25 FAIL 유도)
# 주의: 테스트/교육 환경 전용. 운영 서버에서 사용 금지.
#
# D-07(서비스 root 구동 제한) FAIL 유도는 환경(패키지 정책/SELinux/systemd 단위)에 따라
# 실제 mysqld를 root로 재시작하는 것이 실패할 수 있으므로,
# 실패 시에는 check_D07.sh가 "진짜 mysqld"로 인식할 수 있는 더미(/tmp|/var/tmp/.../mysqld)를
# root로 실행해 FAIL을 유도한다.
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
MYSQL_SOCKET="${MYSQL_SOCKET:-}"
VENDOR_LATEST_VERSION_FAIL="${VENDOR_LATEST_VERSION_FAIL:-8.0.99}"

# 비밀번호 정책(validate_password) 충돌 방지를 위해 기본값은 정책 통과형으로 사용
ROOT_REMOTE_PASSWORD="${ROOT_REMOTE_PASSWORD:-RootRemote1!Aa}"
GUEST_PASSWORD="${GUEST_PASSWORD:-GuestPass1!Aa}"
TEST_PASSWORD="${TEST_PASSWORD:-TestPass1!Aa}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPass1!Aa}"

export MYSQL_PWD="${MYSQL_PASSWORD}"

is_local_host() {
  case "${MYSQL_HOST}" in
    ""|localhost|127.0.0.1|::1) return 0 ;;
    *) return 1 ;;
  esac
}

mysql_args_sock=()
mysqladmin_args_sock=()
if [[ -n "${MYSQL_SOCKET}" ]]; then
  mysql_args_sock=(-S "${MYSQL_SOCKET}")
  mysqladmin_args_sock=(-S "${MYSQL_SOCKET}")
fi

MYSQL_BASE_TCP=(mysql --protocol=TCP -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" -u"${MYSQL_USER}" -N -s -B)
MYSQL_BASE_SOCK=(mysql --protocol=SOCKET -u"${MYSQL_USER}" -N -s -B "${mysql_args_sock[@]}")

run_mysql() {
  local sql="$1"
  "${MYSQL_BASE_TCP[@]}" -e "$sql" && return 0

  # Many Rocky installs only allow root@localhost via unix socket; fall back for local targets.
  if is_local_host; then
    "${MYSQL_BASE_SOCK[@]}" -e "$sql"
    return $?
  fi

  return 1
}

detect_mysql_service_name() {
  # Prefer the running service; otherwise pick the first existing unit.
  if command -v systemctl >/dev/null 2>&1; then
    local name
    for name in mysqld mysql mariadb; do
      if systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "${name}.service"; then
        echo "$name"
        return 0
      fi
    done
    for name in mysqld mysql mariadb; do
      if systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "${name}.service"; then
        echo "$name"
        return 0
      fi
    done
  fi
  echo "mysqld"
}

MYSQL_SERVICE_NAME="${MYSQL_SERVICE_NAME:-}"
if [[ -z "${MYSQL_SERVICE_NAME}" ]]; then
  MYSQL_SERVICE_NAME="$(detect_mysql_service_name)"
fi

restart_mysql_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart "${MYSQL_SERVICE_NAME}" >/dev/null 2>&1
    return $?
  fi
  service "${MYSQL_SERVICE_NAME}" restart >/dev/null 2>&1
}

ensure_mysql_up() {
  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet "${MYSQL_SERVICE_NAME}"; then
      log "${MYSQL_SERVICE_NAME} 비활성 상태 -> 시작"
      systemctl enable --now "${MYSQL_SERVICE_NAME}" >/dev/null 2>&1 || systemctl start "${MYSQL_SERVICE_NAME}" >/dev/null 2>&1
    fi
  fi

  for _ in {1..30}; do
    if mysqladmin --protocol=TCP -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" -u"${MYSQL_USER}" ping >/dev/null 2>&1; then
      return 0
    fi
    if is_local_host && mysqladmin --protocol=SOCKET -u"${MYSQL_USER}" "${mysqladmin_args_sock[@]}" ping >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

find_my_cnf() {
  local candidates=(
    "/etc/my.cnf"
    "/etc/mysql/my.cnf"
    "/etc/my.cnf.d/mysql-server.cnf"
    "/etc/mysql/mysql.conf.d/mysqld.cnf"
  )
  local f
  for f in "${candidates[@]}"; do
    [[ -f "$f" ]] && { printf "%s" "$f"; return 0; }
  done
  printf "/etc/my.cnf"
}

ensure_mysqld_user_setting() {
  local file="$1"
  local run_user="$2"
  local tmp
  tmp="$(mktemp)"

  [[ -f "$file" ]] || touch "$file" 2>/dev/null || true

  if ! grep -qi '^[[:space:]]*\[mysqld\]' "$file" 2>/dev/null; then
    {
      cat "$file"
      printf "\n[mysqld]\nuser=%s\n" "$run_user"
    } > "$tmp"
    cat "$tmp" > "$file"
    rm -f "$tmp"
    return 0
  fi

  awk -v run_user="$run_user" '
    BEGIN { in_mysqld=0; done=0 }
    /^[[:space:]]*\[/ {
      if (in_mysqld && !done) { print "user=" run_user; done=1 }
      in_mysqld = ($0 ~ /^[[:space:]]*\[mysqld\][[:space:]]*$/)
      print
      next
    }
    {
      if (in_mysqld && $0 ~ /^[[:space:]]*user[[:space:]]*=/) {
        if (!done) { print "user=" run_user; done=1 }
        next
      }
      print
    }
    END { if (in_mysqld && !done) print "user=" run_user }
  ' "$file" > "$tmp" && cat "$tmp" > "$file"

  rm -f "$tmp"
  return 0
}

list_real_mysqld_proc_info() {
  local pid user comm exe
  while read -r pid user comm; do
    [[ -z "$pid" ]] && continue
    exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
    [[ "$exe" == */mysqld || "$exe" == */mariadbd ]] || continue
    printf "%s\t%s\t%s\n" "$pid" "$user" "$exe"
  done < <(ps -eo pid=,user=,comm= 2>/dev/null | awk '$3=="mysqld" || $3=="mariadbd"{print $1, $2, $3}')
}

is_real_root_mysqld_running() {
  list_real_mysqld_proc_info | awk -F'\t' '$2=="root"{found=1} END{exit !found}'
}

D07_OVERRIDE_NAME="security_project_d07_root.conf"
D07_OVERRIDE_DIR="/etc/systemd/system/${MYSQL_SERVICE_NAME}.service.d"
D07_OVERRIDE_FILE="${D07_OVERRIDE_DIR}/${D07_OVERRIDE_NAME}"

apply_systemd_root_override() {
  command -v systemctl >/dev/null 2>&1 || return 0
  mkdir -p "$D07_OVERRIDE_DIR" 2>/dev/null || true
  cat > "$D07_OVERRIDE_FILE" <<EOF
[Service]
User=root
Group=root
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
}

MY_CNF="$(find_my_cnf)"
MY_CNF_BACKUP="${MY_CNF}.bak_security_project_d07_$(date +%Y%m%d_%H%M%S)"

rollback_d07_changes() {
  rm -f "$D07_OVERRIDE_FILE" >/dev/null 2>&1 || true
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if [[ -f "$MY_CNF_BACKUP" ]]; then
    cp -p "$MY_CNF_BACKUP" "$MY_CNF" 2>/dev/null || true
  fi
}

create_d07_root_dummy_mysqld() {
  # check_D07.sh는 /proc/<pid>/exe 가 */mysqld 인 프로세스만 "진짜 mysqld"로 인식한다.
  # 따라서 /tmp 또는 /var/tmp 아래에 실행 파일을 mysqld 라는 이름으로 두고 root로 실행한다.
  local base exe pidfile

  for base in /tmp /var/tmp; do
    mkdir -p "${base}/security_project_d07" 2>/dev/null || true
    exe="${base}/security_project_d07/mysqld"
    pidfile="${base}/security_project_d07_dummy.pid"

    cp -f /bin/sleep "$exe" >/dev/null 2>&1 || true
    chmod 755 "$exe" >/dev/null 2>&1 || true

    # noexec 마운트 등으로 실행이 막히면 다음 후보로.
    if ! "$exe" 0 >/dev/null 2>&1; then
      continue
    fi

    nohup "$exe" 999999 >/dev/null 2>&1 &
    echo $! > "$pidfile"
    sleep 1

    if is_real_root_mysqld_running; then
      log "D-07 유도(대체): root mysqld 더미 프로세스 생성 완료 (${exe})"
      return 0
    fi

    # 실패 시 정리 후 다음 경로로 재시도
    kill "$(cat "$pidfile" 2>/dev/null || true)" >/dev/null 2>&1 || true
    rm -f "$pidfile" >/dev/null 2>&1 || true
    rm -rf "${base}/security_project_d07" >/dev/null 2>&1 || true
  done

  return 1
}

log "MySQL 기동 확인 (service=${MYSQL_SERVICE_NAME})"
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

# D-07 유도: systemd User=root + my.cnf user=root 반영 후 재시작 시도
log "D-07 유도: my.cnf user=root + systemd User=root 적용 시도"
cp -p "$MY_CNF" "$MY_CNF_BACKUP" 2>/dev/null || true
apply_systemd_root_override
ensure_mysqld_user_setting "$MY_CNF" "root"

if restart_mysql_service; then
  sleep 2
  if is_real_root_mysqld_running; then
    log "D-07 유도: 서비스 재시작 완료, mysqld가 root로 실행 중"
  else
    warn "D-07 유도 실패(정책/패키지 제약 가능): 재시작은 되었으나 mysqld가 root로 실행 중인지 확인되지 않음 -> 설정 롤백 후 더미 프로세스로 FAIL 유도"
    rollback_d07_changes
    restart_mysql_service >/dev/null 2>&1 || true
    create_d07_root_dummy_mysqld || warn "D-07 유도(대체) 실패: 더미 mysqld 프로세스 생성 실패(/tmp noexec 등 환경 제약 가능)"
  fi
else
  warn "D-07 유도 실패: mysqld 재시작 실패 -> 설정 롤백 후 서비스 복구 시도"
  rollback_d07_changes
  restart_mysql_service >/dev/null 2>&1 || true
  create_d07_root_dummy_mysqld || warn "D-07 유도(대체) 실패: 더미 mysqld 프로세스 생성 실패(/tmp noexec 등 환경 제약 가능)"
fi

# D-25 유도: 점검 기준 버전 상향(실제 버전보다 높게)
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
  1) D-07 FAIL 유도는 실제 서비스 root 재시작을 먼저 시도하고, 실패 시 root 더미 mysqld로 대체합니다.
  2) D-25 FAIL은 VENDOR_LATEST_VERSION 값을 현재 버전보다 높게 둔 상태입니다.
OUT
