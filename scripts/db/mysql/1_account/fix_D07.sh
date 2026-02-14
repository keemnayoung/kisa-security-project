#!/bin/bash
# @Author: 한은결
# D-07: root 권한으로 서비스 구동 제한
ID="D-07"
CATEGORY="계정 관리"
TITLE="root 권한으로 서비스 구동 제한"
IMPORTANCE="중"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_RUN_USER="${MYSQL_RUN_USER:-mysql}"
MY_CNF="${MY_CNF:-}"

# 취약 환경 구성 스크립트(vulnerable_all_fail_rocky.sh)가 D-07 FAIL 유도를 위해
# systemd override(User=root)를 만들 수 있으므로, 조치 시에는 해당 override를 제거한다.
D07_OVERRIDE_NAME="security_project_d07_root.conf"
D07_OVERRIDE_FILE_MYSQ="/etc/systemd/system/mysqld.service.d/${D07_OVERRIDE_NAME}"
D07_OVERRIDE_FILE_MYSQL="/etc/systemd/system/mysql.service.d/${D07_OVERRIDE_NAME}"

remove_d07_dummy_mysqld() {
  # vulnerable_all_fail_rocky.sh가 D-07 FAIL 유도를 위해 생성하는 더미 프로세스(/tmp|/var/tmp/.../mysqld)를 정리한다.
  # 실제 mysqld 바이너리는 보통 /usr/sbin/mysqld 등으로 실행되므로, 경로 기반으로만 제거한다.
  local pidfile pid exe

  for pidfile in /tmp/security_project_d07_dummy.pid /var/tmp/security_project_d07_dummy.pid; do
    if [[ -f "$pidfile" ]]; then
      pid="$(cat "$pidfile" 2>/dev/null || true)"
      if [[ -n "$pid" && -d "/proc/${pid}" ]]; then
        exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
        if [[ "$exe" == "/tmp/security_project_d07/mysqld" || "$exe" == "/var/tmp/security_project_d07/mysqld" ]]; then
          kill "$pid" >/dev/null 2>&1 || true
        fi
      fi
      rm -f "$pidfile" >/dev/null 2>&1 || true
    fi
  done

  # pidfile이 없거나 꼬였을 때를 대비해, root 소유 + dummy 경로로 실행 중인 mysqld만 추가로 제거
  while read -r pid user comm; do
    [[ -z "$pid" || "$user" != "root" || "$comm" != "mysqld" ]] && continue
    exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
    if [[ "$exe" == "/tmp/security_project_d07/mysqld" || "$exe" == "/var/tmp/security_project_d07/mysqld" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done < <(ps -eo pid=,user=,comm= 2>/dev/null | awk '$3=="mysqld"{print $1, $2, $3}')

  rm -rf /tmp/security_project_d07 /var/tmp/security_project_d07 >/dev/null 2>&1 || true
}

find_my_cnf() {
  if [[ -n "$MY_CNF" ]]; then
    printf "%s" "$MY_CNF"
    return
  fi

  local candidates=(
    "/etc/my.cnf"
    "/etc/mysql/my.cnf"
    "/etc/my.cnf.d/mysql-server.cnf"
    "/etc/mysql/mysql.conf.d/mysqld.cnf"
  )

  local f
  for f in "${candidates[@]}"; do
    if [[ -f "$f" ]]; then
      printf "%s" "$f"
      return
    fi
  done

  printf "/etc/my.cnf"
}

ensure_mysqld_user_setting() {
  local file="$1"
  local run_user="$2"
  local tmp
  tmp="$(mktemp)"

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
      if (in_mysqld && !done) {
        print "user=" run_user
        done=1
      }
      in_mysqld = ($0 ~ /^[[:space:]]*\[mysqld\][[:space:]]*$/)
      print
      next
    }
    {
      if (in_mysqld && $0 ~ /^[[:space:]]*user[[:space:]]*=/) {
        if (!done) {
          print "user=" run_user
          done=1
        }
        next
      }
      print
    }
    END {
      if (in_mysqld && !done) {
        print "user=" run_user
      }
    }
  ' "$file" > "$tmp" && cat "$tmp" > "$file"

  rm -f "$tmp"
  return 0
}

list_real_mysqld_users() {
  local pid user comm exe
  while read -r pid user comm; do
    [[ -z "$pid" ]] && continue
    exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
    [[ "$exe" == */mysqld || "$exe" == */mariadbd ]] || continue
    printf "%s\n" "$user"
  done < <(ps -eo pid=,user=,comm= 2>/dev/null | awk '$3=="mysqld" || $3=="mariadbd"{print $1, $2, $3}')
}

is_root_mysqld_running() {
  list_real_mysqld_users | grep -qx 'root'
}

any_mysqld_running() {
  list_real_mysqld_users | awk 'NR==1{found=1} END{exit !found}'
}

restart_mysql_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart mysqld >/dev/null 2>&1 || systemctl restart mysql >/dev/null 2>&1 || systemctl restart mariadb >/dev/null 2>&1
    return $?
  fi

  service mysqld restart >/dev/null 2>&1 || service mysql restart >/dev/null 2>&1 || service mariadb restart >/dev/null 2>&1
  return $?
}

remove_d07_systemd_override() {
  command -v systemctl >/dev/null 2>&1 || return 0

  if [[ -f "$D07_OVERRIDE_FILE_MYSQ" || -f "$D07_OVERRIDE_FILE_MYSQL" ]]; then
    rm -f "$D07_OVERRIDE_FILE_MYSQ" "$D07_OVERRIDE_FILE_MYSQL" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

if ! any_mysqld_running; then
  ACTION_LOG="조치 실패: mysqld 프로세스를 찾을 수 없어 구동 계정 조치를 수행할 수 없습니다."
  EVIDENCE="MySQL 서비스가 실행 중이 아니거나 프로세스 조회에 실패했습니다."
elif ! is_root_mysqld_running; then
  remove_d07_dummy_mysqld
  STATUS="PASS"
  ACTION_RESULT="NOT_REQUIRED"
  ACTION_LOG="MySQL 서비스가 이미 root가 아닌 계정으로 실행 중입니다."
  EVIDENCE="D-07 기준 추가 조치 불필요"
else
  CONF_FILE="$(find_my_cnf)"
  CONF_DIR="$(dirname "$CONF_FILE")"
  BACKUP="${CONF_FILE}.bak_$(date +%Y%m%d_%H%M%S)"

  mkdir -p "$CONF_DIR" 2>/dev/null || true
  [[ -f "$CONF_FILE" ]] || touch "$CONF_FILE"

  cp -p "$CONF_FILE" "$BACKUP" 2>/dev/null || true
  ensure_mysqld_user_setting "$CONF_FILE" "$MYSQL_RUN_USER"
  remove_d07_systemd_override
  remove_d07_dummy_mysqld

  if restart_mysql_service; then
    sleep 1
    if is_root_mysqld_running; then
      ACTION_LOG="조치 일부 실패: 설정은 변경했지만 mysqld가 여전히 root로 실행 중입니다."
      EVIDENCE="설정 파일(${CONF_FILE})에 user=${MYSQL_RUN_USER}를 반영했으나 런타임 반영이 확인되지 않았습니다."
    else
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="my.cnf의 [mysqld] user를 ${MYSQL_RUN_USER}로 설정하고 서비스를 재시작했습니다."
      EVIDENCE="D-07 조치 후 mysqld가 root가 아닌 계정으로 실행됩니다."
    fi
  else
    if [[ -f "$BACKUP" ]]; then
      cp -p "$BACKUP" "$CONF_FILE" 2>/dev/null || true
      remove_d07_systemd_override
      restart_mysql_service >/dev/null 2>&1 || true
    fi
    ACTION_LOG="조치 실패: MySQL 서비스 재시작에 실패하여 설정을 원복했습니다."
    EVIDENCE="설정 변경 후 서비스 재기동 실패"
  fi
fi

cat <<JSON
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide":"MySQL 서비스를 root가 아닌 전용 계정(mysql)으로 구동하도록 설정하였으며, 향후에도 root 권한으로 서비스가 실행되지 않도록 관리하시기 바랍니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
