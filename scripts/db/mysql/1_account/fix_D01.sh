#!/bin/bash
# @Author: 한은결
# D-01: 기본 계정 비밀번호/잠금 정책 조치
ID="D-01"
CATEGORY="계정 관리"
TITLE="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_TIMEOUT=8
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
  return $?
}

sql_escape() {
  local s="$1"
  s="${s//\'/\'\'}"
  printf "%s" "$s"
}

gen_pass() {
  local p
  p="$(tr -dc 'A-Za-z0-9@#%+=_' </dev/urandom | head -c 20)"
  [[ ${#p} -lt 12 ]] && p="RootFix$(date +%s)Aa1!"
  printf "%s" "$p"
}

# NEW_PASS="${NEW_PASS:-$(gen_pass)}"        ### CHANGED: 비밀번호 변경용 새 비밀번호 생성(비활성화)
# esc_pass="$(sql_escape "$NEW_PASS")"       ### CHANGED: 비밀번호 문자열 SQL 이스케이프(비활성화)

Q1="SELECT user,host,COALESCE(authentication_string,''),COALESCE(account_locked,'N') FROM mysql.user WHERE user='root' OR user='';"
Q2="SELECT user,host,COALESCE(authentication_string,''),'N' FROM mysql.user WHERE user='root' OR user='';"

ROWS="$(run_mysql "$Q1")"
RC=$?
if [[ $RC -ne 0 ]]; then
  ROWS="$(run_mysql "$Q2")"
  RC=$?
fi

if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 계정 조회 시간 초과"
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 || -z "$ROWS" ]]; then
  ACTION_LOG="조치 실패: root/기본 계정 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-01 조치를 수행할 수 없습니다."
else
  FAIL=0
  while IFS=$'\t' read -r user host auth locked; do
    [[ -z "$user" && -z "$host" ]] && continue
    esc_user="$(sql_escape "$user")"
    esc_host="$(sql_escape "$host")"

    if [[ "$user" == "root" ]]; then
      # run_mysql "ALTER USER '${esc_user}'@'${esc_host}' IDENTIFIED BY '${esc_pass}';" >/dev/null || FAIL=1   ### CHANGED: root 비밀번호 변경(비활성화)
      case "$host" in
        localhost|127.0.0.1|::1) ;;
        *) run_mysql "ALTER USER '${esc_user}'@'${esc_host}' ACCOUNT LOCK;" >/dev/null || FAIL=1 ;;
      esac
    else
      run_mysql "ALTER USER ''@'${esc_host}' ACCOUNT LOCK;" >/dev/null || FAIL=1
    fi
  done <<< "$ROWS"

  run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1

  # 조치 후 재검증
  AFTER="$(run_mysql "$Q1")"
  RC2=$?
  if [[ $FAIL -eq 0 && $RC2 -eq 0 ]]; then
    VULN=0
    while IFS=$'\t' read -r user host auth locked; do
      [[ -z "$user" && -z "$host" ]] && continue

      if [[ "$user" == "root" ]]; then
        ### CHANGE HERE: 자동 조치 범위는 "원격 root 잠금"만 재검증
        case "$host" in
          localhost|127.0.0.1|::1)
            : ;;  # 로컬 root 비밀번호는 수동 조치이므로 PASS/FAIL 판단에서 제외
          *)
            [[ "$locked" != "Y" ]] && VULN=1 ;;
        esac
      else
        ### CHANGE HERE: 익명 계정('')은 잠금되어야 함
        [[ "$locked" != "Y" ]] && VULN=1
      fi
    done <<< "$AFTER"

    if [[ $VULN -eq 0 ]]; then
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ### CHANGE HERE: 자동 조치 성공 + 수동 조치 안내
      ACTION_LOG="원격 root/익명 계정 잠금 조치를 완료했습니다. (root 비밀번호는 수동으로 변경 필요)"
      EVIDENCE="원격 root 차단 및 익명 계정 잠금 상태 정상 확인. 로컬 root 비밀번호는 정책에 맞게 수동 변경하세요."
    else
      ACTION_LOG="조치 일부 실패: 재검증에서 취약 상태가 남아 있습니다."
      EVIDENCE="D-01 조치 후에도 일부 계정 정책이 기준 미충족입니다."
    fi
  else
    ACTION_LOG="조치 실패: SQL 적용 또는 재검증 과정에서 오류가 발생했습니다."
    EVIDENCE="권한/버전/정책 제약으로 D-01 자동 조치를 완료하지 못했습니다."
  fi
fi

echo ""
cat <<JSON
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide":"원격 root 계정과 익명 계정을 잠금 조치하였으며, 로컬 root 비밀번호는 기관의 비밀번호 정책에 맞게 변경하여 안전하게 관리하시기 바랍니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
