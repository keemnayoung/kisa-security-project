#!/bin/bash
# @Author: 한은결
# D-06: DB 사용자 계정 개별 부여 운영
ID="D-06"
CATEGORY="계정 관리"
TITLE="DB 사용자 계정을 개별적으로 부여하여 사용"
IMPORTANCE="중"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_TIMEOUT=8
MYSQL_CMD="mysql --protocol=TCP -uroot -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
COMMON_USERS_CSV="${COMMON_USERS_CSV:-guest,test,demo,shared,common,public,user}"
EXEMPT_USERS_CSV="${EXEMPT_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
}

in_csv() {
  local needle="$1"
  local csv="$2"
  IFS=',' read -r -a arr <<< "$csv"
  for item in "${arr[@]}"; do
    [[ "$needle" == "$item" ]] && return 0
  done
  return 1
}

sql_escape() {
  local s="$1"
  s="${s//\'/\'\'}"
  printf "%s" "$s"
}

AGG_SQL="
SELECT user,
       SUM(CASE WHEN host NOT IN ('localhost','127.0.0.1','::1') THEN 1 ELSE 0 END) AS non_local_host_count,
       SUM(CASE WHEN host='%' THEN 1 ELSE 0 END) AS wildcard_count
FROM mysql.user
WHERE IFNULL(account_locked,'N') != 'Y'
GROUP BY user;
"

DETAIL_SQL1="SELECT user,host,COALESCE(account_locked,'N') FROM mysql.user;"
DETAIL_SQL2="SELECT user,host,'N' FROM mysql.user;"

AGG_ROWS="$(run_mysql "$AGG_SQL")"
RC1=$?
if [[ $RC1 -ne 0 ]]; then
  ACTION_LOG="조치 실패: 계정 집계 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-06 자동 조치를 수행할 수 없습니다."
else
  ANON_BAD=0
  declare -A BAD_COMMON
  declare -A BAD_SHARED

  while IFS=$'\t' read -r user non_local wildcard; do
    [[ -z "$user" && -z "$non_local" && -z "$wildcard" ]] && continue
    in_csv "$user" "$EXEMPT_USERS_CSV" && continue

    if [[ -z "$user" ]]; then
      ANON_BAD=1
    elif in_csv "$user" "$COMMON_USERS_CSV"; then
      BAD_COMMON["$user"]=1
    elif { [[ "$wildcard" -gt 0 ]] && [[ "$non_local" -gt 1 ]]; } || [[ "$non_local" -ge 3 ]]; then
      BAD_SHARED["$user"]=1
    fi
  done <<< "$AGG_ROWS"

  if [[ $ANON_BAD -eq 0 && ${#BAD_COMMON[@]} -eq 0 && ${#BAD_SHARED[@]} -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="공용/과다 공유 사용 징후 계정이 없어 추가 조치가 필요하지 않습니다."
    EVIDENCE="D-06 기준 추가 조치 불필요"
  else
    DETAIL_ROWS="$(run_mysql "$DETAIL_SQL1")"
    RC2=$?
    if [[ $RC2 -ne 0 ]]; then
      DETAIL_ROWS="$(run_mysql "$DETAIL_SQL2")"
      RC2=$?
    fi

    if [[ $RC2 -ne 0 ]]; then
      ACTION_LOG="조치 실패: 계정 상세 조회 실패"
      EVIDENCE="mysql.user 상세 조회에 실패하여 D-06 조치를 진행하지 못했습니다."
    else
      FAIL=0
      DROP_CNT=0
      LOCK_CNT=0

      while IFS=$'\t' read -r user host locked; do
        [[ -z "$host" ]] && continue
        in_csv "$user" "$EXEMPT_USERS_CSV" && continue

        esc_user="$(sql_escape "$user")"
        esc_host="$(sql_escape "$host")"

        if { [[ -z "$user" ]] && [[ $ANON_BAD -eq 1 ]]; } || [[ -n "${BAD_COMMON[$user]:-}" ]]; then
          run_mysql "DROP USER IF EXISTS '${esc_user}'@'${esc_host}';" >/dev/null || FAIL=1
          DROP_CNT=$((DROP_CNT + 1))
        elif [[ -n "${BAD_SHARED[$user]:-}" ]]; then
          case "$host" in
            localhost|127.0.0.1|::1) ;;
            *)
              run_mysql "ALTER USER '${esc_user}'@'${esc_host}' ACCOUNT LOCK;" >/dev/null || FAIL=1
              LOCK_CNT=$((LOCK_CNT + 1))
              ;;
          esac
        fi
      done <<< "$DETAIL_ROWS"

      run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1

      VERIFY_ROWS="$(run_mysql "$AGG_SQL")"
      RCV=$?
      REMAIN=0
      if [[ $RCV -eq 0 ]]; then
        while IFS=$'\t' read -r user non_local wildcard; do
          [[ -z "$user" && -z "$non_local" && -z "$wildcard" ]] && continue
          in_csv "$user" "$EXEMPT_USERS_CSV" && continue
          if [[ -z "$user" ]] || in_csv "$user" "$COMMON_USERS_CSV"; then
            REMAIN=1
            break
          elif { [[ "$wildcard" -gt 0 ]] && [[ "$non_local" -gt 1 ]]; } || [[ "$non_local" -ge 3 ]]; then
            REMAIN=1
            break
          fi
        done <<< "$VERIFY_ROWS"
      else
        REMAIN=1
      fi

      if [[ $FAIL -eq 0 && $REMAIN -eq 0 ]]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="공용 계정 ${DROP_CNT}건 삭제, 공유 의심 원격 계정 ${LOCK_CNT}건 잠금 조치를 완료했습니다."
        EVIDENCE="D-06 조치 후 공용/과다 공유 사용 징후가 확인되지 않습니다."
      else
        ACTION_LOG="조치 일부 실패: 공용 계정 또는 공유 사용 징후 계정이 일부 남아 있을 수 있습니다."
        EVIDENCE="D-06 자동 조치를 완료하지 못했습니다."
      fi
    fi
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
  "guide":"공용 계정 삭제/잠금 및 사용자별 계정 분리 운영",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
