#!/bin/bash
# @Author: 한은결
# D-21: 인가되지 않은 GRANT OPTION 사용 제한
ID="D-21"
CATEGORY="옵션 관리"
TITLE="인가되지 않은 GRANT OPTION 사용 제한"
IMPORTANCE="중"

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
ALLOWED_USERS_CSV="${ALLOWED_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

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

# check_D21.sh와 동일한 기준(mysql.user.Grant_priv='Y')으로 대상 계정을 식별합니다.
QUERY="SELECT User,Host FROM mysql.user WHERE Grant_priv='Y';"
ROWS="$(run_mysql "$QUERY")"
RC=$?
if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 권한 조회 시간 초과"
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: 권한 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-21 조치를 수행할 수 없습니다."
else
  TARGETS=""
  COUNT=0
  while IFS=$'\t' read -r user host; do
    [[ -z "$host" ]] && continue
    in_csv "$user" "$ALLOWED_USERS_CSV" && continue

    row="${user}"$'\t'"${host}"
    if [[ -z "$TARGETS" ]]; then
      TARGETS="$row"
    else
      TARGETS+=$'\n'"$row"
    fi
    COUNT=$((COUNT + 1))
  done <<< "$ROWS"

  if [[ $COUNT -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="비인가 계정의 GRANT OPTION이 없어 추가 조치가 필요하지 않습니다."
    EVIDENCE="D-21 기준 추가 조치 불필요"
  else
    FAIL=0
    APPLIED=0

    # SHOW GRANTS 결과에서 WITH GRANT OPTION이 붙은 scope별로 GRANT OPTION만 회수합니다.
    # 예) GRANT PROCESS ON *.* TO ... WITH GRANT OPTION  -> REVOKE GRANT OPTION ON *.* FROM ...
    revoke_grant_option_scoped() {
      local user="$1"
      local host="$2"
      local esc_user esc_host grants line scope

      esc_user="$(sql_escape "$user")"
      esc_host="$(sql_escape "$host")"

      grants="$(run_mysql "SHOW GRANTS FOR '${esc_user}'@'${esc_host}';")"
      [[ -z "$grants" ]] && return 1

      while IFS=$'\n' read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" != *"WITH GRANT OPTION"* ]] && continue

        scope="$(printf "%s" "$line" | sed -E 's/.*[[:space:]]ON[[:space:]]+([^[:space:]]+)[[:space:]]+TO[[:space:]].*/\\1/')"
        [[ -z "$scope" || "$scope" == "$line" ]] && continue

        run_mysql "REVOKE GRANT OPTION ON ${scope} FROM '${esc_user}'@'${esc_host}';" >/dev/null || return 1
      done <<< "$grants"

      return 0
    }

    while IFS=$'\t' read -r user host; do
      [[ -z "$host" ]] && continue
      esc_user="$(sql_escape "$user")"
      esc_host="$(sql_escape "$host")"

      # 1) scope별 REVOKE 시도(가능한 경우)
      if ! revoke_grant_option_scoped "$user" "$host"; then
        # 2) 전역(*.*) REVOKE 시도(구버전/권한 구성에 따라 scope 파싱이 실패할 수 있음)
        run_mysql "REVOKE GRANT OPTION ON *.* FROM '${esc_user}'@'${esc_host}';" >/dev/null || true
      fi

      # 3) 여전히 Grant_priv가 남아있으면 최후 수단으로 mysql.user 플래그를 내립니다(교육/테스트 환경용)
      run_mysql "UPDATE mysql.user SET Grant_priv='N' WHERE User='${esc_user}' AND Host='${esc_host}';" >/dev/null || FAIL=1
      APPLIED=$((APPLIED + 1))
    done <<< "$TARGETS"

    run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1

    VERIFY_ROWS="$(run_mysql "$QUERY")"
    RCV=$?
    REMAIN=0
    SAMPLE="N/A"
    if [[ $RCV -eq 0 ]]; then
      while IFS=$'\t' read -r user host; do
        [[ -z "$host" ]] && continue
        in_csv "$user" "$ALLOWED_USERS_CSV" && continue
        REMAIN=1
        if [[ "$SAMPLE" == "N/A" ]]; then
          SAMPLE="${user}@${host}"
        fi
      done <<< "$VERIFY_ROWS"
    else
      REMAIN=1
      SAMPLE="재검증 조회 실패"
    fi

    if [[ $FAIL -eq 0 && $REMAIN -eq 0 ]]; then
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="비인가 계정 GRANT OPTION ${APPLIED}건을 회수했습니다."
      EVIDENCE="D-21 조치 후 비인가 GRANT OPTION 미검출"
    else
      ACTION_LOG="조치 일부 실패: 일부 계정의 GRANT OPTION이 남아 있을 수 있습니다."
      EVIDENCE="D-21 자동 조치를 완료하지 못했습니다. (예: ${SAMPLE})"
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
  "guide":"비인가 계정의 GRANT OPTION을 회수합니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
