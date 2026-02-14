#!/bin/bash
# @Author: 한은결
# D-11: 시스템 테이블 접근 제한
ID="D-11"
CATEGORY="접근 관리"
TITLE="DBA 이외 사용자의 시스템 테이블 접근 제한"
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

extract_user_from_grantee() {
  echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"
}

esc_ident() {
  local s="$1"
  s="${s//\`/\`\`}"
  printf "%s" "$s"
}

QUERY="
SELECT GRANTEE, 'SCHEMA' AS SCOPE, TABLE_SCHEMA AS OBJ, PRIVILEGE_TYPE
FROM information_schema.schema_privileges
WHERE TABLE_SCHEMA IN ('mysql','performance_schema','sys','information_schema')
UNION ALL
SELECT GRANTEE, 'TABLE' AS SCOPE, CONCAT(TABLE_SCHEMA,'.',TABLE_NAME) AS OBJ, PRIVILEGE_TYPE
FROM information_schema.table_privileges
WHERE TABLE_SCHEMA IN ('mysql','performance_schema','sys','information_schema')
UNION ALL
SELECT GRANTEE, 'GLOBAL' AS SCOPE, '*.*' AS OBJ, PRIVILEGE_TYPE
FROM information_schema.user_privileges
WHERE PRIVILEGE_TYPE <> 'USAGE';
"

ROWS="$(run_mysql "$QUERY")"
RC=$?
if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 권한 조회 시간 초과"
  EVIDENCE="권한 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: 권한 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-11 조치를 수행할 수 없습니다."
else
  TARGETS=""
  TARGET_COUNT=0

  while IFS=$'\t' read -r grantee scope obj priv; do
    [[ -z "$grantee" ]] && continue
    user="$(extract_user_from_grantee "$grantee")"
    in_csv "$user" "$ALLOWED_USERS_CSV" && continue

    row="${grantee}"$'\t'"${scope}"$'\t'"${obj}"$'\t'"${priv}"
    if [[ -z "$TARGETS" ]]; then
      TARGETS="$row"
    else
      TARGETS+=$'\n'"$row"
    fi
    TARGET_COUNT=$((TARGET_COUNT + 1))
  done <<< "$ROWS"

  if [[ $TARGET_COUNT -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="비인가 계정의 시스템 테이블 권한이 없어 추가 조치가 필요하지 않습니다."
    EVIDENCE="D-11 기준 추가 조치 불필요"
  else
    FAIL=0
    APPLIED=0

    while IFS=$'\t' read -r grantee scope obj priv; do
      [[ -z "$grantee" || -z "$scope" || -z "$priv" ]] && continue

      SQL=""
      case "$scope" in
        SCHEMA)
          db="$(esc_ident "$obj")"
          SQL="REVOKE ${priv} ON \`${db}\`.* FROM ${grantee};"
          ;;
        TABLE)
          db="${obj%%.*}"
          tb="${obj#*.}"
          db="$(esc_ident "$db")"
          tb="$(esc_ident "$tb")"
          SQL="REVOKE ${priv} ON \`${db}\`.\`${tb}\` FROM ${grantee};"
          ;;
        GLOBAL)
          SQL="REVOKE ${priv} ON *.* FROM ${grantee};"
          ;;
      esac

      if [[ -n "$SQL" ]]; then
        run_mysql "$SQL" >/dev/null || FAIL=1
        APPLIED=$((APPLIED + 1))
      fi
    done <<< "$TARGETS"

    run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1

    VERIFY_ROWS="$(run_mysql "$QUERY")"
    RCV=$?
    REMAIN=0
    SAMPLE="N/A"
    if [[ $RCV -eq 0 ]]; then
      while IFS=$'\t' read -r grantee scope obj priv; do
        [[ -z "$grantee" ]] && continue
        user="$(extract_user_from_grantee "$grantee")"
        in_csv "$user" "$ALLOWED_USERS_CSV" && continue
        REMAIN=1
        if [[ "$SAMPLE" == "N/A" ]]; then
          SAMPLE="${grantee}(${scope}:${obj},${priv})"
        fi
      done <<< "$VERIFY_ROWS"
    else
      REMAIN=1
      SAMPLE="재검증 조회 실패"
    fi

    if [[ $FAIL -eq 0 && $REMAIN -eq 0 ]]; then
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="비인가 계정의 시스템 테이블 관련 권한 ${APPLIED}건을 회수했습니다. 사용자 계정은 업무 DB에 필요한 권한만 수동으로 GRANT하여 운영하세요."
      EVIDENCE="D-11 조치 후 비인가 시스템 권한 미검출 (업무 DB 권한은 최소 범위로 수동 GRANT 필요)"
    else
      ACTION_LOG="조치 일부 실패: 일부 비인가 시스템 권한이 남아 있을 수 있습니다. 사용자 계정은 업무 DB에 필요한 권한만 수동으로 GRANT하여 운영하세요."
      EVIDENCE="D-11 자동 조치를 완료하지 못했습니다. (예: ${SAMPLE}) (업무 DB 권한은 최소 범위로 수동 GRANT 필요)"
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
  "guide":"일반 계정의 시스템 스키마(mysql/performance_schema/sys/information_schema) 접근 권한을 회수하고, 사용자 계정은 업무 DB에 필요한 권한만 수동으로 GRANT하여 최소 권한으로 운영하세요.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
