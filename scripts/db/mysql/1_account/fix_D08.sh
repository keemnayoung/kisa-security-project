#!/bin/bash
# @Author: 한은결
# D-08: 안전한 암호화 알고리즘 사용
ID="D-08"
CATEGORY="계정 관리"
TITLE="안전한 암호화 알고리즘 사용"
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
# caching_sha2_password 계정 전환 시 사용할 임시 비밀번호
ROTATE_PASSWORD="${ROTATE_PASSWORD:-ChangeMe#2026!Aa}"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
}

sql_escape() {
  local s="$1"
  s="${s//\'/\'\'}"
  printf "%s" "$s"
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

CHECK_SQL="
SELECT user,host,plugin
FROM mysql.user
;
"

ROWS="$(run_mysql "$CHECK_SQL")"
RC=$?

if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 계정 조회 시간 초과"
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: 계정 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-08 조치를 수행할 수 없습니다."
else
  WEAK_ROWS=""
  WEAK_COUNT=0

  # 1️⃣ 취약 플러그인 계정 탐지
  while IFS=$'\t' read -r user host plugin; do
    [[ -z "$host" ]] && continue

    if [[ "$plugin" != "caching_sha2_password" ]]; then
      row="${user}"$'\t'"${host}"$'\t'"${plugin}"
      if [[ -z "$WEAK_ROWS" ]]; then
        WEAK_ROWS="$row"
      else
        WEAK_ROWS+=$'\n'"$row"
      fi
      WEAK_COUNT=$((WEAK_COUNT + 1))
    fi
  done <<< "$ROWS"

  # 2️⃣ 이미 모두 안전한 경우
  if [[ $WEAK_COUNT -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="모든 계정이 SHA-256 기반(caching_sha2_password) 인증을 사용 중입니다."
    EVIDENCE="D-08 기준 추가 조치 불필요"
  else
    # 3️⃣ 자동 조치: 모든 취약 계정 대상
    UPDATED_COUNT=0
    DELETED_ANON=0
    FAILED_COUNT=0
    FAIL_SAMPLE="N/A"
    esc_new_pw="$(sql_escape "$ROTATE_PASSWORD")"

    while IFS=$'\t' read -r user host plugin; do
      [[ -z "$host" ]] && continue
      esc_user="$(sql_escape "$user")"
      esc_host="$(sql_escape "$host")"

      if [[ -z "$user" ]]; then
        run_mysql "DROP USER IF EXISTS ''@'${esc_host}';" >/dev/null
        if [[ $? -eq 0 ]]; then
          DELETED_ANON=$((DELETED_ANON + 1))
        else
          FAILED_COUNT=$((FAILED_COUNT + 1))
          [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="''@${host}"
        fi
      else
        run_mysql "ALTER USER '${esc_user}'@'${esc_host}' IDENTIFIED WITH caching_sha2_password BY '${esc_new_pw}';" >/dev/null
        if [[ $? -eq 0 ]]; then
          UPDATED_COUNT=$((UPDATED_COUNT + 1))
          if [[ "$user" == "$MYSQL_USER" ]]; then
            MYSQL_PASSWORD="$ROTATE_PASSWORD"
            export MYSQL_PWD="$MYSQL_PASSWORD"
          fi
        else
          FAILED_COUNT=$((FAILED_COUNT + 1))
          [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="${user}@${host}(${plugin})"
        fi
      fi
    done <<< "$WEAK_ROWS"

    run_mysql "FLUSH PRIVILEGES;" >/dev/null || true

    # 4️⃣ 재검증
    VERIFY_ROWS="$(run_mysql "$CHECK_SQL")"
    RCV=$?

    REMAIN_COUNT=0
    SAMPLE_REMAIN=""

    if [[ $RCV -eq 0 ]]; then
      while IFS=$'\t' read -r user host plugin; do
        [[ -z "$host" ]] && continue

        if [[ "$plugin" != "caching_sha2_password" ]]; then
          REMAIN_COUNT=$((REMAIN_COUNT + 1))
          [[ -z "$SAMPLE_REMAIN" ]] && SAMPLE_REMAIN="${user}@${host}(${plugin})"
        fi
      done <<< "$VERIFY_ROWS"
    else
      REMAIN_COUNT=$WEAK_COUNT
      SAMPLE_REMAIN="$FAIL_SAMPLE"
    fi

    # 5️⃣ 수동 조치 안내
    MANUAL_GUIDE="취약 계정의 인증 플러그인을 SHA-256 기반(caching_sha2_password)으로 수동 전환하십시오. 예) ALTER USER '계정'@'호스트' IDENTIFIED WITH caching_sha2_password BY '새로운비밀번호';"

    if [[ $REMAIN_COUNT -eq 0 ]]; then
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="취약 계정 중 일반 계정 ${UPDATED_COUNT}건을 caching_sha2_password로 전환하고, 익명 계정 ${DELETED_ANON}건을 삭제했습니다."
      EVIDENCE="D-08 조치 후 비-caching_sha2_password 계정이 확인되지 않습니다."
    else
      STATUS="FAIL"
      ACTION_RESULT="MANUAL_REQUIRED"
      ACTION_LOG="취약 계정 자동 조치를 수행했으나 일부 계정은 전환/삭제에 실패했습니다. (성공: 전환 ${UPDATED_COUNT}건, 익명 삭제 ${DELETED_ANON}건, 실패 ${FAILED_COUNT}건)"
      EVIDENCE="취약 인증 플러그인 계정 ${REMAIN_COUNT}건이 확인됩니다. (예: ${SAMPLE_REMAIN}) ${MANUAL_GUIDE}"
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
  "guide":"취약 계정의 인증 플러그인을 caching_sha2_password로 수동 전환하고, 비밀번호는 기관 정책에 맞게 재설정하시기 바랍니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
