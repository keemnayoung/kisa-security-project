#!/bin/bash
# @Author: 한은결
# D-10: 원격에서 DB 서버로의 접속 제한
ID="D-10"
CATEGORY="접근 관리"
TITLE="원격에서 DB 서버로의 접속 제한"
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

# ✅ 자동 허용 로컬 host (자동 적용)
ALLOWED_LOCAL_HOSTS_CSV="${ALLOWED_LOCAL_HOSTS_CSV:-localhost,127.0.0.1,::1}"

# ✅ 자동 조치 대상(불필요 원격 host 계정은 삭제)
# - 기본값은 root 외에도 교육/테스트 환경에서 자주 쓰는 계정(guest/test)을 포함합니다.
# - 운영 환경에서 제외하려면 AUTO_LOCAL_USERS_CSV를 root 등으로 재지정하십시오.
AUTO_LOCAL_USERS_CSV="${AUTO_LOCAL_USERS_CSV:-root,guest,test}"

# ✅ 수동 허용 대상(원격 접속이 필요한 경우 관리자가 지정)
MANUAL_ALLOWED_REMOTE_HOSTS_CSV="${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:-}"
# ✅ 수동 점검 대상으로 남길 계정(기본: admin). 해당 계정의 원격 host는 자동 조치/즉시 실패 처리하지 않고 안내만 남김
MANUAL_REVIEW_USERS_CSV="${MANUAL_REVIEW_USERS_CSV:-admin}"

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

in_csv() {
  local needle="$1"
  local csv="$2"
  IFS=',' read -r -a arr <<< "$csv"
  for item in "${arr[@]}"; do
    [[ "$needle" == "$item" ]] && return 0
  done
  return 1
}

Q1="SELECT user,host,COALESCE(account_locked,'N') FROM mysql.user;"
Q2="SELECT user,host,'N' FROM mysql.user;"

ROWS="$(run_mysql "$Q1")"
RC=$?
if [[ $RC -ne 0 ]]; then
  ROWS="$(run_mysql "$Q2")"
  RC=$?
fi

if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 계정 조회 시간 초과"
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: 계정 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-10 조치를 수행할 수 없습니다."
else
  AUTO_DROP_TARGETS=""
  AUTO_DROP_COUNT=0
  MANUAL_REVIEW_REMAIN=""
  MANUAL_REVIEW_COUNT=0
  MANUAL_REMAIN=""
  MANUAL_COUNT=0

  # 1) 계정/host/잠금 여부 기반으로 분류
  while IFS=$'\t' read -r user host locked; do
    [[ -z "$host" ]] && continue
    [[ "$locked" == "Y" ]] && continue

    # 로컬 허용 host면 문제 없음
    if in_csv "$host" "$ALLOWED_LOCAL_HOSTS_CSV"; then
      continue
    fi

    # AUTO_LOCAL_USERS_CSV에 포함된 계정은 "원격 host는 불필요"로 간주 -> DROP 자동 조치
    if in_csv "$user" "$AUTO_LOCAL_USERS_CSV"; then
      row="${user}"$'\t'"${host}"
      if [[ -z "$AUTO_DROP_TARGETS" ]]; then
        AUTO_DROP_TARGETS="$row"
      else
        AUTO_DROP_TARGETS+=$'\n'"$row"
      fi
      AUTO_DROP_COUNT=$((AUTO_DROP_COUNT + 1))
    else
      # 관리자 수동 허용 host면 유지(예: 지정된 IP/호스트에서만 원격 접속 허용)
      if [[ -n "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV" ]] && in_csv "$host" "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV"; then
        continue
      fi

      # 수동 점검 대상 계정은 자동 조치/즉시 실패 처리하지 않고 안내만 남김(기본: admin)
      if in_csv "$user" "$MANUAL_REVIEW_USERS_CSV"; then
        row="${user}"$'\t'"${host}"
        if [[ -z "$MANUAL_REVIEW_REMAIN" ]]; then
          MANUAL_REVIEW_REMAIN="$row"
        else
          MANUAL_REVIEW_REMAIN+=$'\n'"$row"
        fi
        MANUAL_REVIEW_COUNT=$((MANUAL_REVIEW_COUNT + 1))
        continue
      fi

      # 그 외 계정은 수동 조치 대상으로 남김(FAIL 처리)
      row="${user}"$'\t'"${host}"
      if [[ -z "$MANUAL_REMAIN" ]]; then
        MANUAL_REMAIN="$row"
      else
        MANUAL_REMAIN+=$'\n'"$row"
      fi
      MANUAL_COUNT=$((MANUAL_COUNT + 1))
    fi
  done <<< "$ROWS"

  FAIL=0
  APPLIED=0

  # 2) 자동 조치: AUTO_LOCAL_USERS_CSV 계정의 원격 host 계정은 DROP
  if [[ $AUTO_DROP_COUNT -gt 0 ]]; then
    while IFS=$'\t' read -r user host; do
      [[ -z "$host" ]] && continue
      esc_user="$(sql_escape "$user")"
      esc_host="$(sql_escape "$host")"
      run_mysql "DROP USER IF EXISTS '${esc_user}'@'${esc_host}';" >/dev/null || FAIL=1
      APPLIED=$((APPLIED + 1))
    done <<< "$AUTO_DROP_TARGETS"

    run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1
  fi

  # 3) 재검증: 자동 대상(root 등) 원격 host가 남았는지 확인
  VERIFY_ROWS="$(run_mysql "$Q1")"
  RC2=$?
  if [[ $RC2 -ne 0 ]]; then
    VERIFY_ROWS="$(run_mysql "$Q2")"
    RC2=$?
  fi

  AUTO_REMAIN=0
  MANUAL_REVIEW_REMAIN_AFTER=0
  MANUAL_REMAIN_AFTER=0
  SAMPLE_AUTO="N/A"
  SAMPLE_MANUAL_REVIEW="N/A"
  SAMPLE_MANUAL="N/A"

  if [[ $RC2 -eq 0 ]]; then
    while IFS=$'\t' read -r user host locked; do
      [[ -z "$host" ]] && continue
      [[ "$locked" == "Y" ]] && continue
      in_csv "$host" "$ALLOWED_LOCAL_HOSTS_CSV" && continue

      if in_csv "$user" "$AUTO_LOCAL_USERS_CSV"; then
        AUTO_REMAIN=1
        [[ "$SAMPLE_AUTO" == "N/A" ]] && SAMPLE_AUTO="${user}@${host}"
      else
        # 관리자 수동 허용 host는 유지
        if [[ -n "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV" ]] && in_csv "$host" "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV"; then
          continue
        fi

        # 수동 점검 대상 계정은 안내만 남김
        if in_csv "$user" "$MANUAL_REVIEW_USERS_CSV"; then
          MANUAL_REVIEW_REMAIN_AFTER=1
          [[ "$SAMPLE_MANUAL_REVIEW" == "N/A" ]] && SAMPLE_MANUAL_REVIEW="${user}@${host}"
          continue
        fi

        MANUAL_REMAIN_AFTER=1
        [[ "$SAMPLE_MANUAL" == "N/A" ]] && SAMPLE_MANUAL="${user}@${host}"
      fi
    done <<< "$VERIFY_ROWS"
  else
    # 재검증 실패 시 안전하게 FAIL 처리
    AUTO_REMAIN=1
    MANUAL_REVIEW_REMAIN_AFTER=1
    MANUAL_REMAIN_AFTER=1
    SAMPLE_AUTO="재검증 조회 실패"
    SAMPLE_MANUAL_REVIEW="재검증 조회 실패"
    SAMPLE_MANUAL="재검증 조회 실패"
  fi

  # 4) 결과 정리
  if [[ $FAIL -eq 0 && $AUTO_REMAIN -eq 0 && $MANUAL_REMAIN_AFTER -eq 0 && $MANUAL_REVIEW_REMAIN_AFTER -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="AUTO_LOCAL_USERS_CSV 계정의 원격 host 계정 ${APPLIED}건을 삭제하여 로컬 접속으로 제한했고, 비인가 원격 접근 가능 계정이 미검출됨을 확인했습니다."
    EVIDENCE="D-10 조치 후 원격 접근 가능 계정 미검출"
  else
    # 자동 조치 대상이 남았으면 FAIL
    if [[ $AUTO_REMAIN -eq 1 || $FAIL -eq 1 ]]; then
      STATUS="FAIL"
      ACTION_RESULT="FAIL"
      ACTION_LOG="자동 조치 일부 실패: AUTO_LOCAL_USERS_CSV 계정의 원격 host 계정이 남아 있을 수 있습니다."
      EVIDENCE="자동 조치 후에도 원격 host 계정이 남아 있습니다. 예: ${SAMPLE_AUTO}"
    else
      # 자동 조치는 성공. 남아 있는 계정이 "수동 점검 대상"만이면 PASS(경고), 그 외는 FAIL
      if [[ $MANUAL_REMAIN_AFTER -eq 1 ]]; then
        STATUS="FAIL"
        ACTION_RESULT="MANUAL_REQUIRED"
        ACTION_LOG="AUTO_LOCAL_USERS_CSV 계정의 원격 host 계정은 정리했지만, 기타 계정의 원격 host는 수동 점검/허용 설정이 필요합니다."
        EVIDENCE="수동 점검 대상 원격 host 계정이 존재합니다. 예: ${SAMPLE_MANUAL}"
      else
        STATUS="PASS"
        ACTION_RESULT="SUCCESS_WITH_REVIEW"
        ACTION_LOG="AUTO_LOCAL_USERS_CSV 계정의 원격 host 계정 ${APPLIED}건을 삭제하여 로컬 접속으로 제한했습니다. 다만 수동 점검 대상 계정(MANUAL_REVIEW_USERS_CSV: ${MANUAL_REVIEW_USERS_CSV})의 원격 host 계정은 자동 조치하지 않았습니다."
        EVIDENCE="수동 점검 대상 원격 host 계정이 존재합니다. 예: ${SAMPLE_MANUAL_REVIEW}"
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
  "guide":"로컬 허용 호스트(localhost, 127.0.0.1, ::1)는 자동 기준으로 적용하며, AUTO_LOCAL_USERS_CSV(기본: root)에 포함된 계정의 로컬 외 host 계정은 불필요한 원격 접근 경로로 판단하여 자동 삭제합니다. 원격 접속이 꼭 필요하면 MANUAL_ALLOWED_REMOTE_HOSTS_CSV에 허용 IP/호스트를 지정한 뒤 해당 값으로만 계정('user'@'host')을 생성하세요",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
