#!/bin/bash
# @Author: 한은결
# D-03: 비밀번호 수명/복잡도 정책 적용
ID="D-03"
CATEGORY="계정 관리"
TITLE="비밀번호 사용 기간 및 복잡도 정책 설정"
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

POLICY="${POLICY:-MEDIUM}"
LENGTH="${LENGTH:-8}"
MIXED="${MIXED:-1}"
NUMBER="${NUMBER:-1}"
SPECIAL="${SPECIAL:-1}"
LIFETIME="${LIFETIME:-90}"
EXPIRE_INTERVAL="${EXPIRE_INTERVAL:-91}"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
  return $?
}

# [정책 적용용 SQL] (참고용: 실제 적용은 아래에서 개별 실행)
SETUP_SQL="
INSTALL COMPONENT 'file://component_validate_password';
SET GLOBAL validate_password.policy='${POLICY}';
SET GLOBAL validate_password.length=${LENGTH};
SET GLOBAL validate_password.mixed_case_count=${MIXED};
SET GLOBAL validate_password.number_count=${NUMBER};
SET GLOBAL validate_password.special_char_count=${SPECIAL};
SET GLOBAL default_password_lifetime=${LIFETIME};
"

# ============================================================================
# 1) 비밀번호 복잡도/수명 정책 적용 (자동 조치 핵심)
#    - validate_password: 복잡도 정책
#    - default_password_lifetime: 비밀번호 사용 기간(만료)
# ============================================================================
# INSTALL COMPONENT는 이미 설치된 경우 실패 가능 -> 실패해도 진행
run_mysql "INSTALL COMPONENT 'file://component_validate_password';" >/dev/null || true

# 복잡도 정책 적용
run_mysql "SET GLOBAL validate_password.policy='${POLICY}';" >/dev/null; RC1=$?
run_mysql "SET GLOBAL validate_password.length=${LENGTH};" >/dev/null; RC2=$?
run_mysql "SET GLOBAL validate_password.mixed_case_count=${MIXED};" >/dev/null; RC3=$?
run_mysql "SET GLOBAL validate_password.number_count=${NUMBER};" >/dev/null; RC4=$?
run_mysql "SET GLOBAL validate_password.special_char_count=${SPECIAL};" >/dev/null; RC5=$?

# 수명(만료) 정책 적용
run_mysql "SET GLOBAL default_password_lifetime=${LIFETIME};" >/dev/null; RC6=$?

if [[ $RC1 -ne 0 || $RC2 -ne 0 || $RC3 -ne 0 || $RC4 -ne 0 || $RC5 -ne 0 || $RC6 -ne 0 ]]; then
  ACTION_LOG="조치 실패: 정책 파라미터 적용 중 오류"
  EVIDENCE="validate_password 또는 default_password_lifetime 설정 적용 실패"
else
  # ==========================================================================
  # 2) (선택적) 사용자 계정 비밀번호 만료 주기 적용
  #    - 정책 강화 후 기존 비밀번호가 정책을 만족하지 않을 수 있음
  #    - 여기서는 각 계정에 만료 interval을 부여(실패해도 진행)
  # ==========================================================================
  USERS="$(run_mysql "SELECT user,host FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema','mysqlxsys','mariadb.sys');")"
  while IFS=$'\t' read -r user host; do
    [[ -z "$user" || -z "$host" ]] && continue
    run_mysql "ALTER USER '${user//\'/\'\'}'@'${host//\'/\'\'}' PASSWORD EXPIRE INTERVAL ${EXPIRE_INTERVAL} DAY;" >/dev/null || true
  done <<< "$USERS"

  # ==========================================================================
  # 3) 검증(재확인)
  # ==========================================================================
  VERIFY="$(run_mysql "SHOW VARIABLES WHERE Variable_name IN ('default_password_lifetime','validate_password.policy','validate_password.length','validate_password.mixed_case_count','validate_password.number_count','validate_password.special_char_count');")"
  RCV=$?
  if [[ $RCV -eq 0 && -n "$VERIFY" ]]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="비밀번호 복잡도/수명 정책을 적용했습니다. (정책을 만족하지 않는 기존 비밀번호는 변경하십시오.)"
    EVIDENCE="D-03 정책값 적용 완료. 사용자 계정은 강화된 정책에 맞게 비밀번호 변경 필요"
  else
    ACTION_LOG="조치 일부 실패: 설정 검증 조회 실패"
    EVIDENCE="정책 적용 후 검증 단계에서 오류"
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
  "guide":"validate_password 및 default_password_lifetime 정책을 적용하였습니다. 기존 계정의 비밀번호는 정책에 부합하도록 변경하시기 바랍니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
