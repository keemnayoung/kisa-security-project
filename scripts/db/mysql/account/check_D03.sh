#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : 계정 관리
# @Platform    : MySQL
# @Severity    : 상
# @Title       : 비밀번호 사용 기간 및 복잡도 정책 설정
# @Description : 기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-03"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.system_variables"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

is_integer() { [[ "$1" =~ ^[0-9]+$ ]]; }

run_mysql_query() {
  local query="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
  else
    $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR"
  fi
}

# 비밀번호 정책 관련 시스템 변수 및 컴포넌트 설정 조회
QUERY="
SHOW VARIABLES
WHERE Variable_name IN (
  'default_password_lifetime',
  'validate_password.policy',
  'validate_password.length',
  'validate_password.mixed_case_count',
  'validate_password.number_count',
  'validate_password.special_char_count',
  'validate_password_policy',
  'validate_password_length',
  'validate_password_mixed_case_count',
  'validate_password_number_count',
  'validate_password_special_char_count'
);
"

RESULT="$(run_mysql_query "$QUERY")"

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE="비밀번호 정책을 일괄 변경할 경우 기존 계정의 접속 차단이나 서비스 애플리케이션의 인증 실패 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 validate_password 설정 및 default_password_lifetime 변수값을 기관 보안 정책(최소 8자 이상, 3종류 조합 등)에 맞게 수동으로 조치해 주시기 바랍니다."

# 접속 에러 및 결과 부재 시 예외 처리
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 계정 목록 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 점검을 완료하지 못했습니다."
  DETAIL_CONTENT="error=TIMEOUT"
elif [[ "$RESULT" == "ERROR" ]]; then
  STATUS="FAIL"
  REASON_LINE="데이터베이스 접속 권한 부족 또는 연결 실패로 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="error=CONNECT_FAILED"
else
  get_var() {
    local name="$1"
    echo "$RESULT" | awk -v k="$name" '$1==k{print $2; exit}'
  }

  # 버전별 변수명 차이를 고려한 데이터 추출
  LIFETIME="$(get_var "default_password_lifetime")"
  POLICY="$(get_var "validate_password.policy")"
  [[ -z "$POLICY" ]] && POLICY="$(get_var "validate_password_policy")"
  LENGTH="$(get_var "validate_password.length")"
  [[ -z "$LENGTH" ]] && LENGTH="$(get_var "validate_password_length")"
  MIXED="$(get_var "validate_password.mixed_case_count")"
  [[ -z "$MIXED" ]] && MIXED="$(get_var "validate_password_mixed_case_count")"
  NUMBER="$(get_var "validate_password.number_count")"
  [[ -z "$NUMBER" ]] && NUMBER="$(get_var "validate_password_number_count")"
  SPECIAL="$(get_var "validate_password.special_char_count")"
  [[ -z "$SPECIAL" ]] && SPECIAL="$(get_var "validate_password_special_char_count")"

  # 전체 설정 상태 기록
  DETAIL_CONTENT="default_password_lifetime=${LIFETIME:-N/A}\nvalidate_password.policy=${POLICY:-N/A}\nvalidate_password.length=${LENGTH:-N/A}\nvalidate_password.mixed_case_count=${MIXED:-N/A}\nvalidate_password.number_count=${NUMBER:-N/A}\nvalidate_password.special_char_count=${SPECIAL:-N/A}"

  # 위반 항목 추출 (취약한 부분의 값만 수집)
  FAIL_ITEMS=()
  if [[ -z "$LIFETIME" ]] || [[ "$LIFETIME" -eq 0 ]] || [[ "$LIFETIME" -gt 90 ]]; then
    FAIL_ITEMS+=("default_password_lifetime=${LIFETIME:-0}")
  fi
  if [[ -z "$POLICY" ]] || [[ "$(echo "$POLICY" | tr '[:lower:]' '[:upper:]')" == "LOW" ]]; then
    FAIL_ITEMS+=("validate_password.policy=${POLICY:-LOW}")
  fi
  if [[ -z "$LENGTH" ]] || [[ "$LENGTH" -lt 8 ]]; then
    FAIL_ITEMS+=("validate_password.length=${LENGTH:-0}")
  fi
  if [[ "$MIXED" -lt 1 ]] || [[ "$NUMBER" -lt 1 ]] || [[ "$SPECIAL" -lt 1 ]]; then
    FAIL_ITEMS+=("complexity_rules(mixed=$MIXED, num=$NUMBER, spec=$SPECIAL)")
  fi

  # 최종 점검 결과 및 사유 생성
  if [[ "${#FAIL_ITEMS[@]}" -eq 0 ]]; then
    STATUS="PASS"
    REASON_LINE="default_password_lifetime=${LIFETIME}, validate_password.policy=${POLICY}, length=${LENGTH}로 설정되어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    # 취약한 항목들만 쉼표로 연결하여 간략하게 표시
    REASON_STR=$(IFS=', '; echo "${FAIL_ITEMS[*]}")
    REASON_LINE="${REASON_STR}로 설정되어 이 항목에 대해 취약합니다."
  fi
fi

# raw_evidence 구성
CHECK_COMMAND="$MYSQL_CMD_BASE \"$QUERY\""
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF