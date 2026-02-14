#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
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
CATEGORY="계정 관리"
TITLE="비밀번호 사용 기간 및 복잡도 정책 설정"
IMPORTANCE="상"
TARGET_FILE="mysql.system_variables"

# 기본 결과값: 점검 전 FAIL, 기준 충족 시 PASS로 전환
STATUS="FAIL"
EVIDENCE="N/A"

# 실행 안정성: DB 지연 시 무한 대기를 막기 위한 timeout/접속 옵션
TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 유효성 체크: 숫자 비교 전 정수값 여부 확인
is_integer() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

# 공통 실행 함수: timeout 적용 + 오류 토큰(ERROR/ERROR_TIMEOUT) 표준화
run_mysql_query() {
    local query="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
    else
        $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR"
    fi
}

# [가이드 10~12p 대응] 기간/복잡도 정책 변수 일괄 조회
QUERY="
SHOW VARIABLES
WHERE Variable_name IN (
  -- [가이드 12p] 비밀번호 사용 기간(LifeTime) 점검 변수
  'default_password_lifetime',
  -- [가이드 12p] 복잡도 정책 강도/길이/조합 규칙 점검 변수
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

# 정책 변수 조회 실행
RESULT="$(run_mysql_query "$QUERY")"

# 점검 불가 상황(시간초과/접속실패) 처리
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="비밀번호 정책 변수 조회가 ${MYSQL_TIMEOUT}초를 초과하여 D-03 진단에 실패했습니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-03(비밀번호 기간/복잡도) 점검을 수행할 수 없습니다."
else
    # 조회 결과에서 특정 변수값을 추출하는 헬퍼 함수
    get_var() {
        local name="$1"
        echo "$RESULT" | awk -v k="$name" '$1==k{print $2; exit}'
    }

    # 버전별 변수명 차이(점 표기/언더스코어 표기)를 흡수하여 최종 값 확정
    PASSWORD_LIFETIME="$(get_var "default_password_lifetime")"
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

    # 취약 사유 누적 배열: 하나라도 있으면 최종 FAIL
    REASONS=()

    # [가이드 10p, 12p] 기간 정책 적용 여부: default_password_lifetime > 0 이어야 함
    if ! is_integer "$PASSWORD_LIFETIME"; then
        REASONS+=("default_password_lifetime 값을 확인할 수 없음")
    elif [[ "$PASSWORD_LIFETIME" -le 0 ]]; then
        REASONS+=("default_password_lifetime=${PASSWORD_LIFETIME}(0 이하)")
    fi

    # [가이드 12p] 복잡도 정책 컴포넌트/정책 강도 확인(LOW는 미흡으로 판정)
    if [[ -z "$POLICY" ]]; then
        REASONS+=("validate_password 정책 변수 미확인(컴포넌트/플러그인 미적용 가능)")
    else
        POLICY_UPPER="$(echo "$POLICY" | tr '[:lower:]' '[:upper:]')"
        if [[ "$POLICY_UPPER" == "LOW" ]]; then
            REASONS+=("validate_password policy가 LOW")
        fi
    fi

    # [가이드 12p] 최소 길이 기준 확인(예시 기준 8자 이상)
    if ! is_integer "$LENGTH"; then
        REASONS+=("비밀번호 최소 길이(validate_password length) 값을 확인할 수 없음")
    elif [[ "$LENGTH" -lt 8 ]]; then
        REASONS+=("비밀번호 최소 길이=${LENGTH}(8 미만)")
    fi

    # [가이드 12p] 대소문자/숫자/특수문자 최소 포함 개수 확인(각 1 이상)
    for rule in "대소문자:$MIXED" "숫자:$NUMBER" "특수문자:$SPECIAL"; do
        label="${rule%%:*}"
        value="${rule#*:}"
        if ! is_integer "$value"; then
            REASONS+=("${label} 조합 최소 개수 값을 확인할 수 없음")
            continue
        fi
        if [[ "$value" -lt 1 ]]; then
            REASONS+=("${label} 조합 최소 개수=${value}(1 미만)")
        fi
    done

    # 누적 사유 기반 최종 판정
    if [[ "${#REASONS[@]}" -eq 0 ]]; then
        STATUS="PASS"
        EVIDENCE="D-03 양호: 비밀번호 사용 기간(default_password_lifetime=${PASSWORD_LIFETIME}) 및 복잡도 정책(policy=${POLICY}, length=${LENGTH}, mixed=${MIXED}, number=${NUMBER}, special=${SPECIAL})이 적용되어 있습니다."
    else
        STATUS="FAIL"
        EVIDENCE="D-03 취약: ${REASONS[*]}"
    fi
fi

# 시스템 변수 점검 항목이므로 파일 해시는 N/A 처리
FILE_HASH="N/A(VARIABLE_CHECK)"

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하면 MySQL의 비밀번호 복잡도 정책이 강화되어 이후 생성되거나 변경되는 계정의 비밀번호가 정책에 맞게 설정되어야 합니다. 기존 계정의 비밀번호에는 즉각적인 영향이 없으나, 정책에 맞지 않는 비밀번호로 변경 시에는 거부되므로 비밀번호 변경 작업 시 주의가 필요합니다. 일반적인 시스템 운영에는 직접적인 영향이 없습니다."

# 표준 JSON 결과 출력 (수집 파이프라인 연계 포맷)
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide":"1) 복잡도 정책 컴포넌트를 설치하십시오.'file://component_validate_password'; 복잡도 정책을 MEDIUM 이상으로 설정하고(길이>=8, 대소문자/숫자/특수문자>=1) 값을 지정하십시오; 비밀번호 사용 기간을 1 이상으로 설정하십시오(예: 90일);",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
