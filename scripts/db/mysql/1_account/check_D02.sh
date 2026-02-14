#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : 계정 관리
# @Platform    : MySQL
# @Severity    : 상
# @Title       : 데이터베이스의 불필요 계정 제거 또는 잠금 설정
# @Description : DB 운용에 사용하지 않는 불필요 계정 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-02"
CATEGORY="계정 관리"
TITLE="불필요한 계정 제거 또는 잠금 설정"
IMPORTANCE="상"
TARGET_FILE="mysql.user(table)"

# 기본 결과값: 점검 전 FAIL, 양호 조건 충족 시 PASS로 변경
STATUS="FAIL"
EVIDENCE="N/A"

# 실행 안정성: DB 응답 지연 시 무한 대기를 막기 위한 timeout/접속 옵션
TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 점검 제외 대상: DB 엔진 내부 계정(시스템 계정)
SYSTEM_USERS_CSV="'root','mysql.sys','mysql.session','mysql.infoschema','mysqlxsys','mariadb.sys'"

# 오탐 최소화 정책:
# - 기본 모드: 명백한 불필요 계정(데모/테스트/익명)만 취약 판정
# - 기관 계정 기준이 제공된 경우(AUTHORIZED_USERS_CSV): 허용 목록 외 계정도 취약 판정
AUTHORIZED_USERS_CSV="${AUTHORIZED_USERS_CSV:-}"
DEMO_USERS_CSV="${DEMO_USERS_CSV:-scott,pm,adams,clark,test,guest,demo,sample}"

# 계정 잠금 여부 포함 조회
QUERY_PRIMARY="
SELECT user, host, IFNULL(account_locked,'N') AS account_locked
FROM mysql.user
WHERE user NOT IN (${SYSTEM_USERS_CSV});
"

# 구버전 호환: account_locked 미지원 환경에서는 시스템 외 계정 존재 여부로 판정
QUERY_FALLBACK="
SELECT user, host, 'N' AS account_locked
FROM mysql.user
WHERE user NOT IN (${SYSTEM_USERS_CSV});
"

# 공통 실행 함수: timeout 적용 + 오류 토큰(ERROR/ERROR_TIMEOUT) 표준화
run_mysql_query() {
    local query="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
    else
        $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR"
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

# 1차 조회 실패 시 2차(구버전 호환) 조회로 재시도
RESULT="$(run_mysql_query "$QUERY_PRIMARY")"
QUERY_MODE="PRIMARY"
if [[ "$RESULT" == "ERROR" ]]; then
    RESULT="$(run_mysql_query "$QUERY_FALLBACK")"
    QUERY_MODE="FALLBACK"
fi

# 점검 불가 상황(시간초과/접속실패) 처리
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 계정 목록을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 지연 또는 접속 설정을 확인해야 합니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속에 실패하여 계정 잠금 상태를 확인할 수 없습니다. 진단 계정 권한 또는 접속 정보를 점검해야 합니다."
else
    VULN_COUNT=0
    SAMPLE="N/A"
    REASON=""

    while IFS=$'\t' read -r user host locked; do
        [[ -z "$user" && -z "$host" ]] && continue
        [[ "$locked" == "Y" ]] && continue

        # 익명 계정은 대표적인 불필요 계정
        if [[ -z "$user" ]]; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="anonymous@${host}"
            [[ -z "$REASON" ]] && REASON="익명 계정 잠금/삭제 미적용"
            continue
        fi

        # 데모/테스트 계정명은 불필요 계정으로 간주
        if in_csv "$user" "$DEMO_USERS_CSV"; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="${user}@${host}"
            [[ -z "$REASON" ]] && REASON="데모/테스트 계정(${user}) 활성 상태"
            continue
        fi

        # 기관 승인 계정 목록이 주어진 경우: 목록 외 계정은 취약
        if [[ -n "$AUTHORIZED_USERS_CSV" ]] && ! in_csv "$user" "$AUTHORIZED_USERS_CSV"; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="${user}@${host}"
            [[ -z "$REASON" ]] && REASON="기관 허용 목록 외 계정 활성 상태"
            continue
        fi
    done <<< "$RESULT"

    if [[ "$VULN_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        if [[ -n "$AUTHORIZED_USERS_CSV" ]]; then
            EVIDENCE="D-02 양호: 허용 계정 목록 기준으로 불필요 계정이 확인되지 않았습니다."
        elif [[ "$QUERY_MODE" == "FALLBACK" ]]; then
            EVIDENCE="D-02 양호(구버전 호환 점검): 명백한 불필요 계정(익명/데모/테스트) 활성 상태가 확인되지 않았습니다."
        else
            EVIDENCE="D-02 양호: 명백한 불필요 계정(익명/데모/테스트) 활성 상태가 확인되지 않았습니다."
        fi
    else
        STATUS="FAIL"
        EVIDENCE="D-02 취약: 불필요 계정으로 판단되는 활성 계정이 확인되었습니다. (${VULN_COUNT}개, 사유: ${REASON}, 예: ${SAMPLE})"
    fi
fi

# 시스템 테이블 점검이므로 파일 해시는 N/A 처리
FILE_HASH="N/A(TABLE_CHECK)"

IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="이 조치를 적용하면 불필요한 계정이 삭제되어 해당 계정으로의 접속 및 관련 권한이 모두 사라집니다. 삭제된 계정을 사용하던 자동화 작업, 테스트 스크립트, 애플리케이션 연결 등에서 접속 실패가 발생할 수 있으므로, 사전에 영향 범위를 확인하고 필요한 대체 계정이나 권한을 준비한 후 적용해야 합니다."

# 표준 JSON 결과 출력 (수집 파이프라인 연계 포맷)
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "계정 목록을 점검하여 익명 계정 및 데모/테스트 계정(${DEMO_USERS_CSV})은 삭제하거나 잠그십시오. 기관 허용 계정 목록을 운영하는 경우 AUTHORIZED_USERS_CSV 기준으로 목록 외 계정을 정리하십시오.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
