#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-06"
CATEGORY="계정 관리"
TITLE="DB 사용자 계정을 개별적으로 부여하여 사용"
IMPORTANCE="중"
TARGET_FILE="mysql.user"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 오탐 완화:
# - 단순 host_count>1 만으로 취약 판정하지 않음
# - 명백한 공용 계정명, 과도한 다중 원격 호스트, 와일드카드+다중호스트 조합을 우선 탐지
COMMON_USERS_CSV="${COMMON_USERS_CSV:-guest,test,demo,shared,common,public,user}"
EXEMPT_USERS_CSV="${EXEMPT_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

QUERY="
SELECT user,
       SUM(CASE WHEN host NOT IN ('localhost','127.0.0.1','::1') THEN 1 ELSE 0 END) AS non_local_host_count,
       SUM(CASE WHEN host='%' THEN 1 ELSE 0 END) AS wildcard_count,
       GROUP_CONCAT(host ORDER BY host SEPARATOR ',') AS hosts
FROM mysql.user
WHERE IFNULL(account_locked,'N') != 'Y'
GROUP BY user;
"

in_csv() {
    local needle="$1"
    local csv="$2"
    IFS=',' read -r -a arr <<< "$csv"
    for item in "${arr[@]}"; do
        [[ "$needle" == "$item" ]] && return 0
    done
    return 1
}

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="DB 사용자 계정 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 D-06 점검에 실패했습니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 계정 개별 사용 여부를 확인할 수 없습니다."
else
    VULN_COUNT=0
    SAMPLE="N/A"
    REASON=""

    while IFS=$'\t' read -r user non_local wildcard hosts; do
        [[ -z "$user" ]] && continue

        if in_csv "$user" "$EXEMPT_USERS_CSV"; then
            continue
        fi

        flag="N"
        reason=""

        if in_csv "$user" "$COMMON_USERS_CSV"; then
            flag="Y"
            reason="공용/테스트 성격의 계정명"
        elif [[ "$wildcard" -gt 0 && "$non_local" -gt 1 ]]; then
            flag="Y"
            reason="와일드카드(host=%) + 다중 원격 호스트"
        elif [[ "$non_local" -ge 3 ]]; then
            flag="Y"
            reason="다수 원격 호스트에서 동일 계정 사용"
        fi

        if [[ "$flag" == "Y" ]]; then
            VULN_COUNT=$((VULN_COUNT + 1))
            if [[ "$SAMPLE" == "N/A" ]]; then
                SAMPLE="${user} (hosts=${hosts})"
                REASON="$reason"
            fi
        fi
    done <<< "$RESULT"

    if [[ "$VULN_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        EVIDENCE="공용 계정 사용 징후(명백한 공용 계정명/과도한 다중 원격 호스트)가 확인되지 않아 D-06 기준을 충족합니다."
    else
        STATUS="FAIL"
        EVIDENCE="공용 계정 사용 가능성이 높은 계정이 확인되었습니다. ${VULN_COUNT}개, 사유: ${REASON}, 예: ${SAMPLE}"
    fi
fi

# 파일 해시
if [ -f "$TARGET_FILE" ]; then
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    [[ -z "$FILE_HASH" ]] && FILE_HASH="HASH_ERROR"
else
    FILE_HASH="NOT_FOUND"
fi

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하면 공용 계정이 삭제되고, 사용자별·응용 프로그램별 계정으로 대체됩니다. 일반적인 시스템 운영에는 영향이 없으며, 각 계정에 적절한 권한이 부여되어 있어 정상적인 데이터베이스 접근과 작업 수행이 가능합니다. 다만, 모든 권한을 부여한 계정은 보안 위험이 증가할 수 있으므로 최소 권한 원칙을 준수하여 설정해야 합니다."

cat << EOF_JSON
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "공용/테스트 성격의 계정명(COMMON_USERS_CSV) 또는 다수의 원격 host에서 공유되는 계정은 삭제하거나 잠그십시오. 사용자별·응용프로그램별 계정으로 분리하고, 원격 접속은 필요한 host로만 제한하며 host='%' 사용을 최소화하십시오.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
