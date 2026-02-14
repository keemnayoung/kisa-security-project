#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-04"
CATEGORY="계정 관리"
TITLE="관리자 권한 최소 부여"
IMPORTANCE="상"
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
# - root 외 전부 취약이 아니라, 기관 인가 관리자 목록을 예외 처리
# - 인가 사용자/계정은 환경변수로 확장 가능
ALLOWED_ADMIN_USERS_CSV="${ALLOWED_ADMIN_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_ADMIN_PRINCIPALS_CSV="${ALLOWED_ADMIN_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"

# 가이드의 SUPER 중심 예시 + MySQL 8 동적 관리자 권한(*_ADMIN)까지 점검
QUERY="
SELECT grantee,
       GROUP_CONCAT(DISTINCT privilege_type ORDER BY privilege_type SEPARATOR ',') AS privileges
FROM information_schema.user_privileges
WHERE privilege_type IN ('SUPER','SYSTEM_USER','CREATE USER','RELOAD','SHUTDOWN','PROCESS')
   OR privilege_type LIKE '%_ADMIN'
GROUP BY grantee;
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

extract_user() {
    echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"
}

extract_host() {
    echo "$1" | sed -E "s/^'[^']+'@'([^']+)'$/\1/"
}

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="관리자 권한 부여 상태 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 D-04 점검에 실패했습니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 관리자 권한 부여 상태를 확인할 수 없습니다."
else
    VIOLATION_COUNT=0
    SAMPLE="N/A"

    while IFS=$'\t' read -r grantee privs; do
        [[ -z "$grantee" ]] && continue

        user="$(extract_user "$grantee")"
        host="$(extract_host "$grantee")"
        principal="${user}@${host}"

        if in_csv "$user" "$ALLOWED_ADMIN_USERS_CSV"; then
            continue
        fi
        if in_csv "$principal" "$ALLOWED_ADMIN_PRINCIPALS_CSV"; then
            continue
        fi

        VIOLATION_COUNT=$((VIOLATION_COUNT + 1))
        if [[ "$SAMPLE" == "N/A" ]]; then
            SAMPLE="${principal} [${privs}]"
        fi
    done <<< "$RESULT"

    if [[ "$VIOLATION_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        EVIDENCE="관리자급 권한이 인가된 관리자 계정으로 제한되어 D-04 기준을 충족합니다."
    else
        STATUS="FAIL"
        EVIDENCE="인가되지 않은 계정에 관리자급 권한이 부여되어 있습니다. (${VIOLATION_COUNT}개, 예: ${SAMPLE})"
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
ACTION_IMPACT="이 조치를 적용하면 'test' 계정에서 SUPER 권한이 제거되지만, 일반적인 시스템 운영 및 기존 작업에는 영향이 없습니다. 다만, 해당 계정이 SUPER 권한을 필요로 하는 특정 관리 작업이나 글로벌 설정 변경을 수행하려고 할 경우에는 권한 부족으로 작업이 실패할 수 있으므로 주의가 필요합니다."

cat << EOF_JSON
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "SUPER/SYSTEM_USER/CREATE USER/RELOAD/SHUTDOWN/PROCESS 및 동적 관리자 권한(*_ADMIN)은 인가된 관리자 계정에만 부여하십시오. 불필요한 계정에는 REVOKE로 회수하고, 인가 목록(ALLOWED_ADMIN_USERS_CSV, ALLOWED_ADMIN_PRINCIPALS_CSV)을 기관 정책에 맞게 관리하십시오.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
