#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : 접근 관리
# @Platform    : MySQL
# @Severity    : 상
# @Title       : DBA 이외 사용자의 시스템 테이블 접근 제한
# @Description : mysql 등 시스템 스키마에 일반 사용자가 접근 불가하도록 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-11"
CATEGORY="접근 관리"
TITLE="DBA 이외 사용자의 시스템 테이블 접근 제한"
IMPORTANCE="상"
TARGET_FILE="information_schema"

STATUS="FAIL"
EVIDENCE="N/A"
ACTION_LOG="N/A"

TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 점검 전용 스크립트:
# D-11은 "일반 계정의 시스템 테이블 접근 가능 여부"를 확인해야 하므로
# check 단계에서는 권한 변경(REVOKE/GRANT)을 수행하지 않는다.
#
# 조회 범위
# 1) 시스템 스키마 대상 스키마/테이블 권한
# 2) 전역(*.*) 권한(USAGE 제외) - 전역 권한은 시스템 스키마 접근으로 이어질 수 있음
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

if [[ -n "$TIMEOUT_BIN" ]]; then
    LIST=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    LIST=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

# DBA/시스템 계정 예외 목록 (기관 정책에 따라 확장 가능)
ALLOWED_USERS_CSV="${ALLOWED_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

is_allowed_user() {
    local user="$1"
    IFS=',' read -r -a arr <<< "$ALLOWED_USERS_CSV"
    for u in "${arr[@]}"; do
        [[ "$user" == "$u" ]] && return 0
    done
    return 1
}

extract_user_from_grantee() {
    # 입력 예: 'appuser'@'10.0.0.%'
    # 출력 예: appuser
    echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"
}

if [[ "$LIST" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="시스템 테이블 접근 권한을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 점검을 수행하지 못했습니다."
    ACTION_LOG="DB 응답 지연으로 인해 D-11 점검을 완료하지 못했습니다."
elif [[ "$LIST" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 시스템 테이블 접근 권한 점검을 수행할 수 없습니다."
    ACTION_LOG="MySQL 접속 실패로 D-11 점검을 수행하지 못했습니다."
else
    if [[ -z "$LIST" ]]; then
        STATUS="PASS"
        EVIDENCE="시스템 테이블 관련 권한이 일반 사용자에게 부여되어 있지 않아 D-11 기준을 충족합니다."
        ACTION_LOG="점검 결과, 시스템 테이블 접근 권한은 허용 계정으로만 제한되어 있습니다."
    else
        VIOLATION_COUNT=0
        SAMPLE="N/A"

        while IFS=$'\t' read -r grantee scope obj priv; do
            [[ -z "$grantee" ]] && continue
            user="$(extract_user_from_grantee "$grantee")"
            if is_allowed_user "$user"; then
                continue
            fi

            VIOLATION_COUNT=$((VIOLATION_COUNT + 1))
            if [[ "$SAMPLE" == "N/A" ]]; then
                SAMPLE="${grantee} (${scope}:${obj}, ${priv})"
            fi
        done <<< "$LIST"

        if [[ "$VIOLATION_COUNT" -eq 0 ]]; then
            STATUS="PASS"
            EVIDENCE="시스템 테이블 관련 권한이 일반 사용자에게 부여되어 있지 않아 D-11 기준을 충족합니다."
            ACTION_LOG="점검 결과, 시스템 테이블 접근 권한은 허용 계정으로만 제한되어 있습니다."
        else
            STATUS="FAIL"
            EVIDENCE="DBA 외 계정에 시스템 테이블 접근 가능 권한이 확인되었습니다. (${VIOLATION_COUNT}건, 예: ${SAMPLE})"
            ACTION_LOG="D-11 점검 결과 취약: 일반 계정 권한 회수(REVOKE) 조치가 필요합니다."
        fi
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
ACTION_IMPACT="이 조치를 적용하면 일반 사용자 계정은 시스템 테이블에 접근할 수 없게 되지만, 지정된 데이터베이스 및 테이블에 대한 권한은 그대로 유지됩니다. 따라서 일반적인 시스템 운영 및 애플리케이션 동작에는 영향이 없으며, 권한 범위를 벗어난 작업 시에만 접근이 제한됩니다."

cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "시스템 스키마(mysql/performance_schema/sys/information_schema) 접근 권한은 허용 계정(ALLOWED_USERS_CSV)으로만 제한하십시오. 일반 계정에 부여된 전역/스키마/테이블 권한은 REVOKE로 회수하고, 업무 DB에 필요한 권한만 최소 범위로 부여하십시오.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
