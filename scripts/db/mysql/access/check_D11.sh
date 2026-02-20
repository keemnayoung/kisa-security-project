#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
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
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="information_schema"

MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 시스템 스키마 권한(스키마/테이블/전역)을 조회하기 위한 SQL 쿼리 정의
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

# 쿼리 실행 결과 수집
LIST=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")

# 점검에서 제외할 관리자용 허용 계정 목록 설정
ALLOWED_USERS_CSV="${ALLOWED_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

# 특정 계정이 허용 목록에 포함되어 있는지 확인하는 함수
is_allowed_user() {
    local user="$1"
    IFS=',' read -r -a arr <<< "$ALLOWED_USERS_CSV"
    for u in "${arr[@]}"; do
        [[ "$user" == "$u" ]] && return 0
    done
    return 1
}

# GRANTEE 형태('user'@'host')에서 순수 사용자명만 추출하는 함수
extract_user_from_grantee() {
    echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"
}

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 발생할 수 있는 운영 위험성과 수동 조치 방법 정의
GUIDE_LINE="이 항목에 대해서 일반 사용자 계정의 권한을 자동 회수할 경우, 해당 계정을 사용하는 애플리케이션의 메타데이터 조회 기능이나 특정 관리 쿼리가 차단되어 서비스 오류가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 권한이 불필요한 일반 계정에 대해 REVOKE <권한명> ON <시스템DB>.* FROM '<계정명>'@'<호스트>' 명령을 사용하여 시스템 테이블 접근 권한을 회수하시기 바랍니다."

# 데이터베이스 접속 및 쿼리 실행 결과에 따른 분기점
if [[ "$LIST" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 접속 정보가 올바르지 않거나 권한이 부족하여 점검을 수행할 수 없습니다."
    DETAIL_CONTENT="connection_error(mysql_access=FAILED)"
else
    # 권한 데이터 분석 및 위반 사항 식별 분기점
    if [[ -z "$LIST" ]]; then
        STATUS="PASS"
        REASON_LINE="시스템 스키마 관련 권한이 일반 사용자에게 부여되어 있지 않아 이 항목에 대해 양호합니다."
        DETAIL_CONTENT="시스템 스키마(mysql, sys 등)에 대한 일반 사용자 권한 설정값이 존재하지 않습니다."
    else
        VIOLATION_COUNT=0
        VULN_SAMPLES=""
        CURRENT_SETTINGS=""

        # 수집된 권한 리스트를 순회하며 위반 계정 확인
        while IFS=$'\t' read -r grantee scope obj priv; do
            [[ -z "$grantee" ]] && continue
            
            user="$(extract_user_from_grantee "$grantee")"
            CURRENT_SETTINGS="${CURRENT_SETTINGS}${grantee} -> [${scope}] ${obj} (${priv})\n"

            if is_allowed_user "$user"; then
                continue
            fi

            VIOLATION_COUNT=$((VIOLATION_COUNT + 1))
            VULN_SAMPLES="${VULN_SAMPLES}${grantee}(${priv}), "
        done <<< "$LIST"

        # 최종 양호/취약 판정 및 사유
        if [[ "$VIOLATION_COUNT" -eq 0 ]]; then
            STATUS="PASS"
            REASON_LINE="시스템 스키마 권한이 허용된 관리 계정(${ALLOWED_USERS_CSV})으로만 제한되어 있어 이 항목에 대해 양호합니다."
        else
            STATUS="FAIL"
            CLEAN_SAMPLES=$(echo "$VULN_SAMPLES" | sed 's/, $//')
            REASON_LINE="${CLEAN_SAMPLES} 계정에 시스템 테이블 접근 권한이 부여되어 있어 이 항목에 대해 취약합니다."
        fi
        
        DETAIL_CONTENT="[현재 시스템 테이블 권한 설정 현황]\n${CURRENT_SETTINGS}"
    fi
fi

# 증적용 실행 명령어 정리
CHECK_COMMAND="mysql -e \"SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM information_schema.schema_privileges...\""

# raw_evidence 구성
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
cat << EOF_JSON
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF_JSON