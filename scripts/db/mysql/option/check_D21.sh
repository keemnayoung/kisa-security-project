#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : 옵션 관리
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-21"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"
CHECK_COMMAND="information_schema.table_privileges/schema_privileges/user_privileges(is_grantable=YES or GRANT OPTION) 점검"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 인가 예외 목록 정의 (관리자 계정)
ALLOWED_GRANT_USERS_CSV="${ALLOWED_GRANT_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_GRANT_PRINCIPALS_CSV="${ALLOWED_GRANT_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"

# CSV 리스트 포함 여부 확인 함수
in_csv() {
    local needle="$1"
    local csv="$2"
    needle="$(printf "%s" "$needle" | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
    IFS=',' read -r -a arr <<< "$csv"
    for item in "${arr[@]}"; do
        item="$(printf "%s" "$item" | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
        [[ -n "$item" && "$needle" == "$item" ]] && return 0
    done
    return 1
}

# 계정 식별 정보를 추출하는 함수들
extract_user_from_grantee() { echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"; }
extract_host_from_grantee() { echo "$1" | sed -E "s/^'[^']+'@'([^']+)'$/\1/"; }

# 인가된 계정인지 여부를 판단하는 함수
is_allowed_grantee() {
    local grantee="$1"
    local user host principal
    user="$(extract_user_from_grantee "$grantee")"
    host="$(extract_host_from_grantee "$grantee")"
    principal="${user}@${host}"
    in_csv "$user" "$ALLOWED_GRANT_USERS_CSV" && return 0
    in_csv "$principal" "$ALLOWED_GRANT_PRINCIPALS_CSV" && return 0
    return 1
}

# MySQL 쿼리 실행 및 결과 반환 함수
run_mysql_query() {
    local query="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
    else
        $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR"
    fi
}

# 권한 위임(GRANT OPTION) 부여 현황 조회를 위한 쿼리문
Q_IS_TABLE="SELECT GRANTEE,'TABLE' AS SCOPE, CONCAT(TABLE_SCHEMA,'.',TABLE_NAME) AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.table_privileges WHERE IS_GRANTABLE='YES';"
Q_IS_SCHEMA="SELECT GRANTEE,'SCHEMA' AS SCOPE, TABLE_SCHEMA AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.schema_privileges WHERE IS_GRANTABLE='YES';"
Q_IS_GLOBAL="SELECT GRANTEE,'GLOBAL' AS SCOPE, '*.*' AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.user_privileges WHERE IS_GRANTABLE='YES' OR PRIVILEGE_TYPE='GRANT OPTION';"

R_TABLE="$(run_mysql_query "$Q_IS_TABLE")"
R_SCHEMA="$(run_mysql_query "$Q_IS_SCHEMA")"
R_GLOBAL="$(run_mysql_query "$Q_IS_GLOBAL")"

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 권한 체계 붕괴 및 관리 스크립트 장애 위험성 정의
GUIDE_LINE="이 항목에 대해서 GRANT OPTION 권한을 자동으로 회수할 경우, 해당 계정을 통해 하위 계정을 관리하거나 권한을 배분하는 자동화 스크립트 및 관리 도구가 즉시 차단되어 운영상 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 권한 위임이 불필요한 일반 계정에 대해 REVOKE GRANT OPTION ON *.* FROM '<계정명>'@'<호스트>' 명령을 수행하여 조치해 주시기 바랍니다."

# 점검 수행 가능 여부 및 예외 상황
if [[ "$R_TABLE" == "ERROR_TIMEOUT" || "$R_SCHEMA" == "ERROR_TIMEOUT" || "$R_GLOBAL" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 응답 지연으로 인해 권한 정보를 조회할 수 없어 점검을 완료하지 못했습니다."
    DETAIL_CONTENT="timeout_error(${MYSQL_TIMEOUT}s)"
elif [[ "$R_GLOBAL" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 접속 실패 또는 권한 부족으로 인해 점검을 수행할 수 없습니다."
    DETAIL_CONTENT="connection_error(mysql_access=FAILED)"
else
    VULN_COUNT=0
    VULN_LIST=""
    ALL_SETTINGS=""

    # 수집된 권한 행들을 분석하여 위반 사항 식별하는 로직
    analyze_rows() {
        local rows="$1"
        while IFS=$'\t' read -r grantee scope obj priv grantable; do
            [[ -z "$grantee" || -z "$priv" ]] && continue
            ALL_SETTINGS="${ALL_SETTINGS}${grantee} [${scope}:${obj}] (IS_GRANTABLE=${grantable})\n"
            if ! is_allowed_grantee "$grantee"; then
                VULN_COUNT=$((VULN_COUNT + 1))
                VULN_LIST="${VULN_LIST}${grantee}[${scope}:${obj}],"
            fi
        done <<< "$rows"
    }

    analyze_rows "$R_TABLE"
    analyze_rows "$R_SCHEMA"
    analyze_rows "$R_GLOBAL"

    # 점검 결과 및 상세 설정 현황 구성
    if [[ "$VULN_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        REASON_LINE="모든 계정의 IS_GRANTABLE 설정이 인가된 관리자 목록 내에서만 허용되어 있어 이 항목에 대해 양호합니다."
    else
        STATUS="FAIL"
        CLEAN_VULN=$(echo "$VULN_LIST" | sed 's/,$//')
        REASON_LINE="${CLEAN_VULN} 계정에 인가되지 않은 GRANT OPTION 권한이 부여되어 있어 이 항목에 대해 취약합니다."
    fi
    DETAIL_CONTENT="[현재 시스템 전체 GRANT OPTION 설정 현황]\n${ALL_SETTINGS}"
fi

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
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF