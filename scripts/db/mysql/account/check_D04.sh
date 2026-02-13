#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.2 (scan_history DB 연동)
# @Author: 한은결
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : 계정 관리 (MySQL)
# @Platform    : MySQL 8.0.x
# @IMPORTANCE  : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여
# @Description : 관리자급 권한(SUPER/SYSTEM_USER/CREATE USER 등 및 *_ADMIN) 부여 계정이 인가 목록으로 제한되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="D-04"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"
CHECK_COMMAND="mysql -N -s -B -e \"SELECT grantee, GROUP_CONCAT(DISTINCT privilege_type ORDER BY privilege_type SEPARATOR ',') AS privileges FROM information_schema.user_privileges WHERE privilege_type IN ('SUPER','SYSTEM_USER','CREATE USER','RELOAD','SHUTDOWN','PROCESS') OR privilege_type LIKE '%_ADMIN' GROUP BY grantee;\""

REASON_LINE=""
DETAIL_CONTENT=""

TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

ALLOWED_ADMIN_USERS_CSV="${ALLOWED_ADMIN_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_ADMIN_PRINCIPALS_CSV="${ALLOWED_ADMIN_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"

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

# MySQL 조회 실행 (조건문)
if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

# 결과에 따른 PASS/FAIL 결정
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL에서 관리자 권한 부여 상태 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 점검이 정상 수행되지 않았으므로 취약합니다. 접속 상태 및 권한을 확인한 뒤 재점검해야 합니다."
    DETAIL_CONTENT="query_timeout=${MYSQL_TIMEOUT}s"
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속 실패 또는 권한 부족으로 관리자 권한 부여 상태를 확인할 수 없어 보안 정책 적용 여부를 판단할 수 없으므로 취약합니다. 접속 계정/권한 및 네트워크 접근을 점검해야 합니다."
    DETAIL_CONTENT="mysql_connect_or_privilege_error"
else
    VIOLATION_COUNT=0
    VIOLATIONS=""
    SAMPLE="N/A"

    # 조회 결과를 순회하며 위반 계정 수집(반복문)
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
        VIOLATIONS+="${principal} privileges=${privs}"$'\n'

        if [[ "$SAMPLE" == "N/A" ]]; then
            SAMPLE="${principal} privileges=${privs}"
        fi
    done <<< "$RESULT"

    if [[ "$VIOLATION_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        REASON_LINE="MySQL에서 관리자급 권한이 인가된 관리자 계정으로만 제한되어 있어 불필요한 관리자 권한 오남용 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="allowed_admins_only"
    else
        STATUS="FAIL"
        REASON_LINE="MySQL에서 인가되지 않은 계정에 관리자급 권한이 부여되어 권한 오남용 및 계정 탈취 시 전체 DB 통제 위험이 있으므로 취약합니다. 인가되지 않은 계정의 SUPER/SYSTEM_USER 및 *_ADMIN 권한을 회수하고 인가 목록으로 관리해야 합니다."
        DETAIL_CONTENT="violation_count=$VIOLATION_COUNT"$'\n'"sample=$SAMPLE"$'\n'"violations:"$'\n'"$(printf "%s" "$VIOLATIONS" | sed 's/[[:space:]]*$//')"
    fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
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