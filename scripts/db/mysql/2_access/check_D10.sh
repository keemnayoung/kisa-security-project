#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-12
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : 접근 관리
# @Platform    : MySQL
# @Importance  : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : 지정된 IP/호스트에서만 DB 접근 허용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-10"
CATEGORY="접근 관리"
TITLE="원격에서 DB 서버로의 접속 제한"
IMPORTANCE="상"
TARGET_FILE="mysql.user.host"

STATUS="FAIL"
EVIDENCE="N/A"

MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"

# 기본 허용 호스트(로컬). 필요 시 ALLOWED_HOSTS_CSV로 추가 가능
ALLOWED_HOSTS_CSV="${ALLOWED_HOSTS_CSV:-localhost,127.0.0.1,::1}"

run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
    else
        $MYSQL_CMD "$sql" 2>/dev/null
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

#  자동 조치용(로컬로 강제 제한할 계정)
# - 원격 허용을 없애고 로컬로만 제한할 대상 계정 목록
# - 예: "root,admin,app"
AUTO_LOCAL_USERS_CSV="${AUTO_LOCAL_USERS_CSV:-root}"

#  수동 조치용(원격 허용이 필요한 경우 관리자가 지정)
# - 예: "10.0.0.10,10.0.0.11,db-client.example.com"
MANUAL_ALLOWED_REMOTE_HOSTS_CSV="${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:-}"
# 수동 점검 대상으로 남길 계정(기본: admin). 해당 계정의 원격 host는 즉시 취약으로 보지 않고 안내만 남김
MANUAL_REVIEW_USERS_CSV="${MANUAL_REVIEW_USERS_CSV:-admin}"

Q1="SELECT user,host,COALESCE(account_locked,'N') FROM mysql.user;"
Q2="SELECT user,host,'N' FROM mysql.user;"

ROWS="$(run_mysql "$Q1")"
RC=$?
if [[ $RC -ne 0 ]]; then
    ROWS="$(run_mysql "$Q2")"
    RC=$?
fi

if [[ $RC -eq 124 ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 계정 host 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과했습니다."
elif [[ $RC -ne 0 || -z "$ROWS" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-10 점검을 수행할 수 없습니다."
else
    VULN_COUNT=0
    SAMPLE="N/A"
    MANUAL_REVIEW_COUNT=0
    MANUAL_SAMPLE="N/A"
    AUTO_FIXED=0
    AUTO_FAIL=0

    while IFS=$'\t' read -r user host locked; do
        [[ -z "$host" ]] && continue

        # 잠금 계정은 실제 원격 접근이 불가능하므로 제외
        if [[ "$locked" == "Y" ]]; then
            continue
        fi

        #  1) 자동 조치: AUTO_LOCAL_USERS_CSV 대상 계정의 원격 호스트는 제거하고 로컬만 유지
        # - 예: root@'%' 또는 root@'10.0.0.10' 등은 삭제하고,
        #       root@'localhost', '127.0.0.1', '::1'만 유지
        if in_csv "$user" "$AUTO_LOCAL_USERS_CSV"; then
            if ! in_csv "$host" "$ALLOWED_HOSTS_CSV"; then
                # 원격 host 계정 삭제
                esc_user="${user//\'/\'\'}"
                esc_host="${host//\'/\'\'}"
                run_mysql "DROP USER IF EXISTS '${esc_user}'@'${esc_host}';" >/dev/null
                if [[ $? -eq 0 ]]; then
                    AUTO_FIXED=$((AUTO_FIXED + 1))
                    continue
                else
                    AUTO_FAIL=$((AUTO_FAIL + 1))
                    # 삭제 실패해도 취약 판정으로 카운트
                fi
            else
                continue
            fi
        fi

        # 2) 기본 허용 목록(로컬) 또는 관리자가 수동으로 허용한 원격 호스트면 통과
        if in_csv "$host" "$ALLOWED_HOSTS_CSV"; then
            continue
        fi
        if [[ -n "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV" ]] && in_csv "$host" "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV"; then
            continue
        fi

        # 3) 수동 점검 계정(예: admin)은 즉시 취약 처리하지 않고 안내 대상으로만 남김
        if in_csv "$user" "$MANUAL_REVIEW_USERS_CSV"; then
            MANUAL_REVIEW_COUNT=$((MANUAL_REVIEW_COUNT + 1))
            if [[ "$MANUAL_SAMPLE" == "N/A" ]]; then
                MANUAL_SAMPLE="${user}@${host}"
            fi
            continue
        fi

        # ❗ 그 외는 취약
        VULN_COUNT=$((VULN_COUNT + 1))
        if [[ "$SAMPLE" == "N/A" ]]; then
            SAMPLE="${user}@${host}"
        fi
    done <<< "$ROWS"

    if [[ $VULN_COUNT -eq 0 ]]; then
        STATUS="PASS"
        if [[ $MANUAL_REVIEW_COUNT -gt 0 ]]; then
            EVIDENCE="원격 host 계정 중 수동 점검 대상 계정이 존재하나(MANUAL_REVIEW_USERS_CSV: ${MANUAL_REVIEW_USERS_CSV}), 즉시 취약으로 분류하지 않았습니다. (예: ${MANUAL_SAMPLE}) (자동 조치: 원격 계정 ${AUTO_FIXED}건 삭제)"
        else
            EVIDENCE="모든 활성 계정이 허용 호스트(${ALLOWED_HOSTS_CSV}${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:+,${MANUAL_ALLOWED_REMOTE_HOSTS_CSV}})로 제한되어 D-10 기준을 충족합니다. (자동 조치: 원격 계정 ${AUTO_FIXED}건 삭제)"
        fi
    else
        STATUS="FAIL"
        EVIDENCE="허용되지 않은 원격 접근 가능 계정이 확인되었습니다. (${VULN_COUNT}건, 예: ${SAMPLE}) (자동 조치: 원격 계정 ${AUTO_FIXED}건 삭제, 실패 ${AUTO_FAIL}건)"
    fi
fi

if [ -f "$TARGET_FILE" ]; then
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    [[ -z "$FILE_HASH" ]] && FILE_HASH="HASH_ERROR"
else
    FILE_HASH="NOT_FOUND"
fi

IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="허용되지 않은 호스트의 DB 접속이 제한되어 비인가 원격 접근 위험이 감소합니다."

cat <<EOF_JSON
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "활성 계정의 host를 로컬 허용 호스트(${ALLOWED_HOSTS_CSV}) 또는 MANUAL_ALLOWED_REMOTE_HOSTS_CSV로 제한하십시오. 와일드카드('%') 또는 불필요한 원격 host 계정은 삭제하거나 잠그십시오.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
