#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
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
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user.host"

MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"

# 점검 시 제외할 내부망 및 로컬 주소 정의
ALLOWED_HOSTS_CSV="${ALLOWED_HOSTS_CSV:-localhost,127.0.0.1,::1}"

# MySQL 쿼리 실행 함수 (타임아웃 및 에러 처리 포함)
run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
    else
        $MYSQL_CMD "$sql" 2>/dev/null
    fi
}

# CSV 형식의 리스트에 특정 값이 포함되어 있는지 확인하는 함수
in_csv() {
    local needle="$1"
    local csv="$2"
    IFS=',' read -r -a arr <<< "$csv"
    for item in "${arr[@]}"; do
        [[ "$needle" == "$item" ]] && return 0
    done
    return 1
}

# 로컬 전용 계정 및 수동 관리 대상 리스트 설정
AUTO_LOCAL_USERS_CSV="${AUTO_LOCAL_USERS_CSV:-root}"
MANUAL_ALLOWED_REMOTE_HOSTS_CSV="${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:-}"
MANUAL_REVIEW_USERS_CSV="${MANUAL_REVIEW_USERS_CSV:-admin}"

# 계정 상태(잠금 여부)를 포함하여 유효한 접속 호스트 정보를 조회
Q1="SELECT user,host,COALESCE(account_locked,'N') FROM mysql.user;"
Q2="SELECT user,host,'N' FROM mysql.user;"

ROWS="$(run_mysql "$Q1")"
RC=$?
# account_locked 컬럼이 없는 구버전 대응
if [[ $RC -ne 0 ]]; then
    ROWS="$(run_mysql "$Q2")"
    RC=$?
fi

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치(계정 삭제/수정) 시 발생할 수 있는 운영 환경 접속 차단 위험 정의
GUIDE_LINE="이 항목에 대해서 모든 클라이언트('%') 접속 계정을 자동으로 변경하거나 삭제할 경우, 실제 운영 중인 애플리케이션의 DB 접속이 즉시 차단되어 서비스 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 사용되지 않는 원격 접속 계정은 DROP USER 명령으로 삭제하고, 필요한 계정은 UPDATE user SET host='<특정IP>' WHERE... 명령을 통해 접속 범위를 특정 IP로 제한하여 조치해 주시기 바랍니다."

# 점검 수행 가능 여부 판정 분기점
if [[ $RC -eq 124 ]]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 조회 시간이 제한 시간을 초과하여 이 항목에 대한 점검을 완료할 수 없습니다."
    DETAIL_CONTENT="timeout_error(${MYSQL_TIMEOUT}s)"
elif [[ $RC -ne 0 || -z "$ROWS" ]]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 접속 권한 문제나 연결 오류로 인해 이 항목에 대한 점검을 수행할 수 없습니다."
    DETAIL_CONTENT="connection_error(mysql_access=FAILED)"
else
    VULN_COUNT=0
    SAMPLE_LIST=""
    TOTAL_LIST=""
    AUTO_FIXED=0

    # 수집된 계정 정보를 순회하며 원격 허용 정책 위반 여부 확인
    while IFS=$'\t' read -r user host locked; do
        [[ -z "$host" ]] && continue
        TOTAL_LIST="${TOTAL_LIST}${user}@${host}(locked:${locked})\n"

        # 계정이 잠겨 있거나 허용된 로컬/원격 호스트인 경우 통과
        if [[ "$locked" == "Y" ]] || in_csv "$host" "$ALLOWED_HOSTS_CSV" || ([[ -n "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV" ]] && in_csv "$host" "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV"); then
            continue
        fi

        # 허용되지 않은 원격 접속('%' 등) 식별
        VULN_COUNT=$((VULN_COUNT + 1))
        SAMPLE_LIST="${SAMPLE_LIST}${user}@${host},"
    done <<< "$ROWS"

    # 점검 결과에 따른 사유 문구 생성
    if [[ $VULN_COUNT -eq 0 ]]; then
        STATUS="PASS"
        REASON_LINE="모든 활성 계정이 지정된 허용 호스트(${ALLOWED_HOSTS_CSV})로 제한되어 있어 이 항목에 대해 양호합니다."
    else
        STATUS="FAIL"
        CLEAN_SAMPLES=$(echo "$SAMPLE_LIST" | sed 's/,$//')
        REASON_LINE="${CLEAN_SAMPLES} 계정이 모든 호스트('%') 또는 허용되지 않은 원격 주소로 설정되어 있어 이 항목에 대해 취약합니다."
    fi
    
    # 전체 계정 설정 현황 상세 작성
    DETAIL_CONTENT="[전체 계정 접속 허용 범위 설정 값]\n${TOTAL_LIST}"
fi

# 증적 데이터 JSON 구조화
CHECK_COMMAND="mysql -e \"SELECT user,host,account_locked FROM mysql.user;\""
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# 파이썬/DB 환경에서 개행 및 특수문자 처리를 위한 이스케이프
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 결과 JSON 출력
echo ""
cat << EOF_JSON
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF_JSON