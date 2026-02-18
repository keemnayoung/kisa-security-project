#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : SHA-256 이상 기반 인증 암호 알고리즘 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-08"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user.plugin"

MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 계정별로 설정된 인증 플러그인(암호화 방식) 정보를 수집하기 위한 쿼리
QUERY="SELECT user, host, plugin FROM mysql.user;"

# 데이터베이스 응답 지연을 방지하기 위해 5초의 타임아웃을 적용하여 쿼리 실행
run_mysql_query() {
    timeout 5s $MYSQL_CMD "$QUERY" 2>/dev/null
}

RESULT=$(run_mysql_query)
RET_CODE=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 애플리케이션 접속 라이브러리 호환성 문제로 인한 서비스 중단 위험성 정의
GUIDE_LINE="이 항목에 대해서 인증 플러그인을 자동으로 변경할 경우, SHA-256 방식을 지원하지 않는 구버전 클라이언트나 애플리케이션 라이브러리에서 DB 접속 서버 연결이 차단되는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 사용 중인 애플리케이션의 커넥터 버전을 점검하고, ALTER USER 명령을 통해 caching_sha2_password와 같은 안전한 알고리즘으로 변경하여 조치해 주시기 바랍니다."

# 쿼리 실행 결과(성공, 타임아웃, 접속 에러)에 따른 판정 분기점
if [ $RET_CODE -eq 124 ]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 응답 지연으로 인해 암호화 알고리즘 정보를 조회할 수 없어 점검을 완료하지 못했습니다."
    DETAIL_CONTENT="timeout_error(5s)"
elif [ $RET_CODE -ne 0 ]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 접속 정보가 올바르지 않거나 권한이 부족하여 암호화 알고리즘 점검을 수행할 수 없습니다."
    DETAIL_CONTENT="connection_error"
else
    # SHA-256 기반이 아닌 인증 플러그인을 사용하는 계정을 식별
    # MySQL 8.0 기준 권고 방식인 caching_sha2_password를 양호 기준으로 설정
    WEAK_USERS=$(echo "$RESULT" | awk '$3!="caching_sha2_password"{print $1"@"$2"["$3"]"}')
    
    # 전체 계정 설정 현황 생성 (DETAIL_CONTENT용)
    ALL_USERS_INFO=$(echo "$RESULT" | awk '{print "- "$1"@"$2"["$3"]"}' | sed ':a;N;$!ba;s/\n/\\n/g')
    DETAIL_CONTENT="[현재 계정별 인증 플러그인 설정 현황]\n${ALL_USERS_INFO}"

    # 점검 기준에 따른 양호/취약 판정 및 사유 작성
    if [[ -z "$WEAK_USERS" ]]; then
        STATUS="PASS"
        REASON_LINE="모든 계정이 caching_sha2_password 플러그인을 사용하여 SHA-256 이상의 암호화 알고리즘으로 설정되어 있어 이 항목에 대해 양호합니다."
    else
        STATUS="FAIL"
        WEAK_LIST=$(echo "$WEAK_USERS" | tr '\n' ',' | sed 's/,$//')
        REASON_LINE="${WEAK_LIST} 계정들이 SHA-256 미만의 알고리즘으로 설정되어 있어 이 항목에 대해 취약합니다."
    fi
fi

# 증적 데이터를 JSON 형식으로 구조화
CHECK_COMMAND="mysql -N -s -B -e \"$QUERY\""
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# 파이썬 대시보드 및 DB에서 줄바꿈(\n)이 정상적으로 유지되도록 이스케이프 처리
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 결과값 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF