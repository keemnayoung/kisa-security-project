#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : 패치 관리
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 안전한 버전의 데이터베이스를 사용하고 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-25"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
CMD_TIMEOUT_SEC=8
MYSQL_TIMEOUT_SEC=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 시스템 명령 실행 및 타임아웃 처리 함수
run_cmd() {
    local cmd="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${CMD_TIMEOUT_SEC}s bash -lc "$cmd" 2>/dev/null
    else
        bash -lc "$cmd" 2>/dev/null
    fi
}

# MySQL 쿼리 실행 및 버전 정보 수집 함수
run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT_SEC}s $MYSQL_CMD_BASE "$sql" 2>/dev/null
    else
        $MYSQL_CMD_BASE "$sql" 2>/dev/null
    fi
}

# 문자열에서 시맨틱 버전(숫자.숫자.숫자)만 추출
extract_semver() {
    echo "$1" | grep -Eo '[0-9]+(\.[0-9]+){1,3}' | head -n 1
}

# 버전 비교 함수 (현재 버전 >= 기준 버전)
version_ge() {
    local a="$1"
    local b="$2"
    [[ -z "$a" || -z "$b" ]] && return 1
    local first
    first="$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n 1)"
    [[ "$first" == "$b" ]]
}

# 벤더 공지 최신 버전(수동 입력용 환경변수)
VENDOR_LATEST_VERSION="${VENDOR_LATEST_VERSION:-}"

# 현재 설치된 MySQL 버전 확인 및 접속 테스트
MYSQL_VERSION_RAW="$(run_mysql "SELECT VERSION();")"
RC0=$?

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 패치 시 발생할 수 있는 서비스 중단 및 호환성 위험 정의
GUIDE_LINE="이 항목에 대해서 데이터베이스 엔진을 자동으로 업데이트할 경우, 패치 과정 중 DB 서비스가 재시작되어 실시간 트래픽이 차단되거나 신규 버전에서의 쿼리 호환성 문제로 애플리케이션 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 점검 대상 서버의 중요도를 고려하여 백업을 선행하고, 정기 점검 시간에 패키지 매니저(yum, apt 등)를 이용해 최신 보안 패치를 적용하여 조치해 주시기 바랍니다."

# 버전 정보 수집 가능 여부에 따른 분기점
if [[ $RC0 -eq 124 ]]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 응답 지연으로 인해 현재 설치된 버전을 확인할 수 없어 점검을 수행하지 못했습니다."
    DETAIL_CONTENT="timeout_error(${MYSQL_TIMEOUT_SEC}s)"
elif [[ $RC0 -ne 0 || -z "$MYSQL_VERSION_RAW" ]]; then
    STATUS="FAIL"
    REASON_LINE="데이터베이스 접속 권한 부족 또는 연결 오류로 인해 버전 패치 여부를 판단할 수 없습니다."
    DETAIL_CONTENT="connection_error(mysql_access=FAILED)"
else
    CURRENT_SEMVER="$(extract_semver "$MYSQL_VERSION_RAW")"
    
    # 패키지 매니저별 최신 후보 버전 조회
    PM="unknown"
    command -v apt-get >/dev/null 2>&1 && PM="apt"
    command -v dnf >/dev/null 2>&1 && PM="dnf"
    command -v yum >/dev/null 2>&1 && PM="yum"
    
    CANDIDATE_VER="N/A"
    case "$PM" in
        apt) CANDIDATE_VER="$(run_cmd "apt-cache policy mysql-server | awk '/Candidate:/{print \$2; exit}'")" ;;
        dnf|yum) CANDIDATE_VER="$(run_cmd "$PM -q info mysql-community-server | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=\"\"){print v\"-\"r}else{print \"N/A\"}}'")" ;;
    esac

    CANDIDATE_SEMVER="$(extract_semver "$CANDIDATE_VER")"
    VENDOR_SEMVER="$(extract_semver "$VENDOR_LATEST_VERSION")"

    # 비교 기준 결정 (사용자 입력 우선, 없을 시 저장소 후보)
    REF_SEMVER=""
    if [[ -n "$VENDOR_SEMVER" ]]; then
        REF_SEMVER="$VENDOR_SEMVER"
    else
        REF_SEMVER="$CANDIDATE_SEMVER"
    fi

    # 버전 비교 및 보안성 판단 분기점
    if [[ -z "$CURRENT_SEMVER" ]]; then
        STATUS="FAIL"
        REASON_LINE="설치된 MySQL 버전 문자열 형식을 해석할 수 없어 점검을 완료할 수 없습니다."
        DETAIL_CONTENT="parsed_version=NULL, raw_string=${MYSQL_VERSION_RAW}"
    elif [[ -z "$REF_SEMVER" ]]; then
        STATUS="FAIL"
        REASON_LINE="벤더 권고 버전 또는 저장소의 최신 패치 정보를 확인할 수 없어 점검을 수행할 수 없습니다."
        DETAIL_CONTENT="reference_version=NOT_FOUND"
    else
        # 양호/취약 판정 및 설정값 명시 분기점
        if version_ge "$CURRENT_SEMVER" "$REF_SEMVER"; then
            STATUS="PASS"
            REASON_LINE="현재 사용 중인 버전(${CURRENT_SEMVER})이 벤더 권고 기준 버전(${REF_SEMVER}) 이상으로 유지되고 있어 이 항목에 대해 양호합니다."
        else
            STATUS="FAIL"
            REASON_LINE="현재 사용 중인 버전(${CURRENT_SEMVER})이 보안 패치가 적용된 기준 버전(${REF_SEMVER}) 미만으로 확인되어 이 항목에 대해 취약합니다."
        fi
        DETAIL_CONTENT="[MySQL 패치 관리 상세 현황]\n- 현재 설치 버전: ${MYSQL_VERSION_RAW}\n- 저장소 최신 후보: ${CANDIDATE_VER}\n- 벤더 권고 기준: ${VENDOR_LATEST_VERSION:-N/A}"
    fi
fi

# 증적용 JSON 구조화 및 개행 처리
CHECK_COMMAND="SELECT VERSION(); package manager info check;"
TARGET_FILE="DBMS(MySQL) Version"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# 파이썬/DB 환경에서 줄바꿈(\n)이 정상적으로 유지되도록 이스케이프 처리
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 결과 출력 (파이썬 대시보드 연동용)
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF