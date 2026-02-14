#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
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
CATEGORY="패치 관리"
TITLE="주기적 보안 패치 및 벤더 권고 사항 적용"
IMPORTANCE="상"

# 조치 결과 변수
STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 무한 로딩 방지
TIMEOUT_BIN=""
CMD_TIMEOUT_SEC=8
MYSQL_TIMEOUT_SEC=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

run_cmd() {
    local cmd="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${CMD_TIMEOUT_SEC}s bash -lc "$cmd" 2>/dev/null
        return $?
    else
        bash -lc "$cmd" 2>/dev/null
        return $?
    fi
}

run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT_SEC}s $MYSQL_CMD_BASE "$sql" 2>/dev/null
        return $?
    else
        $MYSQL_CMD_BASE "$sql" 2>/dev/null
        return $?
    fi
}

extract_semver() {
    local v="$1"
    # 8.0.44-0ubuntu0.22.04.1 같은 문자열에서 비교 가능한 숫자 버전만 추출
    echo "$v" | grep -Eo '[0-9]+(\.[0-9]+){1,3}' | head -n 1
}

version_ge() {
    # $1 >= $2 이면 0
    local a="$1"
    local b="$2"
    [[ -z "$a" || -z "$b" ]] && return 1
    local first
    first="$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n 1)"
    [[ "$first" == "$b" ]]
}

# 0) 실행 옵션(환경변수)
# 기본은 실제 업데이트 미수행(점검/안내)
DO_UPDATE="${DO_UPDATE:-N}"          # Y이면 실제 업데이트 수행
RESTART_MYSQL="${RESTART_MYSQL:-N}"  # Y이면 업데이트 후 mysqld 재시작 시도
PACKAGE_NAME="${PACKAGE_NAME:-}"     # 패키지명 강제 지정(선택)
VENDOR_LATEST_VERSION="${VENDOR_LATEST_VERSION:-}"  # 벤더 공지 최신 버전(수동 입력)

# MySQL 버전 확인(SELECT VERSION())
MYSQL_VERSION_RAW="$(run_mysql "SELECT VERSION();")"
RC0=$?

if [[ $RC0 -eq 124 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 버전 확인 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
    EVIDENCE="MySQL 버전 확인(SELECT VERSION()) 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
elif [[ $RC0 -ne 0 || -z "$MYSQL_VERSION_RAW" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 버전을 확인할 수 없어 업데이트 여부를 판단하지 못하였습니다."
    EVIDENCE="SELECT VERSION() 수행에 실패하여 현재 설치된 MySQL 버전을 확인할 수 없습니다."
else
    # D-25 핵심: 현재 DBMS 버전을 확인하고 최신 기준과 비교할 대상을 준비한다.
    CURRENT_SEMVER="$(extract_semver "$MYSQL_VERSION_RAW")"

    # 패키지 매니저 탐지
    PM=""
    if command -v apt-get >/dev/null 2>&1; then PM="apt"
    elif command -v dnf >/dev/null 2>&1; then PM="dnf"
    elif command -v yum >/dev/null 2>&1; then PM="yum"
    elif command -v zypper >/dev/null 2>&1; then PM="zypper"
    else PM="unknown"
    fi

    # 설치 패키지명 자동 추정(환경마다 다름)
    if [[ -z "$PACKAGE_NAME" ]]; then
        case "$PM" in
            apt)    PACKAGE_NAME="mysql-server" ;;
            dnf|yum) PACKAGE_NAME="mysql-community-server" ;;  # 오라클 repo 사용 시 흔함
            zypper) PACKAGE_NAME="mysql-community-server" ;;
            *)      PACKAGE_NAME="mysql-server" ;;
        esac
    fi

    # "저장소 기준 최신 후보 버전" 조회
    CANDIDATE_VER="N/A"
    case "$PM" in
        apt)
            # apt-cache policy 출력에서 Candidate 추출
            CANDIDATE_VER="$(run_cmd "apt-cache policy ${PACKAGE_NAME} | awk '/Candidate:/{print \$2; exit}'")"
            ;;
        dnf)
            # dnf info에서 Version/Release 추출(가능한 경우)
            CANDIDATE_VER="$(run_cmd "dnf -q info ${PACKAGE_NAME} | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=\"\"){print v\"-\"r}else{print \"N/A\"}}'")"
            ;;
        yum)
            CANDIDATE_VER="$(run_cmd "yum -q info ${PACKAGE_NAME} | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=\"\"){print v\"-\"r}else{print \"N/A\"}}'")"
            ;;
        zypper)
            CANDIDATE_VER="$(run_cmd "zypper -q info ${PACKAGE_NAME} | awk -F': ' '/^Version/{print \$2; exit}'")"
            ;;
        *)
            CANDIDATE_VER="N/A"
            ;;
    esac

    CANDIDATE_SEMVER="$(extract_semver "$CANDIDATE_VER")"
    VENDOR_SEMVER="$(extract_semver "$VENDOR_LATEST_VERSION")"

    # D-25 핵심: 벤더 최신 버전(수동 입력) 우선, 없으면 저장소 최신 후보를 기준으로 보안 패치 필요 여부를 판정한다.
    REF_LABEL=""
    REF_RAW=""
    REF_SEMVER=""
    if [[ -n "$VENDOR_SEMVER" ]]; then
        REF_LABEL="벤더 최신 버전"
        REF_RAW="$VENDOR_LATEST_VERSION"
        REF_SEMVER="$VENDOR_SEMVER"
    elif [[ -n "$CANDIDATE_SEMVER" ]]; then
        REF_LABEL="패키지 저장소 최신 후보"
        REF_RAW="$CANDIDATE_VER"
        REF_SEMVER="$CANDIDATE_SEMVER"
    fi

    BASE_EVID="현재 MySQL 버전은 ${MYSQL_VERSION_RAW}이며, ${REF_LABEL:-비교 기준}은 ${REF_RAW:-N/A}입니다."

    if [[ -z "$CURRENT_SEMVER" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 현재 버전 문자열을 비교 가능한 형식으로 해석하지 못했습니다."
        EVIDENCE="SELECT VERSION() 결과(${MYSQL_VERSION_RAW})에서 비교용 버전을 추출하지 못했습니다."
    elif [[ -z "$REF_SEMVER" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 최신 기준 버전을 확인할 수 없어 업데이트 필요 여부를 판단하지 못했습니다."
        EVIDENCE="${BASE_EVID} VENDOR_LATEST_VERSION(예: 8.0.44)을 지정하거나 패키지 저장소 조회 가능 환경에서 재실행해야 합니다."
    else
        if version_ge "$CURRENT_SEMVER" "$REF_SEMVER"; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="현재 MySQL 버전이 최신 기준 이상으로 확인되어 추가 업데이트 없이 보안 패치 상태를 유지하였습니다."
            EVIDENCE="${BASE_EVID} 비교 결과 현재 버전(${CURRENT_SEMVER})이 기준 버전(${REF_SEMVER}) 이상입니다."
        else
            # 최신이 아닐 수 있음 → DO_UPDATE에 따라 실제 업데이트 수행
            if [[ "$DO_UPDATE" != "Y" ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 최신 버전 확인 결과 업데이트가 필요하나, 자동 업데이트는 수행하지 않도록 설정되어 있습니다."
                EVIDENCE="${BASE_EVID} 업데이트 적용이 필요하며, DO_UPDATE=Y로 실행 시 패키지 업데이트를 수행할 수 있습니다."
            else
                # D-25 핵심: 보안 패치가 적용된 버전으로 실제 업데이트를 수행한다.
                # 실제 업데이트 수행
                UPGRADE_RC=1
                case "$PM" in
                    apt)
                        run_cmd "apt-get update -y" >/dev/null
                        run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y ${PACKAGE_NAME}" >/dev/null
                        UPGRADE_RC=$?
                        ;;
                    dnf)
                        run_cmd "dnf -y upgrade ${PACKAGE_NAME}" >/dev/null
                        UPGRADE_RC=$?
                        ;;
                    yum)
                        run_cmd "yum -y update ${PACKAGE_NAME}" >/dev/null
                        UPGRADE_RC=$?
                        ;;
                    zypper)
                        run_cmd "zypper -n up ${PACKAGE_NAME}" >/dev/null
                        UPGRADE_RC=$?
                        ;;
                esac

                if [[ $UPGRADE_RC -ne 0 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 패키지 업데이트 수행에 실패하였습니다."
                    EVIDENCE="${BASE_EVID} 패키지 업데이트 명령 수행에 실패하여 보안 패치를 적용할 수 없습니다."
                else
                    # (선택) mysqld 재시작
                    if [[ "$RESTART_MYSQL" == "Y" ]]; then
                        # systemctl 우선, 없으면 service 시도
                        if command -v systemctl >/dev/null 2>&1; then
                            run_cmd "systemctl restart mysqld || systemctl restart mysql" >/dev/null
                        else
                            run_cmd "service mysqld restart || service mysql restart" >/dev/null
                        fi
                    fi

                    # 업데이트 후 버전 재확인
                    NEW_MYSQL_VER="$(run_mysql "SELECT VERSION();")"
                    if [[ -z "$NEW_MYSQL_VER" ]]; then
                        NEW_MYSQL_VER="확인되지 않음"
                    fi
                    NEW_SEMVER="$(extract_semver "$NEW_MYSQL_VER")"

                    if [[ -n "$NEW_SEMVER" ]] && version_ge "$NEW_SEMVER" "$REF_SEMVER"; then
                        STATUS="PASS"
                        ACTION_RESULT="SUCCESS"
                        ACTION_LOG="MySQL을 보안 패치 적용 버전으로 업데이트하여 벤더 권고 사항을 반영했습니다."
                        EVIDENCE="업데이트 전 ${MYSQL_VERSION_RAW}, 업데이트 후 ${NEW_MYSQL_VER}로 확인되며 기준 버전(${REF_SEMVER}) 이상입니다."
                    else
                        STATUS="FAIL"
                        ACTION_RESULT="FAIL"
                        ACTION_LOG="조치가 부분적으로만 수행되었습니다. 업데이트는 수행했으나 최신 기준 충족을 확인하지 못했습니다."
                        EVIDENCE="업데이트 후 버전(${NEW_MYSQL_VER})이 기준 버전(${REF_RAW}) 이상인지 확인되지 않았습니다."
                    fi
                fi
            fi
        fi
    fi
fi

# JSON 표준 출력 (고정 구조)
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "SELECT VERSION()으로 확인한 현재 버전을 벤더 최신 버전(VENDOR_LATEST_VERSION) 또는 패키지 저장소 최신 후보와 비교하십시오. 기준 미만이면 DO_UPDATE=Y로 업데이트를 수행하고, 필요 시 RESTART_MYSQL=Y로 재시작한 뒤 버전을 재확인하십시오.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
