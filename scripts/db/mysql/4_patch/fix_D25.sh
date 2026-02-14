#!/bin/bash
# @Author: 한은결
# D-25: 주기적 보안 패치 및 벤더 권고 사항 적용
ID="D-25"
CATEGORY="패치 관리"
TITLE="주기적 보안 패치 및 벤더 권고 사항 적용"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 무한 로딩 방지
CMD_TIMEOUT_SEC=8
MYSQL_TIMEOUT_SEC=5
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"

MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 실행 옵션
DO_UPDATE="${DO_UPDATE:-N}"          # Y이면 실제 업데이트 수행
RESTART_MYSQL="${RESTART_MYSQL:-N}"  # Y이면 업데이트 후 mysqld 재시작 시도
PACKAGE_NAME="${PACKAGE_NAME:-}"     # 패키지명 강제 지정(선택)

# ✅ 수동 입력 없이도 동작하도록 "기준 최신 패치"를 내장
# - 기본 8.0.44 (요구사항)
# - 필요하면 환경변수로 변경 가능: REQUIRED_BASELINE=8.0.46 ./fix_D-25.sh
REQUIRED_BASELINE="${REQUIRED_BASELINE:-8.0.44}"

# 안내 URL(요구사항)
MYSQL_ARCHIVE_URL="http://downloads.mysql.com/archives.php"

run_cmd() {
  local cmd="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${CMD_TIMEOUT_SEC}s bash -lc "$cmd" 2>/dev/null
  else
    bash -lc "$cmd" 2>/dev/null
  fi
}

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT_SEC}s $MYSQL_CMD_BASE "$sql" 2>/dev/null
  else
    $MYSQL_CMD_BASE "$sql" 2>/dev/null
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

detect_pm() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"
  elif command -v yum >/dev/null 2>&1; then echo "yum"
  elif command -v zypper >/dev/null 2>&1; then echo "zypper"
  else echo "unknown"
  fi
}

detect_package_name() {
  local pm="$1"
  # 환경마다 패키지명이 달라서 우선순위 후보로 탐색
  case "$pm" in
    apt) echo "mysql-server" ;;
    dnf|yum|zypper) echo "mysql-community-server" ;;
    *) echo "mysql-server" ;;
  esac
}

get_candidate_version() {
  local pm="$1"
  local pkg="$2"

  case "$pm" in
    apt)
      run_cmd "apt-cache policy ${pkg} | awk '/Candidate:/{print \$2; exit}'"
      ;;
    dnf)
      run_cmd "dnf -q info ${pkg} | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=\"\"){print v\"-\"r}else{print \"\"}}'"
      ;;
    yum)
      run_cmd "yum -q info ${pkg} | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=\"\"){print v\"-\"r}else{print \"\"}}'"
      ;;
    zypper)
      run_cmd "zypper -q info ${pkg} | awk -F': ' '/^Version/{print \$2; exit}'"
      ;;
    *)
      echo ""
      ;;
  esac
}

do_update_pkg() {
  local pm="$1"
  local pkg="$2"
  case "$pm" in
    apt)
      run_cmd "apt-get update -y" >/dev/null || return 1
      run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade ${pkg}" >/dev/null || \
      run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y ${pkg}" >/dev/null
      return $?
      ;;
    dnf)
      run_cmd "dnf -y upgrade ${pkg}" >/dev/null
      return $?
      ;;
    yum)
      run_cmd "yum -y update ${pkg}" >/dev/null
      return $?
      ;;
    zypper)
      run_cmd "zypper -n up ${pkg}" >/dev/null
      return $?
      ;;
    *)
      return 1
      ;;
  esac
}

restart_mysql() {
  [[ "$RESTART_MYSQL" != "Y" ]] && return 0

  if command -v systemctl >/dev/null 2>&1; then
    run_cmd "systemctl restart mysqld || systemctl restart mysql" >/dev/null
    return $?
  fi
  run_cmd "service mysqld restart || service mysql restart" >/dev/null
  return $?
}

# ----------------------------------------------------------------------------
# 1) 현재 MySQL 버전 확인
# ----------------------------------------------------------------------------
MYSQL_VERSION_RAW="$(run_mysql "SELECT VERSION();")"
RC0=$?

if [[ $RC0 -eq 124 ]]; then
  STATUS="FAIL"
  ACTION_RESULT="FAIL"
  ACTION_LOG="조치가 수행되지 않았습니다. MySQL 버전 확인 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
  EVIDENCE="SELECT VERSION() 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 중단하였습니다."
elif [[ $RC0 -ne 0 || -z "$MYSQL_VERSION_RAW" ]]; then
  STATUS="FAIL"
  ACTION_RESULT="FAIL"
  ACTION_LOG="조치가 수행되지 않았습니다. MySQL 버전을 확인할 수 없어 최신 보안 패치 적용 여부를 판단하지 못하였습니다."
  EVIDENCE="SELECT VERSION() 수행 실패로 현재 MySQL 버전을 확인할 수 없습니다."
else
  CURRENT_SEMVER="$(extract_semver "$MYSQL_VERSION_RAW")"
  BASELINE_SEMVER="$(extract_semver "$REQUIRED_BASELINE")"

  if [[ -z "$CURRENT_SEMVER" || -z "$BASELINE_SEMVER" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 버전 비교에 필요한 형식으로 파싱하지 못했습니다."
    EVIDENCE="현재 버전=${MYSQL_VERSION_RAW}, 기준 버전=${REQUIRED_BASELINE}에서 비교용 숫자 버전 추출 실패"
  else
    # ----------------------------------------------------------------------------
    # 2) 기준(기본 8.0.44) 대비 판정
    # ----------------------------------------------------------------------------
    if version_ge "$CURRENT_SEMVER" "$BASELINE_SEMVER"; then
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="현재 MySQL 버전이 최신 보안 패치 기준 이상으로 확인되어 추가 조치 없이 유지합니다."
      EVIDENCE="현재=${MYSQL_VERSION_RAW} (비교용 ${CURRENT_SEMVER}), 기준=${REQUIRED_BASELINE} (비교용 ${BASELINE_SEMVER})"
    else
      # 기준 미달 → 안내(요구사항) + (선택) 업데이트 수행
      PM="$(detect_pm)"

      # 패키지 매니저/저장소 확인이 안 될 수도 있으므로, 안내는 항상 남김
      GUIDE_MSG="현재 버전(${CURRENT_SEMVER})이 기준(${BASELINE_SEMVER}) 미만입니다. 최신 버전/보안 패치 버전 여부는 ${MYSQL_ARCHIVE_URL}에서 MySQL Community Server 기준으로 확인 후 업데이트를 권고합니다."

      if [[ "$PM" == "unknown" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="업데이트가 필요합니다. 패키지 매니저를 확인할 수 없어 자동 업데이트를 수행하지 못했습니다. ${GUIDE_MSG}"
        EVIDENCE="현재=${MYSQL_VERSION_RAW}, 기준=${REQUIRED_BASELINE}, 패키지 매니저 미탐지"
      else
        # 패키지명 자동 지정
        if [[ -z "$PACKAGE_NAME" ]]; then
          PACKAGE_NAME="$(detect_package_name "$PM")"
        fi

        # 저장소 candidate 버전 참고(있으면 증적에 포함)
        CANDIDATE_VER="$(get_candidate_version "$PM" "$PACKAGE_NAME")"
        CANDIDATE_SEMVER="$(extract_semver "$CANDIDATE_VER")"

        if [[ "$DO_UPDATE" != "Y" ]]; then
          STATUS="FAIL"
          ACTION_RESULT="FAIL"
          ACTION_LOG="업데이트가 필요하나 자동 업데이트는 수행하지 않도록 설정되어 있습니다(DO_UPDATE!=Y). ${GUIDE_MSG}"
          EVIDENCE="현재=${MYSQL_VERSION_RAW}, 기준=${REQUIRED_BASELINE}, 저장소 후보=${CANDIDATE_VER:-N/A}"
        else
          # 실제 업데이트 수행
          do_update_pkg "$PM" "$PACKAGE_NAME"
          UPGRADE_RC=$?

          if [[ $UPGRADE_RC -ne 0 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="자동 업데이트 수행에 실패했습니다. ${GUIDE_MSG}"
            EVIDENCE="패키지 매니저=${PM}, 패키지=${PACKAGE_NAME}, 현재=${MYSQL_VERSION_RAW}, 기준=${REQUIRED_BASELINE}, 저장소 후보=${CANDIDATE_VER:-N/A}"
          else
            restart_mysql >/dev/null 2>&1 || true

            NEW_VER="$(run_mysql "SELECT VERSION();")"
            NEW_SEMVER="$(extract_semver "$NEW_VER")"

            if [[ -z "$NEW_VER" || -z "$NEW_SEMVER" ]]; then
              STATUS="FAIL"
              ACTION_RESULT="FAIL"
              ACTION_LOG="업데이트는 수행했으나 업데이트 후 버전 재확인에 실패했습니다. ${GUIDE_MSG}"
              EVIDENCE="업데이트 전=${MYSQL_VERSION_RAW}, 업데이트 후=확인 실패, 기준=${REQUIRED_BASELINE}, 저장소 후보=${CANDIDATE_VER:-N/A}"
            else
              if version_ge "$NEW_SEMVER" "$BASELINE_SEMVER"; then
                STATUS="PASS"
                ACTION_RESULT="SUCCESS"
                ACTION_LOG="MySQL 업데이트를 수행하여 최신 보안 패치 기준 이상을 충족했습니다."
                EVIDENCE="업데이트 전=${MYSQL_VERSION_RAW}(${CURRENT_SEMVER}), 업데이트 후=${NEW_VER}(${NEW_SEMVER}), 기준=${REQUIRED_BASELINE}(${BASELINE_SEMVER}), 저장소 후보=${CANDIDATE_VER:-N/A}"
              else
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="업데이트를 수행했으나 기준 버전 미만입니다. ${GUIDE_MSG}"
                EVIDENCE="업데이트 전=${MYSQL_VERSION_RAW}(${CURRENT_SEMVER}), 업데이트 후=${NEW_VER}(${NEW_SEMVER}), 기준=${REQUIRED_BASELINE}(${BASELINE_SEMVER}), 저장소 후보=${CANDIDATE_VER:-N/A}"
              fi
            fi
          fi
        fi
      fi
    fi
  fi
fi

# JSON 표준 출력
echo ""
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "guide": "MySQL은 벤더가 배포한 최신 보안 패치 적용 버전으로 업그레이드하며, 최신 릴리즈 및 보안 패치 정보는 http://downloads.mysql.com/archives.php에서 확인하세요.",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
