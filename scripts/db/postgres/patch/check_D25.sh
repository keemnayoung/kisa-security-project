#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-25"
STATUS="FAIL"

# PostgreSQL 공식 지원 종료(EOL) 및 최신 마이너 버전 정책 정보
PG_VERSION_POLICY="${PG_VERSION_POLICY:-18|18.2|Yes|2030-11-14;17|17.8|Yes|2029-11-08;16|16.12|Yes|2028-11-09;15|15.16|Yes|2027-11-11;14|14.21|Yes|2026-11-12;13|13.23|No|2025-11-13;12|12.22|No|2024-11-21;11|11.22|No|2023-11-09;10|10.23|No|2022-11-10;9.6|9.6.24|No|2021-11-11}"

# 현재 서버 버전 확인 (기존 로직 유지)
VERSION="$(run_psql "SHOW server_version;" | xargs)"
VERSION="$(echo "$VERSION" | awk '{print $1}')"

# 메이저 버전 정규화 함수 (기존 로직 유지)
normalize_major() {
  local v="$1"
  local a b
  a="$(echo "$v" | cut -d'.' -f1)"
  b="$(echo "$v" | cut -d'.' -f2)"
  if [ -z "$a" ] || ! echo "$a" | grep -Eq '^[0-9]+$'; then
    echo ""
    return
  fi
  if [ "$a" -ge 10 ]; then
    echo "$a"
  else
    [ -z "$b" ] && b="0"
    echo "$a.$b"
  fi
}

# 버전 비교 함수 (기존 로직 유지)
vercmp() {
  local a="$1" b="$2"
  local ai bi i
  IFS='.' read -r -a A <<< "$a"
  IFS='.' read -r -a B <<< "$b"
  local n="${#A[@]}"
  [ "${#B[@]}" -gt "$n" ] && n="${#B[@]}"
  for ((i=0; i<n; i++)); do
    ai="${A[$i]:-0}"
    bi="${B[$i]:-0}"
    ai="${ai%%[^0-9]*}"
    bi="${bi%%[^0-9]*}"
    [ -z "$ai" ] && ai=0
    [ -z "$bi" ] && bi=0
    if [ "$ai" -lt "$bi" ]; then echo -1; return; fi
    if [ "$ai" -gt "$bi" ]; then echo 1; return; fi
  done
  echo 0
}

# 정책 조회 함수 (기존 로직 유지)
policy_lookup() {
  local key="$1"
  echo "$PG_VERSION_POLICY" | tr ';' '\n' | awk -F'|' -v k="$key" '$1==k {print; exit}'
}

# 패키지 매니저 조회용 이름 추정 함수 (기존 로직 유지)
detect_pkg_query_name() {
  if command -v rpm >/dev/null 2>&1; then
    rpm -qa --qf '%{NAME}\n' 2>/dev/null \
      | grep -E '^postgresql([0-9]+)?-server$' \
      | head -n 1
  fi
}

# 레포지토리 내 타겟 마이너 버전 존재 여부 확인 (기존 로직 유지)
repo_has_target_minor() {
  local pkg="$1"
  local minor="$2"
  command -v dnf >/dev/null 2>&1 || return 2
  [ -n "$pkg" ] || return 2
  [ -n "$minor" ] || return 2
  dnf --showduplicates list "$pkg" 2>/dev/null | grep -Fq "$minor"
  return $?
}

# JSON 내 줄바꿈(\n) 처리를 위한 이스케이프 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE="이 항목에 대해서 데이터베이스 엔진 업데이트를 자동으로 수행할 경우, 업데이트 패키지 간의 의존성 충돌이나 업데이트 직후 서비스 재시작 과정에서 예기치 못한 설정 오류로 인해 전체 서비스가 중단될 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 운영 환경의 백업 상태를 점검한 뒤, dnf/yum 등의 패키지 매니저를 이용해 권장 최신 마이너 버전(${POLICY_MINOR:-latest})으로 업데이트하거나 신규 메이저 버전으로 업그레이드하여 조치해 주시기 바랍니다."

# 버전 정보 존재 여부에 따른 분석 분기점
if [ -z "$VERSION" ]; then
  STATUS="FAIL"
  REASON_LINE="PostgreSQL 서버 버전을 확인할 수 없어 보안 패치 적용 여부를 판단하지 못해 이 항목에 대해 취약합니다."
else
  TODAY="$(date '+%Y-%m-%d')"
  MAJOR_KEY="$(normalize_major "$VERSION")"
  POLICY_ROW="$(policy_lookup "$MAJOR_KEY")"

  # 정책 테이블 존재 여부에 따른 분석 분기점
  if [ -z "$MAJOR_KEY" ] || [ -z "$POLICY_ROW" ]; then
    STATUS="FAIL"
    REASON_LINE="사용 중인 ${VERSION} 버전의 정책 기준이 내부 테이블에 존재하지 않아 보안 패치 적정성을 확인할 수 없으므로 이 항목에 대해 취약합니다."
  else
    POLICY_MINOR="$(echo "$POLICY_ROW" | awk -F'|' '{print $2}')"
    POLICY_SUPPORTED="$(echo "$POLICY_ROW" | awk -F'|' '{print $3}')"
    POLICY_FINAL="$(echo "$POLICY_ROW" | awk -F'|' '{print $4}')"
    CMP="$(vercmp "$VERSION" "$POLICY_MINOR")"

    # EOL(지원 종료) 여부 및 마이너 버전 비교 분기점
    if [ "$POLICY_SUPPORTED" != "Yes" ] || [ "$TODAY" \> "$POLICY_FINAL" ]; then
      STATUS="FAIL"
      REASON_LINE="사용 중인 ${VERSION} 버전이 공식 지원 종료(EOL: ${POLICY_FINAL})되어 보안 패치가 제공되지 않으므로 이 항목에 대해 취약합니다."
    elif [ "$CMP" -lt 0 ]; then
      STATUS="FAIL"
      REASON_LINE="현재 사용 중인 버전이 ${VERSION}으로, 권장 최신 마이너 버전인 ${POLICY_MINOR}보다 낮아 보안 패치가 누락될 수 있으므로 이 항목에 대해 취약합니다."
    elif [ "$CMP" -gt 0 ]; then
      STATUS="FAIL"
      REASON_LINE="현재 설치된 버전이 ${VERSION}으로, 정책 테이블에 등록된 최신 기준인 ${POLICY_MINOR}보다 높아 정책 정보 최신화가 필요하므로 이 항목에 대해 취약합니다."
    else
      STATUS="PASS"
      REASON_LINE="공식 지원 기간 내에 있는 ${VERSION} 버전을 사용 중이며 마이너 버전이 최신 정책 기준인 ${POLICY_MINOR}과 일치하여 이 항목에 대해 양호합니다."
    fi
  fi
fi

# 양호/취약 관계없이 현재 설정값(버전 정보) 명시
DETAIL_CONTENT="현재 서버 버전: ${VERSION:-알 수 없음}\n정책상 메이저 버전: ${MAJOR_KEY:-N/A}\n권장 최신 마이너 버전: ${POLICY_MINOR:-N/A}\n기술 지원 종료일(EOL): ${POLICY_FINAL:-N/A}"

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="server_version과 PG_VERSION_POLICY(최신 minor/EOL) 비교 점검"
TARGET_FILE="server_version"

# 요구사항을 반영한 RAW_EVIDENCE JSON 구성
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$(escape_json_str "$CHECK_COMMAND")",
  "detail": "$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "guide": "$(escape_json_str "$GUIDE_LINE")",
  "target_file": "$(escape_json_str "$TARGET_FILE")"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# 최종 결과 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF