#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-17
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : 계정 관리
# @Platform    : MySQL
# @Severity    : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : 기본 계정의 초기 비밀번호 사용 또는 사용 제한 미적용 상태를 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


ID="D-01"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT_SEC=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# SQL root/익명 계정의 인증정보(비밀번호 해시)·잠금·호스트 조회
QUERY_PRIMARY="SELECT user, host, COALESCE(authentication_string,''), COALESCE(account_locked,'N') FROM mysql.user WHERE user='root' OR user='';"
# SQL account_locked 컬럼 미지원 환경 fallback
QUERY_FALLBACK1="SELECT user, host, COALESCE(authentication_string,''), 'N' AS account_locked FROM mysql.user WHERE user='root' OR user='';"
# SQL authentication_string 미지원(구버전) fallback
QUERY_FALLBACK2="SELECT user, host, COALESCE(password,''), 'N' AS account_locked FROM mysql.user WHERE user='root' OR user='';"

run_mysql_query() {
  local query="$1"
  # 무한 대기 방지(timeout 있으면 적용)
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
  else
    $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR"
  fi
}

# 1) 최신 컬럼 기반 조회 시도 → 실패 시 구버전 호환 fallback
ACCOUNT_INFO="$(run_mysql_query "$QUERY_PRIMARY")"
if [[ "$ACCOUNT_INFO" == "ERROR" ]]; then ACCOUNT_INFO="$(run_mysql_query "$QUERY_FALLBACK1")"; fi
if [[ "$ACCOUNT_INFO" == "ERROR" ]]; then ACCOUNT_INFO="$(run_mysql_query "$QUERY_FALLBACK2")"; fi

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE="자동 조치 시 비밀번호 설정 미비 및 권한 설정 오류가 발생할 위험이 존재하여 수동 조치가 필요합니다. 관리자가 직접 확인 후 root 계정의 비밀번호 설정 및 원격 접속 제한을 적용해 주시기 바랍니다."

# 2) 실행 실패 (타임아웃/접속 오류)
if [[ "$ACCOUNT_INFO" == "ERROR_TIMEOUT" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 조회가 ${MYSQL_TIMEOUT_SEC}초를 초과하여 점검을 완료하지 못했습니다."
  DETAIL_CONTENT="result=ERROR_TIMEOUT"
elif [[ "$ACCOUNT_INFO" == "ERROR" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 접속 실패 또는 mysql.user 조회 권한 부족으로 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="result=ERROR"
else
  VULN_COUNT=0
  ROOT_COUNT=0
  REASONS=()

  # 3) 결과 파싱 (익명/루트 계정 위험요소만 체크)
  while IFS=$'\t' read -r user host auth locked; do
    [[ -z "$user" && -z "$host" ]] && continue

    # 잠긴 계정은 영향 범위에서 제외
    [[ "$locked" == "Y" ]] && continue

    # 익명 계정 존재 자체가 취약 후보(활성 상태)
    if [[ -z "$user" ]]; then
      VULN_COUNT=$((VULN_COUNT + 1))
      REASONS+=("익명 계정 활성화: ${host}")
      continue
    fi

    # root 계정에 대해서만 추가 검증
    if [[ "$user" == "root" ]]; then
      ROOT_COUNT=$((ROOT_COUNT + 1))

      # 비밀번호 미설정(해시 공란)
      if [[ -z "$auth" ]]; then
        VULN_COUNT=$((VULN_COUNT + 1))
        REASONS+=("root 계정 비밀번호 미설정: ${host}")
        continue
      fi

      # 계정 잠금 여부 확인
      if [[ "$locked" == "N" ]]; then
        VULN_COUNT=$((VULN_COUNT + 1))
        REASONS+=("root 계정 잠금 미설정: ${host}")
      fi
    fi
  done <<< "$ACCOUNT_INFO"

  # 4) root 자체 미존재/미조회 분기(판정 불가로 FAIL)
  if [[ "$ROOT_COUNT" -eq 0 ]]; then
    STATUS="FAIL"
    REASON_LINE="root 계정이 존재하지 않거나 조회할 수 없어서 점검을 완료할 수 없기에 취약합니다."
    DETAIL_CONTENT="root_found=0"
  else
    # 5) 취약 항목 0건이면 PASS, 1건 이상이면 FAIL
    if [[ "$VULN_COUNT" -eq 0 ]]; then
      STATUS="PASS"
      REASON_LINE="기본 계정에 대한 초기 비밀번호 및 권한 정책을 변경하여 이 항목에 대하여 양호합니다."
      DETAIL_CONTENT="vuln_count=0"
    else
      STATUS="FAIL"
      REASON_LINE="$VULN_COUNT개의 취약점이 발견되어 이 항목에 대하여 취약합니다."
      DETAIL_CONTENT="vuln_count=${VULN_COUNT}\n${REASONS[*]}"
    fi
  fi
fi

CHECK_COMMAND="$MYSQL_CMD_BASE \"$QUERY_PRIMARY\" (fallback: \"$QUERY_FALLBACK1\" / \"$QUERY_FALLBACK2\")"

# 원문 결과 포함(과다 출력 우려 시 head -n 적용 가능)
DETAIL_CONTENT="${DETAIL_CONTENT}; account_info=${ACCOUNT_INFO}"

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE",
  "guide": "$GUIDE_LINE"
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