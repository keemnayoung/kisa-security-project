#!/bin/bash

# 1. 환경변수 설정 (외부 의존성 제거)
export POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
export POSTGRES_PORT="${POSTGRES_PORT:-5432}"
export POSTGRES_DB="${POSTGRES_DB:-postgres}"
export POSTGRES_USER="${POSTGRES_USER:-postgres}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
export PG_SUPERUSER="${PG_SUPERUSER:-postgres}"

# 2. 기본 정보
ID="D-01"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="pg_shadow"

# 점검 쿼리
CHECK_SQL="SELECT s.usename FROM pg_shadow s JOIN pg_roles r ON r.rolname=s.usename WHERE r.rolsuper=true AND (s.passwd IS NULL OR s.passwd='');"

REASON_LINE=""
DETAIL_CONTENT=""

# 3. 접속 함수 (핵심: 멈춤 방지 로직)
run_psql() {
  local sql="$1"
  local timeout_cmd=""

  if command -v timeout >/dev/null 2>&1; then
    timeout_cmd="timeout 10s"
  fi
  
  # [시도 1] 비밀번호(환경변수)로 접속 시도 (MySQL 방식)
  # -h localhost를 명시해서 Peer 인증 대신 Password 인증을 유도함
  # -w(--no-password)로 비밀번호 프롬프트 대기를 차단함
  if PGPASSWORD="${POSTGRES_PASSWORD}" $timeout_cmd psql -w -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null; then
    return 0
  fi

  # [시도 2] sudo 사용 (Peer 인증)
  # ★★★ 중요: -n 옵션 (non-interactive) 추가 ★★★
  # 비밀번호 물어볼 상황이면 그냥 '실패'하고 넘어감 (무한 로딩 방지)
  if command -v sudo >/dev/null 2>&1; then
    $timeout_cmd sudo -n -u "$PG_SUPERUSER" psql -w -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null
    return $?
  fi
  
  return 1
}

# 4. 실행
VULN_USERS=$(run_psql "$CHECK_SQL")
RET_CODE=$?

# 5. 결과 판단
if [ $RET_CODE -ne 0 ]; then
  STATUS="FAIL"
  REASON_LINE="PostgreSQL 접속 실패 (권한 부족 또는 설정 오류). 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="connection_failed"
elif [ -z "$VULN_USERS" ]; then
  STATUS="PASS"
  REASON_LINE="PostgreSQL에서 비밀번호가 미설정된 SUPERUSER 계정이 존재하지 않습니다."
  DETAIL_CONTENT="no_superuser_without_password"
else
  STATUS="FAIL"
  REASON_LINE="PostgreSQL에서 비밀번호가 미설정된 SUPERUSER 계정이 발견되었습니다."
  DETAIL_CONTENT="$(printf "%s\n" "$VULN_USERS" | sed 's/[[:space:]]*$//')"
fi

# 6. JSON 생성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "SELECT usename FROM pg_shadow ...",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# 7. 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
