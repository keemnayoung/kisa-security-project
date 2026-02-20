#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : 지정된 IP 주소에서만 DB 서버 접속이 허용되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-10"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

# PostgreSQL 설정 파일 및 접속 주소 정보 수집
CONF_FILE=$(run_psql "SHOW config_file;" | xargs)
HBA_FILE=$(run_psql "SHOW hba_file;" | xargs)
LISTEN_ADDR=$(run_psql "SHOW listen_addresses;" | xargs)

# 구성 파일 경로 및 설정값 추출을 위한 기존 함수 로직 유지
resolve_conf_path() {
  local p="$1"
  if [ -n "$p" ] && [ -f "$p" ]; then
    printf '%s' "$p"
    return 0
  fi
  if [ -n "${PGDATA:-}" ] && [ -f "${PGDATA}/postgresql.conf" ]; then
    printf '%s' "${PGDATA}/postgresql.conf"
    return 0
  fi
  return 1
}

resolve_hba_path() {
  local p="$1"
  if [ -n "$p" ] && [ -f "$p" ]; then
    printf '%s' "$p"
    return 0
  fi
  if [ -n "${PGDATA:-}" ] && [ -f "${PGDATA}/pg_hba.conf" ]; then
    printf '%s' "${PGDATA}/pg_hba.conf"
    return 0
  fi
  return 1
}

extract_listen_addresses_from_file() {
  local f="$1"
  [ -n "$f" ] && [ -f "$f" ] || return 1
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
    {
      line=$0
      sub(/[[:space:]]*#.*/,"",line)
      if (line ~ /^[[:space:]]*listen_addresses[[:space:]]*=/) {
        sub(/^[[:space:]]*listen_addresses[[:space:]]*=/,"",line)
        gsub(/^[[:space:]]+/,"",line); gsub(/[[:space:]]+$/,"",line)
        gsub(/^'\''/,"",line); gsub(/'\''$/,"",line)
        gsub(/^"/,"",line); gsub(/"$/,"",line)
        v=line
      }
    }
    END{ if (v!="") print v }
  ' "$f"
}

is_listen_safe() {
  local raw="$1"
  raw=$(printf '%s' "$raw" | tr -d "'\"" | tr -d '[:space:]')
  [ -n "$raw" ] || return 1
  printf '%s' "$raw" | tr ',' '\n' | awk '
    BEGIN{ok=1}
    {
      t=tolower($0)
      if (t=="" ) next
      if (t!="localhost" && t!="127.0.0.1" && t!="::1") ok=0
    }
    END{exit(ok?0:1)}
  '
}

is_loopback_addr() {
  local addr="$1"
  addr=$(printf '%s' "$addr" | tr -d "'\"" | tr -d '[:space:]')
  printf '%s' "$addr" | awk '
    {a=tolower($0)}
    END{
      if (a=="localhost" || a=="samehost") exit 0
      if (a=="127.0.0.1/32" || a=="127.0.0.0/8" || a=="127.0.0.1") exit 0
      if (a=="::1/128" || a=="::1") exit 0
      exit 1
    }
  '
}

is_open_addr() {
  local addr="$1"
  addr=$(printf '%s' "$addr" | tr -d "'\"" | tr -d '[:space:]')
  printf '%s' "$addr" | awk '
    {a=tolower($0)}
    END{
      if (a=="*" || a=="all" || a=="0.0.0.0/0" || a=="::/0" || a=="::0/0" || a=="0/0") exit 0
      exit 1
    }
  '
}

# pg_hba.conf 경로 확인 및 listen_addresses 설정값 확정
HBA_FILE_RESOLVED="$(resolve_hba_path "$HBA_FILE" 2>/dev/null || true)"
if [ -n "$HBA_FILE_RESOLVED" ] && [ -f "$HBA_FILE_RESOLVED" ]; then
  HBA_FILE="$HBA_FILE_RESOLVED"
fi

if [ -z "${LISTEN_ADDR:-}" ]; then
  CONF_FILE_RESOLVED="$(resolve_conf_path "$CONF_FILE" 2>/dev/null || true)"
  AUTO_CONF=""
  if [ -n "${PGDATA:-}" ] && [ -f "${PGDATA}/postgresql.auto.conf" ]; then
    AUTO_CONF="${PGDATA}/postgresql.auto.conf"
  fi
  LISTEN_ADDR="$(extract_listen_addresses_from_file "$AUTO_CONF" 2>/dev/null || true)"
  [ -z "${LISTEN_ADDR:-}" ] && LISTEN_ADDR="$(extract_listen_addresses_from_file "$CONF_FILE_RESOLVED" 2>/dev/null || true)"
fi

# pg_hba.conf 파일 존재 여부에 따른 분석
if [ -z "$HBA_FILE" ] || [ ! -f "$HBA_FILE" ]; then
  STATUS="FAIL"
  REASON_LINE="pg_hba.conf 경로를 확인할 수 없어 원격 접속 허용 범위를 점검하지 못했습니다."
  DETAIL_CONTENT="hba_file=NOT_FOUND"
else
  # 원격 접속 규칙 및 허용 주소 추출 로직
  HOST_SUMMARY=$(
    awk '
      /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
      {
        line=NR
        sub(/[[:space:]]*#.*/,"")
        gsub(/[[:space:]]+/," ",$0)
        sub(/^ /,""); sub(/ $/,"")
        split($0,a," ")
        if (tolower(a[1]) ~ /^host/) {
          if (length(a) >= 5) {
            printf "line:%s type=%s db=%s user=%s addr=%s method=%s\n", line,a[1],a[2],a[3],a[4],a[length(a)]
          }
        }
      }
    ' "$HBA_FILE"
  )

  ALLOWED_ADDR=$(printf '%s\n' "$HOST_SUMMARY" | awk -F'addr=| method=' 'NF>=3{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//')
  TRUST_LINES=$(printf '%s\n' "$HOST_SUMMARY" | awk '/[[:space:]]method=trust([[:space:]]|$)/{sub(/^line:/,"",$1); sub(/[^0-9].*$/,"",$1); print $1}' | tr '\n' ',' | sed 's/,$//')

  OPEN_ADDR=""
  LOOPBACK_ADDR=""
  OTHER_ADDR=""
  if [ -n "$ALLOWED_ADDR" ]; then
    while IFS= read -r addr; do
      [ -n "$addr" ] || continue
      if is_loopback_addr "$addr"; then
        LOOPBACK_ADDR+="${addr},"
      elif is_open_addr "$addr"; then
        OPEN_ADDR+="${addr},"
      else
        OTHER_ADDR+="${addr},"
      fi
    done < <(printf '%s' "$ALLOWED_ADDR" | tr ',' '\n')
  fi
  OPEN_ADDR=$(printf '%s' "$OPEN_ADDR" | sed 's/,$//')
  LOOPBACK_ADDR=$(printf '%s' "$LOOPBACK_ADDR" | sed 's/,$//')
  OTHER_ADDR=$(printf '%s' "$OTHER_ADDR" | sed 's/,$//')

  LISTEN_STATUS="취약"
  if is_listen_safe "${LISTEN_ADDR:-}"; then
    LISTEN_STATUS="허용"
  fi

  # 점검 결과 판정
  if [ "$LISTEN_STATUS" != "허용" ] || [ -n "$OPEN_ADDR" ] || [ -n "$OTHER_ADDR" ]; then
    STATUS="FAIL"
    # 취약한 설정 부분만 기술하여 사유 작성
    VULN_MSG=""
    if [ "$LISTEN_STATUS" != "허용" ]; then VULN_MSG="listen_addresses가 ${LISTEN_ADDR}로 설정되어 있고 "; fi
    if [ -n "$OPEN_ADDR" ]; then VULN_MSG="${VULN_MSG}pg_hba.conf에 모든 대역 허용(${OPEN_ADDR})이 포함되어 있으며 "; fi
    if [ -n "$OTHER_ADDR" ]; then VULN_MSG="${VULN_MSG}비루프백 원격 CIDR(${OTHER_ADDR})이 허용되어 있어 "; fi
    REASON_LINE="${VULN_MSG}이 항목에 대해 취약합니다."
  else
    STATUS="PASS"
    REASON_LINE="listen_addresses가 ${LISTEN_ADDR}로 설정되어 있고 pg_hba.conf에서 루프백 주소만 허용되어 있어 이 항목에 대해 양호합니다."
  fi
  
  # 양호/취약 관계없이 현재 설정값만 명시
  DETAIL_CONTENT="listen_addresses: ${LISTEN_ADDR:-unknown}\npg_hba.conf 허용 주소: ${ALLOWED_ADDR:-없음}\ntrust 인증 라인: ${TRUST_LINES:-없음}"
fi

# 수동 조치 위험성 및 조치 방법 정의
GUIDE_LINE="이 항목에 대해서 listen_addresses를 루프백으로 강제 변경하거나 pg_hba.conf의 허용 대역을 일괄 제거할 경우, 외부 웹 서버나 애플리케이션의 DB 연결이 즉시 차단되어 서비스 전체 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 listen_addresses 설정을 localhost 또는 신뢰할 수 있는 특정 관리용 IP로 제한하고, pg_hba.conf 파일에서 0.0.0.0/0과 같은 광범위한 대역을 실제 업무에 필요한 특정 IP 대역으로 수정하여 조치해 주시기 바랍니다."

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="SHOW config_file; SHOW hba_file; SHOW listen_addresses; parse pg_hba.conf(listen_addresses/CIDR-ADDRESS)"


escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# raw_evidence 구성
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "guide":"$(escape_json_str "$GUIDE_LINE")",
  "target_file":"$(escape_json_str "${HBA_FILE:-unknown}")"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# scan_history 저장용 JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF