#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 윤영아
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
# @Description : 데이터베이스의 주요 파일들에 대해 관리자를 제외한 일반 사용자의 파일 수정 권한을 제거하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-14"
STATUS="PASS"
EVIDENCE_LIST=""

# PostgreSQL 시스템 설정에서 주요 디렉터리 및 파일 경로 추출
DATA_DIR=$(run_psql "SHOW data_directory;" | xargs)
[ -z "$DATA_DIR" ] && DATA_DIR="$PGDATA"
HBA_FILE=$(run_psql "SHOW hba_file;" | xargs)
CONF_FILE=$(run_psql "SHOW config_file;" | xargs)
IDENT_FILE="$DATA_DIR/pg_ident.conf"
LOG_DIR=$(run_psql "SHOW log_directory;" | xargs)

# 로그 디렉터리가 상대 경로일 경우 절대 경로로 변환
if [ -n "$LOG_DIR" ] && [ "${LOG_DIR#/}" = "$LOG_DIR" ]; then
  LOG_DIR="$DATA_DIR/$LOG_DIR"
fi

POSTGRES_HOME=$(getent passwd "$PG_SUPERUSER" | cut -d: -f6)
HISTORY_FILE="${POSTGRES_HOME}/.psql_history"

# 이스케이프 함수
escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 개별 파일/디렉터리의 권한 및 소유자를 점검하는 함수
check_item() {
  local file="$1"
  local max_mode="$2"
  local type="$3"

  if [ ! -e "$file" ]; then
    return
  fi

  local mode owner
  mode=$(stat -c '%a' "$file" 2>/dev/null)
  owner=$(stat -c '%U' "$file" 2>/dev/null)

  if [ -z "$mode" ] || [ -z "$owner" ]; then
    STATUS="FAIL"
    EVIDENCE_LIST="${EVIDENCE_LIST}${file}(조회실패)\n"
    return
  fi

  if [ "$owner" != "$PG_SUPERUSER" ] && [ "$owner" != "postgres" ]; then
    STATUS="FAIL"
    EVIDENCE_LIST="${EVIDENCE_LIST}${file}(소유자:${owner})\n"
  fi

  if [ "$mode" -gt "$max_mode" ] 2>/dev/null; then
    STATUS="FAIL"
    EVIDENCE_LIST="${EVIDENCE_LIST}${file}(권한:${mode})\n"
  fi

  if [ "$type" = "logdir" ] && [ -d "$file" ]; then
    while IFS= read -r lf; do
      lmode=$(stat -c '%a' "$lf" 2>/dev/null)
      if [ -n "$lmode" ] && [ "$lmode" -gt 640 ] 2>/dev/null; then
        STATUS="FAIL"
        EVIDENCE_LIST="${EVIDENCE_LIST}${lf}(로그권한:${lmode})\n"
      fi
    done < <(find "$file" -maxdepth 1 -type f 2>/dev/null)
  fi
}

# 정의된 기준에 따라 각 항목 점검 수행
check_item "$DATA_DIR" 750 "dir"
check_item "$CONF_FILE" 640 "file"
check_item "$HBA_FILE" 640 "file"
check_item "$IDENT_FILE" 640 "file"
check_item "$HISTORY_FILE" 600 "file"
check_item "$LOG_DIR" 750 "logdir"

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 파일 접근 불가로 인한 DB 가동 중단 위험과 수동 조치 가이드
GUIDE_LINE="이 항목에 대해서 주요 파일의 권한을 자동으로 변경할 경우, 데이터베이스 엔진이 설정 파일을 읽지 못하거나 로그를 기록하지 못해 DB 서비스가 즉시 중단될 수 있는 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 chown 명령어로 소유자를 postgres(또는 실행 계정)로 변경하고, chmod 명령어를 사용하여 디렉터리는 750, 설정 파일은 640, 히스토리 파일은 600 이하로 조치해 주시기 바랍니다."

# 점검 결과 및 상세 내용 구성 분기점
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="주요 파일 및 디렉터리의 소유자와 권한 설정이 보안 기준을 모두 준수하고 있어 이 항목에 대해 양호합니다."
else
  # 취약한 항목만 추출하여 사유 구성 (줄바꿈 없이 한 문장으로 처리)
  VULN_ITEMS=$(echo -e "$EVIDENCE_LIST" | sed '/^$/d' | tr '\n' ',' | sed 's/,$//')
  REASON_LINE="${VULN_ITEMS} 항목의 권한 또는 소유자가 적절하지 않게 설정되어 있어 이 항목에 대해 취약합니다."
fi

# 양호/취약 관계없이 현재 점검된 모든 파일의 설정 현황 명시
DETAIL_CONTENT="[현재 주요 파일 설정 현황]\n- 데이터 디렉터리: ${DATA_DIR} ($(stat -c '%a %U' $DATA_DIR 2>/dev/null))\n- 설정 파일: ${CONF_FILE} ($(stat -c '%a %U' $CONF_FILE 2>/dev/null))\n- 인증 설정: ${HBA_FILE} ($(stat -c '%a %U' $HBA_FILE 2>/dev/null))\n- Ident 설정: ${IDENT_FILE} ($(stat -c '%a %U' $IDENT_FILE 2>/dev/null))\n- 히스토리: ${HISTORY_FILE} ($(stat -c '%a %U' $HISTORY_FILE 2>/dev/null))\n- 로그 디렉터리: ${LOG_DIR} ($(stat -c '%a %U' $LOG_DIR 2>/dev/null))"

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="stat 기반 주요 파일/디렉터리 권한·소유자 점검(data_directory/config_file/hba_file/log_directory/.psql_history)"
TARGET_FILE="${DATA_DIR},${CONF_FILE},${HBA_FILE},${IDENT_FILE},${HISTORY_FILE},${LOG_DIR}"

# raw_evidence 구성
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$(escape_json_str "$CHECK_COMMAND")",
  "detail": "$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "guide": "$(escape_json_str "$GUIDE_LINE")",
  "target_file": "$(escape_json_str "$TARGET_FILE")"
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