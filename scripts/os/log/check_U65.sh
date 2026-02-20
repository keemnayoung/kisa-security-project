#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-65
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP/Chrony 서비스 활성 및 동기화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-65"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE_NTP="/etc/ntp.conf"
TARGET_FILE_CHRONY1="/etc/chrony.conf"
TARGET_FILE_CHRONY2="/etc/chrony/chrony.conf"
TARGET_FILE="${TARGET_FILE_NTP} ${TARGET_FILE_CHRONY1} ${TARGET_FILE_CHRONY2}"
TARGET_FILE_NL="${TARGET_FILE_NTP}\n${TARGET_FILE_CHRONY1}\n${TARGET_FILE_CHRONY2}"

# 점검 명령
CHECK_COMMAND='
systemctl list-units --type=service | grep -E "ntp|chrony" || echo "no_ntp_or_chrony_unit";
command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null | head -n 30 || echo "ntpq_cmd_not_found";
command -v chronyc >/dev/null 2>&1 && chronyc sources 2>/dev/null | head -n 40 || echo "chronyc_cmd_not_found";
[ -f /etc/ntp.conf ] && grep -nE "^[[:space:]]*(server|pool)[[:space:]]+" /etc/ntp.conf | head -n 20 || echo "ntp_conf_no_server_pool_or_not_found";
for f in /etc/chrony.conf /etc/chrony/chrony.conf; do
  [ -f "$f" ] && (echo "### $f"; grep -nE "^[[:space:]]*(server|pool)[[:space:]]+" "$f" | head -n 20) || true;
done
'

json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

conf_path() { for f in "$@"; do [ -f "$f" ] && { echo "$f"; return 0; }; done; echo ""; return 1; }
has_server_pool() { [ -n "$1" ] && grep -qE '^[[:space:]]*(server|pool)[[:space:]]+' "$1" 2>/dev/null; }

# NTP 상태 수집
NTP_UNIT_STATE="inactive"
NTP_CONF="$(conf_path "$TARGET_FILE_NTP")"
NTP_CONF_OK="no"
NTP_SYNC="no"
NTP_CONF_LINES=""

if systemctl list-units --type=service 2>/dev/null | grep -qE 'ntp|ntpd'; then
  NTP_UNIT_STATE="active"
fi

if [ -n "$NTP_CONF" ] && has_server_pool "$NTP_CONF"; then
  NTP_CONF_OK="yes"
  NTP_CONF_LINES="$(grep -nE '^[[:space:]]*(server|pool)[[:space:]]+' "$NTP_CONF" 2>/dev/null | head -n 10)"
fi

if command -v ntpq >/dev/null 2>&1; then
  ntpq -pn 2>/dev/null | grep -Eq '^[[:space:]]*[\*\+]' && NTP_SYNC="yes"
fi

# Chrony 상태 수집
CHRONY_UNIT_STATE="inactive"
CHRONY_CONF="$(conf_path "$TARGET_FILE_CHRONY1" "$TARGET_FILE_CHRONY2")"
CHRONY_CONF_OK="no"
CHRONY_SYNC="no"
CHRONY_CONF_LINES=""

if systemctl list-units --type=service 2>/dev/null | grep -qE 'chrony|chronyd'; then
  CHRONY_UNIT_STATE="active"
fi

if [ -n "$CHRONY_CONF" ] && has_server_pool "$CHRONY_CONF"; then
  CHRONY_CONF_OK="yes"
  CHRONY_CONF_LINES="$(grep -nE '^[[:space:]]*(server|pool)[[:space:]]+' "$CHRONY_CONF" 2>/dev/null | head -n 10)"
fi

if command -v chronyc >/dev/null 2>&1; then
  chronyc sources 2>/dev/null | grep -Eq '^[[:space:]]*\^(\*|\+)' && CHRONY_SYNC="yes"
fi

# DETAIL_CONTENT 구성
DETAIL_CONTENT="NTP
service(list-units): ${NTP_UNIT_STATE}
conf: ${NTP_CONF:-not_found} (server/pool=${NTP_CONF_OK})
sync(ntpq -pn *|+): ${NTP_SYNC}"
[ -n "$NTP_CONF_LINES" ] && DETAIL_CONTENT="${DETAIL_CONTENT}
conf_lines:
${NTP_CONF_LINES}"

DETAIL_CONTENT="${DETAIL_CONTENT}

Chrony
service(list-units): ${CHRONY_UNIT_STATE}
conf: ${CHRONY_CONF:-not_found} (server/pool=${CHRONY_CONF_OK})
sync(chronyc sources ^*|^+): ${CHRONY_SYNC}"
[ -n "$CHRONY_CONF_LINES" ] && DETAIL_CONTENT="${DETAIL_CONTENT}
conf_lines:
${CHRONY_CONF_LINES}"

# 최종 판정
# 양호 조건: (NTP active + conf ok + sync ok) 또는 (Chrony active + conf ok + sync ok)
NTP_OK=0
CHRONY_OK=0
[ "$NTP_UNIT_STATE" = "active" ] && [ "$NTP_CONF_OK" = "yes" ] && [ "$NTP_SYNC" = "yes" ] && NTP_OK=1
[ "$CHRONY_UNIT_STATE" = "active" ] && [ "$CHRONY_CONF_OK" = "yes" ] && [ "$CHRONY_SYNC" = "yes" ] && CHRONY_OK=1

# 이유 문장 생성
REASON_SENTENCE=""

if [ "$NTP_OK" -eq 1 ] || [ "$CHRONY_OK" -eq 1 ]; then
  STATUS="PASS"
  if [ "$CHRONY_OK" -eq 1 ]; then
    REASON_SENTENCE="chrony_service=${CHRONY_UNIT_STATE}, chrony_conf=${CHRONY_CONF:-not_found} server/pool=${CHRONY_CONF_OK}, chrony_sync=${CHRONY_SYNC} 로 설정되어 있어 이 항목에 대해 양호합니다."
  else
    REASON_SENTENCE="ntp_service=${NTP_UNIT_STATE}, ntp_conf=${NTP_CONF:-not_found} server/pool=${NTP_CONF_OK}, ntp_sync=${NTP_SYNC}로 이 항목에 대해 양호합니다."
  fi
else
  STATUS="FAIL"
  FAIL_BITS=""
  # 취약 사유
  [ "$NTP_UNIT_STATE" != "active" ] && FAIL_BITS="${FAIL_BITS}ntp_service=${NTP_UNIT_STATE}\n"
  [ "$NTP_CONF_OK" != "yes" ] && FAIL_BITS="${FAIL_BITS}ntp_conf=${NTP_CONF:-not_found} server/pool=${NTP_CONF_OK}\n"
  [ "$NTP_SYNC" != "yes" ] && FAIL_BITS="${FAIL_BITS}ntp_sync=${NTP_SYNC}\n"
  [ "$CHRONY_UNIT_STATE" != "active" ] && FAIL_BITS="${FAIL_BITS}chrony_service=${CHRONY_UNIT_STATE}\n"
  [ "$CHRONY_CONF_OK" != "yes" ] && FAIL_BITS="${FAIL_BITS}chrony_conf=${CHRONY_CONF:-not_found} server/pool=${CHRONY_CONF_OK}\n"
  [ "$CHRONY_SYNC" != "yes" ] && FAIL_BITS="${FAIL_BITS}chrony_sync=${CHRONY_SYNC}\n"
  FAIL_BITS="$(echo -e "$FAIL_BITS" | sed '/^[[:space:]]*$/d' | paste -sd ', ' -)"
  REASON_SENTENCE="${FAIL_BITS} 로 설정되어 있어 이 항목에 대해 취약합니다."
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE="시간 동기화 설정을 자동으로 변경하면 시간 의존 서비스(인증/로그/배치/모니터링 등)에 영향이 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 허용된 NTP 서버 목록과 동기화 정책을 확인 후 NTP 또는 Chrony 설정 파일에 server/pool 값을 반영해 주시기 바랍니다.
설정 적용 후 systemctl restart ntp 또는 systemctl restart chrony를 수행하고 ntpq -pn 또는 chronyc sources로 동기화 상태를 확인해 주시기 바랍니다.
동기화 주기 조정이 필요하면 환경 정책에 맞게 minpoll/maxpoll 등 관련 값을 검토해 주시기 바랍니다."

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_SENTENCE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE_NL"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

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
