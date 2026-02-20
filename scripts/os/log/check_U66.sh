#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-66
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 정책에 따른 시스템 로깅 설정
# @Description : 내부 정책에 따른 시스템 로깅 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-66"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CONFIG_CANDIDATES=(/etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/rsyslog.d/default.conf)
LOG_FILES=(/var/log/messages /var/log/secure /var/log/maillog /var/log/cron)

TARGET_FILE="/etc/rsyslog.conf /etc/rsyslog.d/*.conf"
CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active rsyslog 2>/dev/null || true); (pgrep -a rsyslogd 2>/dev/null || true); (command -v rsyslogd >/dev/null 2>&1 && rsyslogd -N1 2>&1 || echo "rsyslogd_not_found"); for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/rsyslog.d/default.conf; do [ -f "$f" ] && echo "[FILE] $f" && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$f" | head -n 200; done; for l in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron; do [ -f "$l" ] && echo "[LOGFILE] $l exists (size=$(stat -c%s "$l" 2>/dev/null || echo 0), mtime=$(stat -c%y "$l" 2>/dev/null || echo unknown))" || echo "[LOGFILE] $l missing"; done'

json_escape(){ echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'; }

# 설정 파일 수집
CONF_FILES=()
for f in "${CONFIG_CANDIDATES[@]}"; do [ -f "$f" ] && CONF_FILES+=("$f"); done

# 서비스 동작 상태 판별
RSYSLOG_RUNNING="N"
if command -v systemctl >/dev/null 2>&1; then systemctl is-active --quiet rsyslog 2>/dev/null && RSYSLOG_RUNNING="Y"; fi
pgrep -x rsyslogd >/dev/null 2>&1 && RSYSLOG_RUNNING="Y"

# 설정 유효성 판별
RSYSLOG_CONF_OK="Y"
if command -v rsyslogd >/dev/null 2>&1; then rsyslogd -N1 >/dev/null 2>&1 || RSYSLOG_CONF_OK="N"; fi

REQUIRED=$(
cat <<'EOF'
P1|\*\.info;mail\.none;authpriv\.none;cron\.none[[:space:]]+/var/log/messages|rule=*.info;mail.none;authpriv.none;cron.none->/var/log/messages
P2|auth,authpriv\.\*[[:space:]]+/var/log/secure|rule=auth,authpriv.*->/var/log/secure
P3|mail\.\*[[:space:]]+/var/log/maillog|rule=mail.*->/var/log/maillog
P4|cron\.\*[[:space:]]+/var/log/cron|rule=cron.*->/var/log/cron
P5|\*\.alert[[:space:]]+/dev/console|rule=*.alert->/dev/console
P6|\*\.emerg[[:space:]]+\*|rule=*.emerg->*
EOF
)

FOUND_SUMMARY=""
POLICY_STATE=""
BAD_POLICY=""
if [ "${#CONF_FILES[@]}" -eq 0 ]; then
  STATUS="FAIL"
  BAD_POLICY+="rsyslog_config_not_found\n"
  POLICY_STATE+="rsyslog_config_not_found\n"
else
  while IFS='|' read -r key re desc; do
    [ -z "${key:-}" ] && continue
    hit="N"; found=""
    for cf in "${CONF_FILES[@]}"; do
      m=$(grep -nE "$re" "$cf" 2>/dev/null | head -n 1 || true)
      if [ -n "$m" ]; then hit="Y"; found="$cf:$m"; break; fi
    done
    if [ "$hit" = "Y" ]; then
      FOUND_SUMMARY+="$key found_in=$found\n"
      POLICY_STATE+="$key $desc found_in=$found\n"
    else
      STATUS="FAIL"
      BAD_POLICY+="$key $desc missing\n"
      POLICY_STATE+="$key $desc missing\n"
    fi
  done <<< "$REQUIRED"
fi

# 로그 기록 여부 판별(최근 갱신 또는 비어있지 않음)
NOW_EPOCH=$(date +%s)
ACTIVE_WINDOW_SEC=$((7*24*60*60))
LOG_ACTIVE_COUNT=0
LOG_STATE=""
BAD_LOG=""
for lf in "${LOG_FILES[@]}"; do
  if [ -f "$lf" ]; then
    sz=$(stat -c %s "$lf" 2>/dev/null || echo 0)
    mt=$(stat -c %Y "$lf" 2>/dev/null || echo 0)
    age=$(( mt>0 ? (NOW_EPOCH-mt) : 0 ))
    active="N"
    if [ "$sz" -gt 0 ] || { [ "$mt" -gt 0 ] && [ "$age" -le "$ACTIVE_WINDOW_SEC" ]; }; then
      active="Y"; LOG_ACTIVE_COUNT=$((LOG_ACTIVE_COUNT+1))
    else
      STATUS="FAIL"; BAD_LOG+="logfile_not_active=$lf size=$sz age_sec=$age\n"
    fi
    LOG_STATE+="logfile=$lf exists size=$sz age_sec=$age active=$active\n"
  else
    STATUS="FAIL"; BAD_LOG+="logfile_missing=$lf\n"
    LOG_STATE+="logfile=$lf missing\n"
  fi
done
if [ "$LOG_ACTIVE_COUNT" -lt 1 ]; then
  STATUS="FAIL"
  BAD_LOG+="no_active_log_detected_in_major_logfiles\n"
fi

# 서비스/유효성 실패
BAD_RUNTIME=""
if [ "$RSYSLOG_RUNNING" != "Y" ]; then STATUS="FAIL"; BAD_RUNTIME+="rsyslog_running=N\n"; fi
if [ "$RSYSLOG_CONF_OK" != "Y" ]; then STATUS="FAIL"; BAD_RUNTIME+="rsyslog_conf_ok=N\n"; fi

# 현재 설정값
DETAIL_CONTENT="$(cat <<EOF
rsyslog_running=$RSYSLOG_RUNNING
rsyslog_conf_ok=$RSYSLOG_CONF_OK
$POLICY_STATE$(printf "%b" "$LOG_STATE" | sed 's/[[:space:]]*$//')
EOF
)"

# 양호/취약 사유 문장
if [ "$STATUS" = "PASS" ]; then
  REASON_SETTINGS="rsyslog_running=Y, rsyslog_conf_ok=Y, policies=P1~P6 present, active_logs>=1"
  REASON_LINE="${REASON_SETTINGS} 로 설정되어 있어 이 항목에 대해 양호합니다."
else
  REASON_SETTINGS="$(printf "%b%b%b" "$BAD_RUNTIME" "$BAD_POLICY" "$BAD_LOG" | sed 's/[[:space:]]*$//' | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
  [ -z "$REASON_SETTINGS" ] && REASON_SETTINGS="logging_policy_or_runtime_issue"
  REASON_LINE="${REASON_SETTINGS} 로 설정되어 있어 이 항목에 대해 취약합니다."
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE="이 항목은 로그량 증가로 인한 저장소 부족, 성능 저하, 로그 범위/보존기간/회전 정책 불일치 위험이 있어 수동 조치가 필요합니다.
관리자가 직접 확인 후 rsyslog 설정 파일(/etc/rsyslog.conf 또는 /etc/rsyslog.d/*.conf)에 내부 정책에 맞는 규칙을 반영하고, systemctl restart rsyslog 로 적용한 뒤 /var/log/messages·secure·maillog·cron 갱신 및 로그 보존/로테이션 상태를 점검하여 조치해 주시기 바랍니다."

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
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
