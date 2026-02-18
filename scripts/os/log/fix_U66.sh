#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-16
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-66
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 정책에 따른 시스템 로깅 설정
# @Description : 로그 기록 정책을 보안 정책에 따라 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# ===== U-66 내부 정책 로그 설정 =====
# *.info;mail.none;authpriv.none;cron.none    /var/log/messages
# auth,authpriv.*                             /var/log/secure
# mail.*                                     /var/log/maillog
# cron.*                                     /var/log/cron
# *.alert                                    /dev/console
# *.emerg                                    *
# ===== END U-66 =====


# # 기본 변수
# ID="U-66"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# RSYSLOG_CONF="/etc/rsyslog.conf"
# TARGET_FILE="$RSYSLOG_CONF"

# CHECK_COMMAND="( [ -f /etc/rsyslog.conf ] && sed -n '/U-66 내부 정책 로그 설정/,/END U-66/p' /etc/rsyslog.conf ); systemctl is-active rsyslog 2>/dev/null; for f in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron; do [ -e \"\$f\" ] && ls -l \"\$f\" || echo \"\$f\"; done 2>/dev/null"

# MISSING_LOGS=()
# FAIL_FLAG=0
# MODIFIED=0
# DETAIL_CONTENT=""

# # 조치 프로세스
# if [ -f "$RSYSLOG_CONF" ]; then
#   # 기존 정책 중복 방지
#   sed -i '/U-66 내부 정책 로그 설정/,/END U-66/d' "$RSYSLOG_CONF" 2>/dev/null

#   # 내부 정책 로그 설정 적용
#   cat <<'EOF' >> "$RSYSLOG_CONF"

# # U-66 내부 정책 로그 설정
# *.info;mail.none;authpriv.none;cron.none    /var/log/messages
# auth,authpriv.*                             /var/log/secure
# mail.*                                      /var/log/maillog
# cron.*                                      /var/log/cron
# *.alert                                     /dev/console
# *.emerg                                     *
# # END U-66
# EOF

#   MODIFIED=1

#   # 서비스 재시작
#   systemctl restart rsyslog >/dev/null 2>&1

#   # 조치 후 상태 수집(조치 후 상태만 detail에 표시)
#   RSYSLOG_ACTIVE=$(systemctl is-active rsyslog 2>/dev/null)

#   DETAIL_CONTENT=""

#   POLICY_BLOCK=$(sed -n '/U-66 내부 정책 로그 설정/,/END U-66/p' "$RSYSLOG_CONF" 2>/dev/null)
#   [ -n "$POLICY_BLOCK" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${POLICY_BLOCK}
# "

#   [ -n "$RSYSLOG_ACTIVE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}rsyslog_state=$RSYSLOG_ACTIVE
# "

#   MISSING_LOGS=()
#   for LOG in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron; do
#     if [ -e "$LOG" ]; then
#       LOG_STAT=$(ls -l "$LOG" 2>/dev/null)
#       [ -n "$LOG_STAT" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${LOG_STAT}
# "
#     else
#       MISSING_LOGS+=("$LOG")
#     fi
#   done

#   if [ "$RSYSLOG_ACTIVE" = "active" ] && [ ${#MISSING_LOGS[@]} -eq 0 ]; then
#     IS_SUCCESS=1
#     REASON_LINE="rsyslog 정책 설정이 적용되고 rsyslog 서비스가 정상 동작하며 필수 로그 파일이 존재하여 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   else
#     IS_SUCCESS=0
#     REASON_LINE="조치를 수행했으나 rsyslog 서비스 상태 또는 필수 로그 파일 존재 여부가 기준을 충족하지 못해 조치가 완료되지 않았습니다."
#     if [ ${#MISSING_LOGS[@]} -gt 0 ]; then
#       DETAIL_CONTENT="${DETAIL_CONTENT}$(printf "%s\n" "${MISSING_LOGS[@]}")"
#     fi
#   fi
# else
#   IS_SUCCESS=0
#   REASON_LINE="조치 대상 파일(/etc/rsyslog.conf)이 존재하지 않아 조치가 완료되지 않았습니다."
#   DETAIL_CONTENT=""
# fi

# # raw_evidence 구성
# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# # JSON escape 처리 (따옴표, 줄바꿈)
# RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
#   | sed 's/"/\\"/g' \
#   | sed ':a;N;$!ba;s/\n/\\n/g')

# # DB 저장용 JSON 출력
# echo ""
# cat << EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF