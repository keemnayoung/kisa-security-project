#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-47
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 스팸 메일 릴레이 제한
# @Description : 메일 서버의 릴레이 기능을 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-47 스팸 메일 릴레이 제한

# # 1. 항목 정보 정의
# ID="U-47"
# CATEGORY="서비스 관리"
# TITLE="스팸 메일 릴레이 제한"
# IMPORTANCE="상"

# # 2. 보완 로직
# STATUS="PASS"
# SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# ACTION_LOG=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# CHECK_COMMAND='( command -v sendmail >/dev/null 2>&1 && sendmail -d0 < /dev/null 2>/dev/null | head -n 7 || true ); ( [ -f /etc/mail/sendmail.cf ] && grep -inE "promiscuous_relay|Relaying denied" /etc/mail/sendmail.cf 2>/dev/null || true ); ( [ -f /etc/mail/sendmail.mc ] && grep -inE "promiscuous_relay" /etc/mail/sendmail.mc 2>/dev/null || true ); ( [ -f /etc/mail/access ] && tail -n 30 /etc/mail/access 2>/dev/null || true ); ( command -v postconf >/dev/null 2>&1 && postconf -n 2>/dev/null | egrep "^(mynetworks|smtpd_(relay|recipient)_restrictions)\\s*=" || true ); ( [ -f /etc/postfix/main.cf ] && egrep -n "^(mynetworks|smtpd_(relay|recipient)_restrictions)\\s*=" /etc/postfix/main.cf 2>/dev/null || true ); ( [ -f /etc/exim/exim.conf ] && grep -in "relay_from_hosts" /etc/exim/exim.conf 2>/dev/null || true ); ( [ -f /etc/exim4/exim4.conf ] && grep -in "relay_from_hosts" /etc/exim4/exim4.conf 2>/dev/null || true ); ( [ -f /etc/exim4/update-exim4.conf.conf ] && grep -in "relay_from_hosts" /etc/exim4/update-exim4.conf.conf 2>/dev/null || true )'

# # -----------------------------
# # 공용 함수
# # -----------------------------
# add_target_file() {
#   local f="$1"
#   [ -z "$f" ] && return 0
#   if [ -z "$TARGET_FILE" ]; then
#     TARGET_FILE="$f"
#   else
#     TARGET_FILE="${TARGET_FILE}, $f"
#   fi
# }

# append_log() {
#   local msg="$1"
#   [ -z "$msg" ] && return 0
#   if [ -z "$ACTION_LOG" ]; then
#     ACTION_LOG="$msg"
#   else
#     ACTION_LOG="${ACTION_LOG} $msg"
#   fi
# }

# append_detail_line() {
#   local msg="$1"
#   [ -z "$msg" ] && return 0
#   if [ -z "$DETAIL_CONTENT" ]; then
#     DETAIL_CONTENT="$msg"
#   else
#     DETAIL_CONTENT="${DETAIL_CONTENT}\n$msg"
#   fi
# }

# contains_open_all_network() {
#   # 0.0.0.0/0, ::/0, 0/0 등 전체 허용 패턴
#   echo "$1" | grep -qE '(^|[[:space:],])0\.0\.0\.0/0($|[[:space:],])|(^|[[:space:],])::/0($|[[:space:],])|(^|[[:space:],])0/0($|[[:space:],])'
# }

# ensure_line_present() {
#   # 파일에 특정 라인이 없으면 추가
#   local file="$1"
#   local exact="$2"
#   grep -qxF "$exact" "$file" 2>/dev/null || echo "$exact" >> "$file"
# }

# json_escape() {
#   # " 및 줄바꿈 escape
#   echo "$1" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
# }

# # -----------------------------
# # 상태 추적 변수
# # -----------------------------
# FOUND_ANY=0
# VULN_AFTER=0

# # -----------------------------
# # [Sendmail] 조치
# #  - 위험 시그널: promiscuous_relay 제거(가이드 핵심)
# #  - access는 localhost만 RELAY 예시(운영 정책에 맞게 조정 가능)
# # -----------------------------
# if command -v sendmail >/dev/null 2>&1; then
#   FOUND_ANY=1

#   SENDMAIL_CF="/etc/mail/sendmail.cf"
#   SENDMAIL_MC="/etc/mail/sendmail.mc"
#   ACCESS_FILE="/etc/mail/access"
#   ACCESS_DB="/etc/mail/access.db"

#   add_target_file "$SENDMAIL_CF"
#   add_target_file "$SENDMAIL_MC"
#   add_target_file "$ACCESS_FILE"
#   add_target_file "$ACCESS_DB"

#   # sendmail.mc에서 promiscuous_relay 제거(있을 때만)
#   if [ -f "$SENDMAIL_MC" ] && grep -qE 'FEATURE\(\s*`promiscuous_relay`\s*\)' "$SENDMAIL_MC" 2>/dev/null; then
#     sed -i '/FEATURE(\s*`promiscuous_relay`\s*)/d' "$SENDMAIL_MC" 2>/dev/null
#     append_log "Sendmail(sendmail.mc)에서 promiscuous_relay 설정을 제거했습니다."
#     # mc가 있으면 일반적으로 cf는 m4로 재생성하는 환경이 많아, 가능한 경우에만 수행
#     if command -v m4 >/dev/null 2>&1 && [ -f "/etc/mail/sendmail.mc" ]; then
#       # 일부 환경에서 Makefile 사용
#       if [ -f "/etc/mail/Makefile" ] && command -v make >/dev/null 2>&1; then
#         (cd /etc/mail && make >/dev/null 2>&1) && append_log "Sendmail 설정을 재생성(make)했습니다."
#       elif [ -f "/etc/mail/sendmail.mc" ] && [ -f "/etc/mail/sendmail.cf" ] && command -v m4 >/dev/null 2>&1; then
#         # 환경별 m4 경로/매크로가 달라 실패할 수 있으므로 조용히 시도만
#         m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf 2>/dev/null && append_log "Sendmail 설정을 재생성(m4)했습니다."
#       fi
#     fi
#   fi

#   # sendmail.cf에 promiscuous_relay 문자열이 있으면 제거(직접 편집 환경 대비)
#   if [ -f "$SENDMAIL_CF" ] && grep -q "promiscuous_relay" "$SENDMAIL_CF" 2>/dev/null; then
#     sed -i '/promiscuous_relay/d' "$SENDMAIL_CF" 2>/dev/null
#     append_log "Sendmail(sendmail.cf)에서 promiscuous_relay 관련 라인을 제거했습니다."
#   fi

#   # access 파일: localhost/127.0.0.1만 RELAY (필요 최소)
#   if [ ! -f "$ACCESS_FILE" ]; then
#     touch "$ACCESS_FILE" 2>/dev/null
#   fi
#   if [ -f "$ACCESS_FILE" ]; then
#     ensure_line_present "$ACCESS_FILE" "localhost RELAY"
#     ensure_line_present "$ACCESS_FILE" "127.0.0.1 RELAY"
#     # access.db 생성(가능한 경우)
#     if command -v makemap >/dev/null 2>&1; then
#       makemap hash "$ACCESS_DB" < "$ACCESS_FILE" 2>/dev/null && append_log "Sendmail access.db를 갱신했습니다."
#     fi
#   fi

#   # 서비스 재시작(설치/활성 여부에 따라 실패 가능하므로 조용히)
#   systemctl restart sendmail 2>/dev/null && append_log "Sendmail을 재시작했습니다."
# fi

# # -----------------------------
# # [Postfix] 조치
# #  - mynetworks 전체허용(0.0.0.0/0 등) 제거/교정
# #  - smtpd_recipient_restrictions 또는 smtpd_relay_restrictions에 reject_unauth_destination 보강(필수)
# # -----------------------------
# if command -v postfix >/dev/null 2>&1 || command -v postconf >/dev/null 2>&1; then
#   FOUND_ANY=1

#   MAIN_CF="/etc/postfix/main.cf"
#   add_target_file "$MAIN_CF"

#   # main.cf 없으면 생성하지 않고 로그만 남김(환경별 관리 방식 고려)
#   if [ -f "$MAIN_CF" ]; then
#     # mynetworks 전체허용이면 교정
#     if grep -nE '^[[:space:]]*mynetworks[[:space:]]*=' "$MAIN_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | grep -qE '0\.0\.0\.0/0|::/0|0/0'; then
#       # 기존 라인 주석 처리 후 안전값 추가
#       sed -i 's/^\([[:space:]]*mynetworks[[:space:]]*=.*\(0\.0\.0\.0\/0\|::\/0\|0\/0\).*\)$/#\1/g' "$MAIN_CF" 2>/dev/null
#       echo "mynetworks = 127.0.0.0/8" >> "$MAIN_CF"
#       append_log "Postfix main.cf에서 전체 허용 mynetworks 설정을 주석 처리하고 127.0.0.0/8로 설정했습니다."
#     elif ! grep -qE '^[[:space:]]*mynetworks[[:space:]]*=' "$MAIN_CF" 2>/dev/null; then
#       echo "mynetworks = 127.0.0.0/8" >> "$MAIN_CF"
#       append_log "Postfix main.cf에 mynetworks = 127.0.0.0/8을 추가했습니다."
#     fi

#     # recipient_restrictions 보강(없으면 생성, 있으면 reject_unauth_destination 포함 보장)
#     if ! grep -qE '^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=' "$MAIN_CF" 2>/dev/null; then
#       echo "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination" >> "$MAIN_CF"
#       append_log "Postfix main.cf에 smtpd_recipient_restrictions를 추가했습니다."
#     else
#       # 라인(첫 번째 유효 라인)에서 reject_unauth_destination 없으면 끝에 추가
#       LINE_NO="$(grep -nE '^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=' "$MAIN_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1 | cut -d: -f1)"
#       if [ -n "$LINE_NO" ]; then
#         CUR_LINE="$(sed -n "${LINE_NO}p" "$MAIN_CF" 2>/dev/null)"
#         echo "$CUR_LINE" | grep -q "reject_unauth_destination"
#         if [ $? -ne 0 ]; then
#           sed -i "${LINE_NO}s/$/, reject_unauth_destination/" "$MAIN_CF" 2>/dev/null
#           append_log "Postfix main.cf의 smtpd_recipient_restrictions에 reject_unauth_destination를 보강했습니다."
#         fi
#       fi
#     fi

#     # (보조) relay_restrictions가 있을 때도 reject_unauth_destination 포함 보장(운영 환경 대비)
#     if grep -qE '^[[:space:]]*smtpd_relay_restrictions[[:space:]]*=' "$MAIN_CF" 2>/dev/null; then
#       LINE_NO2="$(grep -nE '^[[:space:]]*smtpd_relay_restrictions[[:space:]]*=' "$MAIN_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1 | cut -d: -f1)"
#       if [ -n "$LINE_NO2" ]; then
#         CUR2="$(sed -n "${LINE_NO2}p" "$MAIN_CF" 2>/dev/null)"
#         echo "$CUR2" | grep -q "reject_unauth_destination"
#         if [ $? -ne 0 ]; then
#           sed -i "${LINE_NO2}s/$/, reject_unauth_destination/" "$MAIN_CF" 2>/dev/null
#           append_log "Postfix main.cf의 smtpd_relay_restrictions에 reject_unauth_destination를 보강했습니다."
#         fi
#       fi
#     fi

#     postfix reload 2>/dev/null && append_log "Postfix를 reload했습니다."
#   else
#     append_log "Postfix가 설치되어 있으나 /etc/postfix/main.cf가 없어 자동 조치를 수행하지 못했습니다."
#   fi
# fi

# # -----------------------------
# # [Exim] 조치
# #  - relay_from_hosts 전체허용(*, 0.0.0.0/0 등) -> 127.0.0.1로 제한
# #  - 없으면 추가
# # -----------------------------
# if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
#   FOUND_ANY=1
#   CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf" "/etc/exim4/update-exim4.conf.conf")
#   EXIM_MODIFIED=0
#   FOUND_CONF="0"

#   for conf in "${CONF_FILES[@]}"; do
#     if [ -f "$conf" ]; then
#       FOUND_CONF="1"
#       add_target_file "$conf"

#       # 전체허용이면 치환
#       if grep -v '^[[:space:]]*#' "$conf" 2>/dev/null | grep -qE 'relay_from_hosts[[:space:]]*=[[:space:]]*(\*|0\.0\.0\.0/0|::/0|0/0)'; then
#         sed -i 's/^\([[:space:]]*relay_from_hosts[[:space:]]*=[[:space:]]*\).*/\1 127.0.0.1/' "$conf" 2>/dev/null
#         append_log "Exim 설정에서 relay_from_hosts 전체 허용을 127.0.0.1로 제한했습니다."
#         EXIM_MODIFIED=1
#       fi

#       # 설정이 없으면 추가
#       if ! grep -qE '^[[:space:]]*relay_from_hosts[[:space:]]*=' "$conf" 2>/dev/null; then
#         echo "relay_from_hosts = 127.0.0.1" >> "$conf"
#         append_log "Exim 설정에 relay_from_hosts = 127.0.0.1을 추가했습니다."
#         EXIM_MODIFIED=1
#       fi

#       break
#     fi
#   done

#   if [ "$FOUND_CONF" = "0" ]; then
#     append_log "Exim이 설치되어 있으나 설정 파일을 찾지 못해 자동 조치를 수행하지 못했습니다."
#     VULN_AFTER=1
#   else
#     if [ $EXIM_MODIFIED -eq 1 ]; then
#       systemctl restart exim4 2>/dev/null || systemctl restart exim 2>/dev/null
#       append_log "Exim을 재시작했습니다."
#     fi
#   fi
# fi

# # -----------------------------
# # [검증] (필수 보강: Sendmail/Postfix/Exim 모두 확인)
# #  - 조치 이후(after) 상태만 확인
# # -----------------------------
# # Sendmail after-check
# if command -v sendmail >/dev/null 2>&1; then
#   if [ -f "/etc/mail/sendmail.cf" ] && grep -q "promiscuous_relay" /etc/mail/sendmail.cf 2>/dev/null; then
#     VULN_AFTER=1
#   fi
#   if [ -f "/etc/mail/sendmail.mc" ] && grep -qE 'FEATURE\(\s*`promiscuous_relay`\s*\)' /etc/mail/sendmail.mc 2>/dev/null; then
#     VULN_AFTER=1
#   fi
# fi

# # Postfix after-check (유효 설정 우선: postconf -n)
# if command -v postconf >/dev/null 2>&1; then
#   PF_EFF="$(postconf -n 2>/dev/null)"
#   PF_MY="$(echo "$PF_EFF" | grep -E '^mynetworks[[:space:]]*=' | head -n1)"
#   PF_RR="$(echo "$PF_EFF" | grep -E '^smtpd_relay_restrictions[[:space:]]*=' | head -n1)"
#   PF_RC="$(echo "$PF_EFF" | grep -E '^smtpd_recipient_restrictions[[:space:]]*=' | head -n1)"

#   if [ -n "$PF_MY" ] && contains_open_all_network "$PF_MY"; then
#     VULN_AFTER=1
#   fi

#   echo "$PF_RR $PF_RC" | grep -q "reject_unauth_destination" || {
#     # postconf에 없으면 취약(필수 보호 신호 누락)
#     # 단, postfix가 실제로 돌지 않는 환경에서도 postconf만 존재할 수 있어 FOUND_ANY 기준으로만 판정
#     VULN_AFTER=1
#   }
# else
#   # postconf 없을 때는 main.cf 기준(보조)
#   if [ -f "/etc/postfix/main.cf" ]; then
#     grep -nE '^[[:space:]]*mynetworks[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | grep -v '^[[:space:]]*#' | grep -qE '0\.0\.0\.0/0|::/0|0/0' && VULN_AFTER=1
#     (grep -nE '^[[:space:]]*smtpd_(relay|recipient)_restrictions[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 5) | grep -q "reject_unauth_destination" || VULN_AFTER=1
#   fi
# fi

# # Exim after-check
# for exconf in /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/update-exim4.conf.conf; do
#   if [ -f "$exconf" ]; then
#     grep -v '^[[:space:]]*#' "$exconf" 2>/dev/null | grep -qE 'relay_from_hosts[[:space:]]*=[[:space:]]*(\*|0\.0\.0\.0/0|::/0|0/0)' && VULN_AFTER=1
#     break
#   fi
# done

# # -----------------------------
# # [조치 이후(after) 증적 수집]  (before 설정은 포함하지 않음)
# # -----------------------------
# # Sendmail after evidence
# if command -v sendmail >/dev/null 2>&1; then
#   [ -f /etc/mail/sendmail.mc ] && append_detail_line "[AFTER][sendmail.mc]\n$(grep -inE 'promiscuous_relay' /etc/mail/sendmail.mc 2>/dev/null | tail -n 10)"
#   [ -f /etc/mail/sendmail.cf ] && append_detail_line "[AFTER][sendmail.cf]\n$(grep -inE 'promiscuous_relay|Relaying denied' /etc/mail/sendmail.cf 2>/dev/null | tail -n 20)"
#   [ -f /etc/mail/access ] && append_detail_line "[AFTER][access]\n$(tail -n 30 /etc/mail/access 2>/dev/null)"
#   [ -f /etc/mail/access.db ] && append_detail_line "[AFTER][access.db]\n$(ls -l /etc/mail/access.db 2>/dev/null)"
# fi

# # Postfix after evidence
# if command -v postconf >/dev/null 2>&1; then
#   PF_EFF2="$(postconf -n 2>/dev/null | egrep '^(mynetworks|smtpd_(relay|recipient)_restrictions)[[:space:]]*=' || true)"
#   [ -n "$PF_EFF2" ] && append_detail_line "[AFTER][postfix effective(postconf -n)]\n$PF_EFF2"
# else
#   [ -f /etc/postfix/main.cf ] && append_detail_line "[AFTER][postfix main.cf]\n$(egrep -n '^(mynetworks|smtpd_(relay|recipient)_restrictions)[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n 30)"
# fi

# # Exim after evidence
# for exconf in /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/update-exim4.conf.conf; do
#   if [ -f "$exconf" ]; then
#     append_detail_line "[AFTER][exim config: $exconf]\n$(grep -in 'relay_from_hosts' "$exconf" 2>/dev/null | tail -n 20)"
#     break
#   fi
# done

# [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# # -----------------------------
# # 최종 판정 문구
# # -----------------------------
# if [ $FOUND_ANY -eq 0 ]; then
#   STATUS="PASS"
#   REASON_LINE="메일 서비스(sendmail/postfix/exim)가 설치되어 있지 않아 조치 대상이 없으며 이 항목에 대한 보안 위협이 없습니다."
# else
#   if [ $VULN_AFTER -eq 1 ]; then
#     STATUS="FAIL"
#     REASON_LINE="조치를 수행했으나 릴레이 제한 핵심 설정(예: promiscuous_relay 제거, mynetworks 제한, reject_unauth_destination 적용, relay_from_hosts 제한) 중 일부가 조치 이후에도 미흡하여 취약합니다. 운영 정책에 맞게 허용 대상을 재확인하고 설정을 보완한 뒤 서비스를 재적용하세요."
#     [ -z "$ACTION_LOG" ] && ACTION_LOG="조치를 시도했으나 일부 설정이 여전히 취약합니다."
#   else
#     STATUS="PASS"
#     REASON_LINE="메일 서버 설정에서 릴레이 제한이 조치 이후 정상적으로 적용되어 이 항목에 대한 보안 위협이 없습니다."
#     [ -z "$ACTION_LOG" ] && ACTION_LOG="이미 적절한 릴레이 제한 설정이 적용되어 있습니다."
#   fi
# fi

# # TARGET_FILE 기본값 보정
# if [ -z "$TARGET_FILE" ]; then
#   TARGET_FILE="/etc/mail/sendmail.cf, /etc/mail/sendmail.mc, /etc/mail/access, /etc/mail/access.db, /etc/postfix/main.cf, /etc/exim/exim.conf, /etc/exim4/exim4.conf, /etc/exim4/update-exim4.conf.conf"
# fi

# # raw_evidence 구성 (첫 줄: 조치 결과 요약 / 다음 줄: 조치 이후(after) 증적)
# RAW_EVIDENCE_JSON=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

# echo ""
# cat << EOF
# {
#   "item_code": "$ID",
#   "status": "$STATUS",
#   "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
#   "scan_date": "$SCAN_DATE"
# }
# EOF