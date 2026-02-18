#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-56
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스 접근 제어 설정 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# # 기본 변수
# ID="U-56"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service 2>/dev/null | egrep -i "vsftpd|proftpd|xinetd|inetd" || true); (ls -l /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers 2>/dev/null || true); (grep -nE "^[[:space:]]*(userlist_enable|userlist_deny|userlist_file|UseFtpUsers)[[:space:]]" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null || true)'
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE="N/A"

# ACTION_ERR_LOG=""
# MODIFIED=0
# FTP_IN_USE=0

# append_err(){ ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }
# append_detail(){ DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
# add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE/N\/A/}${TARGET_FILE:+, }$1"; }

# # key=value 설정 강제(없으면 append)
# set_kv() { # $1=file $2=key $3=value
#   local f="$1" k="$2" v="$3"
#   if grep -Eq "^[[:space:]]*${k}[[:space:]]*=" "$f" 2>/dev/null; then
#     sed -Ei "s|^[[:space:]]*${k}[[:space:]]*=.*|${k}=${v}|" "$f" 2>/dev/null || return 1
#   else
#     echo "${k}=${v}" >> "$f" 2>/dev/null || return 1
#   fi
#   return 0
# }

# ensure_list_file() { # $1=file $2=label
#   local f="$1" label="$2"
#   if [ ! -f "$f" ]; then
#     touch "$f" 2>/dev/null || { append_err "$label 생성 실패: $f"; return 1; }
#     MODIFIED=1
#   fi
#   chown root:root "$f" 2>/dev/null || { append_err "$label 소유자 설정 실패: $f"; return 1; }
#   chmod 640 "$f" 2>/dev/null || { append_err "$label 권한 설정 실패: $f"; return 1; }

#   # 최소 차단 사용자(root) 1줄 보장
#   grep -qxF "root" "$f" 2>/dev/null || { echo "root" >> "$f" 2>/dev/null || { append_err "$label 내용 추가 실패: $f"; return 1; }; MODIFIED=1; }

#   # after 증적
#   local owner perm lines
#   owner="$(stat -c '%U:%G' "$f" 2>/dev/null || echo unknown)"
#   perm="$(stat -c '%a' "$f" 2>/dev/null || echo unknown)"
#   lines="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | wc -l | tr -d ' ')"
#   append_detail "$label(after)=$f owner=$owner perm=$perm noncomment_lines=$lines"
#   add_target "$f"
#   return 0
# }

# # root 권한 필수
# if [ "$(id -u)" -ne 0 ]; then
#   REASON_LINE="root 권한이 아니어서 FTP 접근 제어 설정을 적용할 수 없어 조치를 중단합니다."
#   DETAIL_CONTENT="(주의) root 권한이 아니면 설정 파일 수정/권한 변경이 실패할 수 있습니다."
# else
#   # 설정 파일 탐색
#   VSFTPD_CONF=""
#   [ -f "/etc/vsftpd.conf" ] && VSFTPD_CONF="/etc/vsftpd.conf"
#   [ -z "$VSFTPD_CONF" ] && [ -f "/etc/vsftpd/vsftpd.conf" ] && VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"

#   PROFTPD_CONF=""
#   [ -f "/etc/proftpd/proftpd.conf" ] && PROFTPD_CONF="/etc/proftpd/proftpd.conf"
#   [ -z "$PROFTPD_CONF" ] && [ -f "/etc/proftpd.conf" ] && PROFTPD_CONF="/etc/proftpd.conf"

#   # FTP 사용 여부(최소): 설정 파일 존재 또는 서비스 활성(있으면 조치 대상)
#   if [ -n "$VSFTPD_CONF" ] || [ -n "$PROFTPD_CONF" ]; then
#     FTP_IN_USE=1
#   elif command -v systemctl >/dev/null 2>&1; then
#     systemctl is-active --quiet vsftpd 2>/dev/null && FTP_IN_USE=1
#     systemctl is-active --quiet proftpd 2>/dev/null && FTP_IN_USE=1
#   fi

#   if [ "$FTP_IN_USE" -eq 0 ]; then
#     IS_SUCCESS=1
#     REASON_LINE="FTP 서비스가 비활성화되어 조치 대상이 없어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     append_detail "ftp_in_use(after)=0"
#   else
#     append_detail "ftp_in_use(after)=1"

#     # ------------------------
#     # 1) vsftpd 조치(가이드 핵심: user_list 또는 ftpusers 기반 접근제어)
#     # ------------------------
#     if [ -n "$VSFTPD_CONF" ] && [ -f "$VSFTPD_CONF" ]; then
#       add_target "$VSFTPD_CONF"

#       # 접근제어를 user_list로 통일(가장 명확)
#       set_kv "$VSFTPD_CONF" "userlist_enable" "YES" || append_err "vsftpd userlist_enable 설정 실패"
#       set_kv "$VSFTPD_CONF" "userlist_deny" "YES"   || append_err "vsftpd userlist_deny 설정 실패"
#       set_kv "$VSFTPD_CONF" "userlist_file" "/etc/vsftpd.user_list" || append_err "vsftpd userlist_file 설정 실패"

#       ensure_list_file "/etc/vsftpd.user_list" "vsftpd_user_list" || true

#       # after 증적(설정값)
#       v1="$(grep -E '^[[:space:]]*userlist_enable[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | tail -n1 | tr -d ' ')"
#       v2="$(grep -E '^[[:space:]]*userlist_deny[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | tail -n1 | tr -d ' ')"
#       v3="$(grep -E '^[[:space:]]*userlist_file[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | tail -n1 | tr -d ' ')"
#       append_detail "vsftpd_conf(after)=$VSFTPD_CONF"
#       [ -n "$v1" ] && append_detail "vsftpd_${v1}(after)"
#       [ -n "$v2" ] && append_detail "vsftpd_${v2}(after)"
#       [ -n "$v3" ] && append_detail "vsftpd_${v3}(after)"

#       # 재시작(활성인 경우만)
#       if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet vsftpd 2>/dev/null; then
#         systemctl restart vsftpd >/dev/null 2>&1 || append_err "vsftpd 재시작 실패"
#       fi
#     fi

#     # ------------------------
#     # 2) proftpd 조치(가이드 핵심: UseFtpUsers + ftpusers)
#     # ------------------------
#     if [ -n "$PROFTPD_CONF" ] && [ -f "$PROFTPD_CONF" ]; then
#       add_target "$PROFTPD_CONF"

#       # UseFtpUsers on(미설정이면 on 취급이 일반적이나, 명시해 혼선 제거)
#       if grep -qiE '^[[:space:]]*UseFtpUsers[[:space:]]+' "$PROFTPD_CONF" 2>/dev/null; then
#         sed -Ei 's/^[[:space:]]*UseFtpUsers[[:space:]]+.*/UseFtpUsers on/I' "$PROFTPD_CONF" 2>/dev/null || append_err "proftpd UseFtpUsers 설정 실패"
#       else
#         echo "UseFtpUsers on" >> "$PROFTPD_CONF" 2>/dev/null || append_err "proftpd UseFtpUsers 추가 실패"
#       fi

#       # ftpusers 파일 보장(/etc/ftpusers 우선)
#       ensure_list_file "/etc/ftpusers" "proftpd_ftpusers" || true

#       # after 증적
#       p1="$(grep -Ei '^[[:space:]]*UseFtpUsers[[:space:]]+' "$PROFTPD_CONF" 2>/dev/null | tail -n1 | tr -s ' ')"
#       append_detail "proftpd_conf(after)=$PROFTPD_CONF"
#       [ -n "$p1" ] && append_detail "proftpd_${p1}(after)"

#       if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet proftpd 2>/dev/null; then
#         systemctl restart proftpd >/dev/null 2>&1 || append_err "proftpd 재시작 실패"
#       fi
#     fi

#     # ------------------------
#     # 3) inetd/xinetd 기반 흔적이 있는 경우(최소 조치: /etc/ftpusers 보장)
#     # ------------------------
#     # 환경 의존성이 크므로 과도한 서비스 설정 변경은 피하고, 차단목록 파일만 보장
#     if [ -f "/etc/inetd.conf" ] && grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*ftp([[:space:]]|$)'; then
#       ensure_list_file "/etc/ftpusers" "ftpd_ftpusers" || true
#       add_target "/etc/inetd.conf"
#       append_detail "inetd_ftp(after)=enabled_in_inetd_conf"
#     fi
#     if [ -f "/etc/xinetd.d/ftp" ] && grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/xinetd.d/ftp 2>/dev/null | grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then
#       ensure_list_file "/etc/ftpusers" "ftpd_ftpusers" || true
#       add_target "/etc/xinetd.d/ftp"
#       append_detail "xinetd_ftp(after)=disable=no"
#     fi

#     # ------------------------
#     # 최종 판정(에러 있으면 실패)
#     # ------------------------
#     if [ -n "$ACTION_ERR_LOG" ]; then
#       IS_SUCCESS=0
#       REASON_LINE="조치를 수행했으나 일부 설정 적용 또는 서비스 재기동에 실패해 조치가 완료되지 않았습니다."
#       append_detail "error(after)=$ACTION_ERR_LOG"
#     else
#       IS_SUCCESS=1
#       if [ "$MODIFIED" -eq 1 ]; then
#         REASON_LINE="FTP 서비스 접근 제어 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#       else
#         REASON_LINE="FTP 서비스 접근 제어 설정이 이미 적절하여 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#       fi
#     fi
#   fi
# fi

# # raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 조치 후 상태만)
# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n${DETAIL_CONTENT:-none}",
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