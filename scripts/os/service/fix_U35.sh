#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-35
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : 공유 서비스의 익명 접근 제한 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-35 공유 서비스에 대한 익명 접근 제한 설정

# # 기본 변수
# ID="U-35"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND='
# ( [ -f /etc/passwd ] && egrep "^(ftp|anonymous):" /etc/passwd 2>/dev/null ) || echo "no_ftp_or_anonymous_account";
# ( [ -f /etc/vsftpd.conf ] && grep -nEv "^[[:space:]]*#" /etc/vsftpd.conf 2>/dev/null | grep -niE "^[[:space:]]*anonymous_enable[[:space:]]*=" ) \
#   || ( [ -f /etc/vsftpd/vsftpd.conf ] && grep -nEv "^[[:space:]]*#" /etc/vsftpd/vsftpd.conf 2>/dev/null | grep -niE "^[[:space:]]*anonymous_enable[[:space:]]*=" ) \
#   || echo "vsftpd_conf_not_found_or_no_setting";
# ( [ -f /etc/proftpd.conf ] && ( sed -n "/<Anonymous/,/<\/Anonymous>/p" /etc/proftpd.conf 2>/dev/null | grep -nEv "^[[:space:]]*#" | head -n 5; grep -nEv "^[[:space:]]*#" /etc/proftpd.conf 2>/dev/null | grep -niE "^[[:space:]]*(User|UserAlias)[[:space:]]+" | head -n 5 ) ) \
#   || ( [ -f /etc/proftpd/proftpd.conf ] && ( sed -n "/<Anonymous/,/<\/Anonymous>/p" /etc/proftpd/proftpd.conf 2>/dev/null | grep -nEv "^[[:space:]]*#" | head -n 5; grep -nEv "^[[:space:]]*#" /etc/proftpd/proftpd.conf 2>/dev/null | grep -niE "^[[:space:]]*(User|UserAlias)[[:space:]]+" | head -n 5 ) ) \
#   || echo "proftpd_conf_not_found_or_no_active_anonymous";
# ( [ -f /etc/exports ] && grep -nEv "^[[:space:]]*#" /etc/exports 2>/dev/null | grep -nE "(anonuid|anongid)" ) || echo "exports_no_anonuid_anongid";
# ( [ -f /etc/samba/smb.conf ] && grep -nEv "^[[:space:]]*#" /etc/samba/smb.conf 2>/dev/null | grep -niE "guest[[:space:]]*ok[[:space:]]*=[[:space:]]*yes([[:space:]]|$)" ) || echo "samba_no_guest_ok_yes"
# '

# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE="/etc/passwd
# /etc/vsftpd.conf (/etc/vsftpd/vsftpd.conf)
# /etc/proftpd.conf (/etc/proftpd/proftpd.conf)
# /etc/exports
# /etc/samba/smb.conf"

# ACTION_ERR_LOG=""

# # (필수) root 권한 권장 안내(실패 원인 명확화용)
# if [ "$(id -u)" -ne 0 ]; then
#   ACTION_ERR_LOG="(주의) root 권한이 아니면 userdel/sed/systemctl/exportfs/smbcontrol 조치가 실패할 수 있습니다."
# fi

# TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
# MODIFIED=0

# append_err() {
#   if [ -n "$ACTION_ERR_LOG" ]; then
#     ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
#   else
#     ACTION_ERR_LOG="$1"
#   fi
# }

# append_detail() {
#   if [ -n "$DETAIL_CONTENT" ]; then
#     DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
#   else
#     DETAIL_CONTENT="$1"
#   fi
# }

# svc_exists() {
#   local svc="$1"
#   command -v systemctl >/dev/null 2>&1 || return 1
#   systemctl list-unit-files 2>/dev/null | grep -qE "^${svc}\.service" || return 1
#   return 0
# }

# restart_svc_if_exists() {
#   local svc="$1"
#   svc_exists "$svc" || return 0
#   systemctl restart "$svc" 2>/dev/null || append_err "systemctl restart ${svc} 실패"
# }

# # 설정 파일 경로 결정
# VSFTPD_CONF=""
# if [ -f "/etc/vsftpd.conf" ]; then
#   VSFTPD_CONF="/etc/vsftpd.conf"
# elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
#   VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
# fi

# PROFTPD_CONF=""
# if [ -f "/etc/proftpd.conf" ]; then
#   PROFTPD_CONF="/etc/proftpd.conf"
# elif [ -f "/etc/proftpd/proftpd.conf" ]; then
#   PROFTPD_CONF="/etc/proftpd/proftpd.conf"
# fi

# # ---------------------------
# # 1) FTP/anonymous 계정 제거(존재 시)
# # ---------------------------
# if [ -f "/etc/passwd" ]; then
#   if grep -q "^ftp:" /etc/passwd 2>/dev/null; then
#     userdel ftp 2>/dev/null || append_err "userdel ftp 실패"
#     MODIFIED=1
#   fi
#   if grep -q "^anonymous:" /etc/passwd 2>/dev/null; then
#     userdel anonymous 2>/dev/null || append_err "userdel anonymous 실패"
#     MODIFIED=1
#   fi
# else
#   append_err "/etc/passwd 파일을 확인할 수 없어 계정 조치를 수행할 수 없습니다."
# fi

# # ---------------------------
# # 2) vsftpd: anonymous_enable=NO 표준화(설정 파일이 있을 때만)
# # ---------------------------
# if [ -n "$VSFTPD_CONF" ]; then
#   cp -a "$VSFTPD_CONF" "${VSFTPD_CONF}.bak_${TIMESTAMP}" 2>/dev/null || append_err "vsftpd 설정 백업 실패"

#   # YES면 NO로 변경
#   if grep -nEv "^[[:space:]]*#" "$VSFTPD_CONF" 2>/dev/null | grep -qiE "^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES([[:space:]]|$)"; then
#     sed -i 's/^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES([[:space:]]|$)/anonymous_enable=NO/I' "$VSFTPD_CONF" 2>/dev/null \
#       || append_err "vsftpd anonymous_enable=NO 변경 실패"
#     MODIFIED=1
#     restart_svc_if_exists vsftpd
#   else
#     # 설정 라인이 없으면 NO를 추가(보수적 표준화)
#     if ! grep -qiE "^[[:space:]]*anonymous_enable[[:space:]]*=" "$VSFTPD_CONF" 2>/dev/null; then
#       echo "anonymous_enable=NO" >> "$VSFTPD_CONF" 2>/dev/null || append_err "vsftpd anonymous_enable=NO 추가 실패"
#       MODIFIED=1
#       restart_svc_if_exists vsftpd
#     fi
#   fi
# fi

# # ---------------------------
# # 3) proftpd: <Anonymous> 블록 + User/UserAlias 주석 처리(설정 파일이 있을 때만)
# # ---------------------------
# if [ -n "$PROFTPD_CONF" ]; then
#   NEED_BAK=0

#   # <Anonymous> 블록 활성 여부(주석 제외)
#   ANON_ACTIVE="$(sed -n '/<Anonymous/,/<\/Anonymous>/p' "$PROFTPD_CONF" 2>/dev/null | grep -vE '^[[:space:]]*#' | sed '/^[[:space:]]*$/d' | head -n 1)"
#   if [ -n "$ANON_ACTIVE" ]; then
#     NEED_BAK=1
#     sed -i '/<Anonymous/,/<\/Anonymous>/s/^[[:space:]]*/#&/' "$PROFTPD_CONF" 2>/dev/null || append_err "proftpd <Anonymous> 블록 주석 처리 실패"
#     MODIFIED=1
#   fi

#   # (가이드 반영) User/UserAlias 활성 여부(주석 제외)
#   USER_ALIAS_ACTIVE="$(grep -nEv '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -qiE '^[[:space:]]*(User|UserAlias)[[:space:]]+' && echo "yes" || true)"
#   if [ -n "$USER_ALIAS_ACTIVE" ]; then
#     NEED_BAK=1
#     # 해당 라인만 주석 처리(라인 시작 공백 유지)
#     sed -i '/^[[:space:]]*\(User\|UserAlias\)[[:space:]]\+/s/^[[:space:]]*/#&/I' "$PROFTPD_CONF" 2>/dev/null || append_err "proftpd User/UserAlias 주석 처리 실패"
#     MODIFIED=1
#   fi

#   if [ "$NEED_BAK" -eq 1 ]; then
#     cp -a "$PROFTPD_CONF" "${PROFTPD_CONF}.bak_${TIMESTAMP}" 2>/dev/null || append_err "proftpd 설정 백업 실패"
#     restart_svc_if_exists proftpd
#   fi
# fi

# # ---------------------------
# # 4) NFS: anonuid/anongid 옵션 제거 후 exportfs -ra(파일이 있을 때만)
# # ---------------------------
# if [ -f "/etc/exports" ]; then
#   if grep -Ev "^[[:space:]]*#" /etc/exports 2>/dev/null | grep -qE "(anonuid|anongid)"; then
#     cp -a /etc/exports "/etc/exports.bak_${TIMESTAMP}" 2>/dev/null || append_err "exports 백업 실패"
#     sed -i \
#       -e 's/,anonuid=[0-9]\+//g' \
#       -e 's/,anongid=[0-9]\+//g' \
#       -e 's/anonuid=[0-9]\+,//g' \
#       -e 's/anongid=[0-9]\+,//g' \
#       -e 's/(,/(/g; s/,,/,/g; s/,)/)/g' \
#       /etc/exports 2>/dev/null || append_err "exports anonuid/anongid 제거 실패"
#     MODIFIED=1
#     command -v exportfs >/dev/null 2>&1 && exportfs -ra 2>/dev/null || append_err "exportfs -ra 실패 또는 exportfs 없음"
#   fi
# fi

# # ---------------------------
# # 5) Samba: guest ok = no 표준화(파일이 있을 때만)
# # ---------------------------
# if [ -f "/etc/samba/smb.conf" ]; then
#   if grep -nEv "^[[:space:]]*#" /etc/samba/smb.conf 2>/dev/null | grep -qiE "guest[[:space:]]*ok[[:space:]]*=[[:space:]]*yes([[:space:]]|$)"; then
#     cp -a /etc/samba/smb.conf "/etc/samba/smb.conf.bak_${TIMESTAMP}" 2>/dev/null || append_err "smb.conf 백업 실패"
#     sed -i 's/^[[:space:]]*guest[[:space:]]*ok[[:space:]]*=[[:space:]]*yes([[:space:]]|$)/guest ok = no/I' /etc/samba/smb.conf 2>/dev/null \
#       || append_err "smb.conf guest ok=no 변경 실패"
#     MODIFIED=1
#     if command -v smbcontrol >/dev/null 2>&1; then
#       smbcontrol all reload-config 2>/dev/null || append_err "smbcontrol reload-config 실패"
#     else
#       restart_svc_if_exists smbd
#       restart_svc_if_exists smb
#     fi
#   fi
# fi

# # ---------------------------
# # 조치 후 상태 수집(※ before 미표기: 요구사항 반영)
# # ---------------------------
# AFTER_FTP_ACCTS="$(egrep "^(ftp|anonymous):" /etc/passwd 2>/dev/null | cut -d: -f1 | paste -sd, - 2>/dev/null)"
# [ -z "$AFTER_FTP_ACCTS" ] && AFTER_FTP_ACCTS="none"

# AFTER_VSFTPD="not_found"
# if [ -n "$VSFTPD_CONF" ]; then
#   AFTER_VSFTPD="$(grep -nEv '^[[:space:]]*#' "$VSFTPD_CONF" 2>/dev/null | grep -iE '^[[:space:]]*anonymous_enable[[:space:]]*=' | tail -n 1)"
#   [ -z "$AFTER_VSFTPD" ] && AFTER_VSFTPD="no_setting"
# fi

# AFTER_PROFTPD_ANON="not_found"
# AFTER_PROFTPD_USERALIAS="not_found"
# if [ -n "$PROFTPD_CONF" ]; then
#   AFTER_PROFTPD_ANON="$(sed -n '/<Anonymous/,/<\/Anonymous>/p' "$PROFTPD_CONF" 2>/dev/null | grep -nEv '^[[:space:]]*#' | head -n 3 | paste -sd' | ' - 2>/dev/null)"
#   [ -z "$AFTER_PROFTPD_ANON" ] && AFTER_PROFTPD_ANON="no_active_anonymous_block"

#   AFTER_PROFTPD_USERALIAS="$(grep -nEv '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -niE '^[[:space:]]*(User|UserAlias)[[:space:]]+' | head -n 3 | paste -sd' | ' - 2>/dev/null)"
#   [ -z "$AFTER_PROFTPD_USERALIAS" ] && AFTER_PROFTPD_USERALIAS="no_user_or_useralias_active"
# fi

# AFTER_EXPORTS="not_found"
# if [ -f "/etc/exports" ]; then
#   AFTER_EXPORTS="$(grep -nEv '^[[:space:]]*#' /etc/exports 2>/dev/null | grep -E '(anonuid|anongid)' | head -n 3 | paste -sd' | ' - 2>/dev/null)"
#   [ -z "$AFTER_EXPORTS" ] && AFTER_EXPORTS="no_anonuid_anongid"
# fi

# AFTER_SAMBA="not_found"
# if [ -f "/etc/samba/smb.conf" ]; then
#   AFTER_SAMBA="$(grep -nEv '^[[:space:]]*#' /etc/samba/smb.conf 2>/dev/null | grep -iE 'guest[[:space:]]*ok[[:space:]]*=[[:space:]]*yes([[:space:]]|$)' | head -n 3 | paste -sd' | ' - 2>/dev/null)"
#   [ -z "$AFTER_SAMBA" ] && AFTER_SAMBA="no_guest_ok_yes"
# fi

# # detail(조치 후/현재 설정만)
# append_detail "ftp_accounts(after)=$AFTER_FTP_ACCTS"
# append_detail "vsftpd_anonymous_enable(after)=$AFTER_VSFTPD"
# append_detail "proftpd_anonymous_block(after)=$AFTER_PROFTPD_ANON"
# append_detail "proftpd_user_or_useralias(after)=$AFTER_PROFTPD_USERALIAS"
# append_detail "exports_anonuid_anongid(after)=$AFTER_EXPORTS"
# append_detail "samba_guest_ok_yes(after)=$AFTER_SAMBA"

# # ---------------------------
# # 최종 검증(보수적)
# # ---------------------------
# FAIL_FLAG=0

# # 계정: ftp/anonymous 없어야 함
# [ "$AFTER_FTP_ACCTS" != "none" ] && FAIL_FLAG=1

# # vsftpd: 설정 파일이 있으면 anonymous_enable=NO 확인(없으면 실패 처리)
# if [ -n "$VSFTPD_CONF" ]; then
#   if ! echo "$AFTER_VSFTPD" | grep -qiE "anonymous_enable[[:space:]]*=[[:space:]]*NO"; then
#     FAIL_FLAG=1
#   fi
# fi

# # proftpd: 활성 Anonymous 블록 없어야 함 + User/UserAlias 활성 없어야 함
# if [ -n "$PROFTPD_CONF" ]; then
#   [ "$AFTER_PROFTPD_ANON" != "no_active_anonymous_block" ] && FAIL_FLAG=1
#   [ "$AFTER_PROFTPD_USERALIAS" != "no_user_or_useralias_active" ] && FAIL_FLAG=1
# fi

# # exports: anonuid/anongid 없어야 함(파일 존재 시)
# if [ -f "/etc/exports" ]; then
#   [ "$AFTER_EXPORTS" != "no_anonuid_anongid" ] && FAIL_FLAG=1
# fi

# # samba: guest ok=yes 없어야 함(파일 존재 시)
# if [ -f "/etc/samba/smb.conf" ]; then
#   [ "$AFTER_SAMBA" != "no_guest_ok_yes" ] && FAIL_FLAG=1
# fi

# if [ "$FAIL_FLAG" -eq 0 ]; then
#   IS_SUCCESS=1
#   if [ "$MODIFIED" -eq 1 ]; then
#     REASON_LINE="공유 서비스(FTP/NFS/Samba)의 익명 접근 설정이 제한되도록 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   else
#     REASON_LINE="공유 서비스(FTP/NFS/Samba)의 익명 접근 설정이 이미 제한된 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   fi
# else
#   IS_SUCCESS=0
#   REASON_LINE="조치를 수행했으나 공유 서비스(FTP/NFS/Samba)의 익명 접근 관련 설정이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
# fi

# if [ -n "$ACTION_ERR_LOG" ]; then
#   DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
# fi

# # raw_evidence 구성 (after/current만 포함)
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