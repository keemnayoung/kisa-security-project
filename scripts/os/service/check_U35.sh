#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-35
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : 공유 서비스의 익명 접근 제한 설정 여부 점검
# @Criteria_Good : 공유 서비스에 대해 익명 접근을 제한한 경우
# @Criteria_Bad : 공유 서비스에 대해 익명 접근을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-35"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd.conf /etc/proftpd/proftpd.conf /etc/exports /etc/samba/smb.conf"
CHECK_COMMAND='( [ -f /etc/passwd ] && (grep -nE "^ftp:" /etc/passwd; grep -nE "^anonymous:" /etc/passwd) || echo "passwd_not_found" ); ( for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do [ -f "$f" ] && grep -nEv "^[[:space:]]*#" "$f" | grep -niE "^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES([[:space:]]|$)"; done ) ; ( for f in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do [ -f "$f" ] && ( sed -n "/<Anonymous/,/<\\/Anonymous>/p" "$f" 2>/dev/null | grep -nEv "^[[:space:]]*#" ; grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -niE "^[[:space:]]*(User|UserAlias)[[:space:]]+" ); done ); ( [ -f /etc/exports ] && grep -nEv "^[[:space:]]*#" /etc/exports | grep -nE "(anonuid|anongid)" || echo "exports_not_found_or_no_anon" ); ( [ -f /etc/samba/smb.conf ] && grep -nEv "^[[:space:]]*#" /etc/samba/smb.conf | grep -niE "guest[[:space:]]*ok[[:space:]]*=[[:space:]]*yes([[:space:]]|$)" || echo "smb_conf_not_found_or_no_guest_ok_yes" )'

REASON_LINE=""
DETAIL_CONTENT=""

SERVICE_EXISTS=0
VULNERABLE=0

DETAIL_LINES=""
VULN_REASON_LINES=""

append_line() {
  # 첫 번째 인자: 변수명, 두 번째 인자: 추가할 한 줄 문자열
  if [ -n "${!1}" ]; then
    eval "$1=\"\${$1}\n$2\""
  else
    eval "$1=\"$2\""
  fi
}

# /etc/passwd: ftp/anonymous 계정 존재 여부에 따라 익명 접근 가능성 판단
if [ -f /etc/passwd ]; then
  FTP_ACC=$(grep -nE "^ftp:" /etc/passwd 2>/dev/null | head -n 1)
  ANON_ACC=$(grep -nE "^anonymous:" /etc/passwd 2>/dev/null | head -n 1)

  if [ -n "$FTP_ACC" ]; then
    SERVICE_EXISTS=1
    VULNERABLE=1
    append_line DETAIL_LINES "/etc/passwd: ${FTP_ACC}"
    append_line VULN_REASON_LINES "/etc/passwd ftp 계정 존재(${FTP_ACC})"
  else
    append_line DETAIL_LINES "/etc/passwd: ftp 계정 미존재"
  fi

  if [ -n "$ANON_ACC" ]; then
    SERVICE_EXISTS=1
    VULNERABLE=1
    append_line DETAIL_LINES "/etc/passwd: ${ANON_ACC}"
    append_line VULN_REASON_LINES "/etc/passwd anonymous 계정 존재(${ANON_ACC})"
  else
    append_line DETAIL_LINES "/etc/passwd: anonymous 계정 미존재"
  fi
else
  append_line DETAIL_LINES "/etc/passwd: 파일 미존재"
fi

# vsftpd: anonymous_enable=YES 여부에 따라 익명 FTP 허용 여부 판단
VSFTPD_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
  VSFTPD_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
  VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
fi

if [ -n "$VSFTPD_CONF" ]; then
  SERVICE_EXISTS=1
  VS_ANON_LINE=$(grep -nEv "^[[:space:]]*#" "$VSFTPD_CONF" 2>/dev/null | grep -niE "^[[:space:]]*anonymous_enable[[:space:]]*=" | tail -n 1)

  if echo "$VS_ANON_LINE" | grep -qiE "=[[:space:]]*YES([[:space:]]|$)"; then
    VULNERABLE=1
    append_line DETAIL_LINES "${VSFTPD_CONF}: ${VS_ANON_LINE}"
    append_line VULN_REASON_LINES "${VSFTPD_CONF} anonymous_enable=YES(${VS_ANON_LINE})"
  else
    if [ -n "$VS_ANON_LINE" ]; then
      append_line DETAIL_LINES "${VSFTPD_CONF}: ${VS_ANON_LINE}"
    else
      append_line DETAIL_LINES "${VSFTPD_CONF}: anonymous_enable 설정 라인 미확인"
    fi
  fi
else
  append_line DETAIL_LINES "vsftpd: 설정 파일 미존재(/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf)"
fi

# proftpd: <Anonymous> 블록 및 User/UserAlias 활성 여부에 따라 익명 접근 가능성 판단
PROFTPD_CONF=""
if [ -f "/etc/proftpd.conf" ]; then
  PROFTPD_CONF="/etc/proftpd.conf"
elif [ -f "/etc/proftpd/proftpd.conf" ]; then
  PROFTPD_CONF="/etc/proftpd/proftpd.conf"
fi

if [ -n "$PROFTPD_CONF" ]; then
  SERVICE_EXISTS=1

  ANON_BLOCK=$(sed -n '/<Anonymous/,/<\/Anonymous>/p' "$PROFTPD_CONF" 2>/dev/null | grep -Ev '^[[:space:]]*#' | sed '/^[[:space:]]*$/d')
  if [ -n "$ANON_BLOCK" ]; then
    VULNERABLE=1
    ANON_SAMPLE=$(printf "%s\n" "$ANON_BLOCK" | head -n 10)
    append_line DETAIL_LINES "${PROFTPD_CONF}: <Anonymous> 블록(주석 제외) 감지"
    append_line DETAIL_LINES "${ANON_SAMPLE}"
    append_line VULN_REASON_LINES "${PROFTPD_CONF} <Anonymous> 블록 활성"
  else
    append_line DETAIL_LINES "${PROFTPD_CONF}: <Anonymous> 블록 활성 내용 미확인"
  fi

  PROFTPD_USER_ALIAS=$(grep -nEv '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -niE '^[[:space:]]*(User|UserAlias)[[:space:]]+' | head -n 5)
  if [ -n "$PROFTPD_USER_ALIAS" ]; then
    VULNERABLE=1
    append_line DETAIL_LINES "${PROFTPD_CONF}: User/UserAlias 라인(주석 제외) 감지"
    append_line DETAIL_LINES "${PROFTPD_USER_ALIAS}"
    append_line VULN_REASON_LINES "${PROFTPD_CONF} User/UserAlias 활성(${PROFTPD_USER_ALIAS})"
  else
    append_line DETAIL_LINES "${PROFTPD_CONF}: User/UserAlias 활성 설정 미확인"
  fi
else
  append_line DETAIL_LINES "proftpd: 설정 파일 미존재(/etc/proftpd.conf, /etc/proftpd/proftpd.conf)"
fi

# NFS: /etc/exports의 anonuid/anongid 존재 여부에 따라 익명 매핑 접근 가능성 판단
if [ -f "/etc/exports" ]; then
  SERVICE_EXISTS=1
  NFS_ANON=$(grep -nEv "^[[:space:]]*#" /etc/exports 2>/dev/null | grep -nE "(anonuid|anongid)" | head -n 5)
  if [ -n "$NFS_ANON" ]; then
    VULNERABLE=1
    append_line DETAIL_LINES "/etc/exports: anonuid/anongid 라인(주석 제외) 감지"
    append_line DETAIL_LINES "${NFS_ANON}"
    append_line VULN_REASON_LINES "/etc/exports anonuid/anongid 존재(${NFS_ANON})"
  else
    append_line DETAIL_LINES "/etc/exports: anonuid/anongid 미확인"
  fi
else
  append_line DETAIL_LINES "NFS: /etc/exports 파일 미존재"
fi

# Samba: guest ok = yes 여부에 따라 게스트(익명) 접근 허용 여부 판단
if [ -f "/etc/samba/smb.conf" ]; then
  SERVICE_EXISTS=1
  SMB_GUEST=$(grep -nEv "^[[:space:]]*#" /etc/samba/smb.conf 2>/dev/null | grep -niE "guest[[:space:]]*ok[[:space:]]*=" | tail -n 1)
  if echo "$SMB_GUEST" | grep -qiE "=[[:space:]]*yes([[:space:]]|$)"; then
    VULNERABLE=1
    append_line DETAIL_LINES "/etc/samba/smb.conf: ${SMB_GUEST}"
    append_line VULN_REASON_LINES "/etc/samba/smb.conf guest ok=yes(${SMB_GUEST})"
  else
    if [ -n "$SMB_GUEST" ]; then
      append_line DETAIL_LINES "/etc/samba/smb.conf: ${SMB_GUEST}"
    else
      append_line DETAIL_LINES "/etc/samba/smb.conf: guest ok 설정 라인 미확인"
    fi
  fi
else
  append_line DETAIL_LINES "Samba: /etc/samba/smb.conf 파일 미존재"
fi

# DETAIL_CONTENT 구성
DETAIL_CONTENT="$(printf "%b" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

# REASON_LINE 구성
if [ "$SERVICE_EXISTS" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="익명 접근 허용 설정이 확인되지 않아 이 항목에 대해 양호합니다."
elif [ "$VULNERABLE" -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="$(printf "%b" "$VULN_REASON_LINES" | tr '\n' '; ' | sed 's/[[:space:]]*$//; s/;[[:space:]]*$//')로 설정되어 이 항목에 대해 취약합니다."
else
  STATUS="PASS"
  REASON_LINE="익명 접근 허용 설정이 확인되지 않아 이 항목에 대해 양호합니다."
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE=$(cat <<'EOF'
이 항목에 대해서 공유 서비스 설정을 자동으로 변경하면 정상 업무용 공유/접속이 중단되거나 서비스 연동(클라이언트, 배치, 마운트, 접근 권한 정책)에 장애가 발생할 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 FTP는 익명 접속을 비활성화(ftp/anonymous 계정 사용 여부 확인 및 필요 시 제거, vsftpd는 anonymous_enable=NO로 설정), ProFTPd는 <Anonymous> 블록 및 User/UserAlias 기반 익명 설정을 비활성화, NFS는 /etc/exports에서 anonuid/anongid를 제거, Samba는 smb.conf에서 guest ok = no로 변경하고 설정 반영/재기동해 주시기 바랍니다.
EOF
)

# raw_evidence: 각 값은 줄바꿈으로 문장 구분 가능하도록 구성
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
