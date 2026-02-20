#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-55
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : FTP 계정 shell 제한
# @Description : FTP 기본 계정에 쉘 설정 여부 점검
# @Criteria_Good : FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우
# @Criteria_Bad : FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-55"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

PASSWD_FILE="/etc/passwd"
TARGET_FILE="$PASSWD_FILE"
CHECK_COMMAND="awk -F: '\$1==\"ftp\"{print NR\"|\"\$7\"|\"\$0; exit}' $PASSWD_FILE"

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE=""

FTP_REC=""
FTP_LINENO=""
FTP_SHELL=""
FTP_ENTRY=""

json_escape() {
  echo -n "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g'
}

is_locked_shell() {
  case "$1" in
    /bin/false|/sbin/nologin|/usr/sbin/nologin) return 0 ;;
    *) return 1 ;;
  esac
}

# /etc/passwd 미존재 시: 계정 확인 불가로 취약 처리
if [ ! -f "$PASSWD_FILE" ]; then
  STATUS="FAIL"
  REASON_LINE="/etc/passwd 파일이 존재하지 않아 ftp 계정의 로그인 쉘 설정을 확인할 수 있어 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="file_not_found"
else
  # ftp 계정이 존재하는지 1건만 확인 (lineNo|shell|full_entry)
  FTP_REC="$(awk -F: '$1=="ftp"{print NR"|" $7 "|" $0; exit}' "$PASSWD_FILE" 2>/dev/null)"

  # ftp 계정 미존재 시: 점검 대상 계정이 없어 양호 처리
  if [ -z "$FTP_REC" ]; then
    STATUS="PASS"
    REASON_LINE="/etc/passwd에 ftp 계정이 존재하지 않아 이 항목에 대해 양호합니다."
    DETAIL_CONTENT="ftp_account=not_found"
  else
    IFS='|' read -r FTP_LINENO FTP_SHELL FTP_ENTRY <<< "$FTP_REC"
    DETAIL_CONTENT="ftp_entry(line=$FTP_LINENO)=$FTP_ENTRY"

    # ftp 쉘이 제한 쉘이면 양호, 아니면 취약
    if is_locked_shell "$FTP_SHELL"; then
      STATUS="PASS"
      REASON_LINE="/etc/passwd의 ftp 계정 로그인 쉘이 $FTP_SHELL(으)로 설정되어 있어 이 항목에 대해 양호합니다."
    else
      STATUS="FAIL"
      REASON_LINE="/etc/passwd의 ftp 계정 로그인 쉘이 $FTP_SHELL(으)로 설정되어 있어 이 항목에 대해 취약합니다."
    fi
  fi
fi

GUIDE_LINE=$(cat <<'EOF'
자동 조치: 
ftp 계정의 로그인 쉘을 /sbin/nologin(또는 /usr/sbin/nologin, /bin/false)로 변경합니다.
usermod -s /sbin/nologin ftp 명령을 우선 적용하고, 미존재 시 /usr/sbin/nologin 또는 /bin/false로 대체 적용합니다.
변경 후 getent passwd ftp 또는 /etc/passwd 확인으로 ftp 계정 쉘이 nologin/false인지 재확인합니다.
주의사항: 
쉘 변경은 ftp 계정을 참조하는 운영/자동화 작업에 영향을 줄 수 있으므로, 변경 전 서비스 연동 여부를 확인하고 유지보수 창에 적용하는 것이 안전합니다.
EOF
)
# raw_evidence 구성
DETAIL_LINE=""
if [ "$STATUS" = "PASS" ]; then
  DETAIL_LINE="$REASON_LINE"
else
  DETAIL_LINE="$REASON_LINE"
fi

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_LINE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
