#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-20
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : /etc/(x)inetd.conf 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-20"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/* /etc/systemd/system.conf /etc/systemd/*"
CHECK_COMMAND='stat -c "%U %a %n" /etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf 2>/dev/null; find /etc/xinetd.d -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%U %a %n" "{}" 2>/dev/null; find /etc/systemd -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%U %a %n" "{}" 2>/dev/null'

DETAIL_CONTENT=""
REASON_LINE=""
VULN_LINES=""
ALL_LINES=""
GUIDE_LINE="N/A"

append_line() {
  # $1: target var name, $2: line
  if [ "$1" = "ALL" ]; then
    ALL_LINES+="$2"$'\n'
  else
    VULN_LINES+="$2"$'\n'
  fi
}

# 단일 파일 점검: 현재 설정값은 ALL_LINES에 누적, 취약 설정은 VULN_LINES에 누적
check_file() {
  local FILE="$1"

  if [ ! -e "$FILE" ]; then
    append_line "ALL" "[INFO] $FILE file_not_found"
    return
  fi

  local OWNER PERM
  OWNER=$(stat -c %U "$FILE" 2>/dev/null)
  PERM=$(stat -c %a "$FILE" 2>/dev/null)

  append_line "ALL" "$FILE owner=$OWNER perm=$PERM"

  if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
    STATUS="FAIL"
    append_line "VULN" "$FILE owner=$OWNER perm=$PERM"
  fi
}

# 디렉터리 내 파일 점검: 현재 설정값은 ALL_LINES에 누적, 취약 설정은 VULN_LINES에 누적
check_directory_files() {
  local DIR="$1"

  if [ ! -d "$DIR" ]; then
    append_line "ALL" "[INFO] $DIR dir_not_found"
    return
  fi

  while IFS= read -r FILE; do
    local OWNER PERM
    OWNER=$(stat -c %U "$FILE" 2>/dev/null)
    PERM=$(stat -c %a "$FILE" 2>/dev/null)

    append_line "ALL" "$FILE owner=$OWNER perm=$PERM"

    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
      STATUS="FAIL"
      append_line "VULN" "$FILE owner=$OWNER perm=$PERM"
    fi
  done < <(find "$DIR" -type f 2>/dev/null)
}

# 대상 점검 수행
check_file "/etc/inetd.conf"
check_file "/etc/xinetd.conf"
check_directory_files "/etc/xinetd.d"
check_directory_files "/etc/systemd"

DETAIL_CONTENT="$(printf "%s" "$ALL_LINES" | sed 's/[[:space:]]*$//')"
[ -n "$DETAIL_CONTENT" ] || DETAIL_CONTENT="no_data"

# 양호/취약에 따라 REASON_LINE 및 GUIDE_LINE 구성
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="모든 대상 파일이 owner=root이고 perm이 600 이하로 설정되어 있어 이 항목에 대해 양호합니다."
else
  # 취약 시 REASON_LINE에는 취약 설정(설정값)만 포함하고 1문장으로 구성
  VULN_ONE_LINE="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//' | tr '\n' ',' | sed 's/,$//; s/,/, /g')"
  [ -n "$VULN_ONE_LINE" ] || VULN_ONE_LINE="vulnerable_settings_not_collected"
  REASON_LINE="$VULN_ONE_LINE 로 설정되어 있어 이 항목에 대해 취약합니다."
fi

# 취약 가정 자동 조치
GUIDE_LINE="자동 조치:
/etc/inetd.conf, /etc/xinetd.conf, /etc/systemd/system.conf 및 /etc/xinetd.d/*, /etc/systemd/* 파일에 대해 소유자/그룹을 root:root로 변경하고 권한을 600으로 적용합니다.
조치 후 systemctl daemon-reload를 수행하여 설정 반영을 확인합니다(서비스 환경에 따라 재시작이 필요할 수 있습니다).
주의사항: 
일부 환경에서 systemd 설정 파일 권한을 600으로 변경하면 비root 계정으로 설정 조회/진단 도구 사용에 제한이 생길 수 있어 운영 절차에 영향을 줄 수 있습니다."

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
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

# JSON escape 처리 (따옴표, 줄바꿈): DB 저장 후 재로딩 시 \n이 유지되도록 \\n 형태로 저장
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
