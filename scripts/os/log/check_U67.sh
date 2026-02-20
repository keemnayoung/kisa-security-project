#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-67
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 로그 디렉터리 소유자 및 권한 설정
# @Description : 로그에 대한 접근 통제 및 관리 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-67"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/var/log"
CHECK_COMMAND='find /var/log -xdev -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%n owner=%U perm=%a" "{}" 2>/dev/null'

REASON_LINE=""
DETAIL_CONTENT=""
VULN_LINES=""
ALL_LINES=""
TOTAL_FILES=0

# JSON escape 처리 (따옴표, 줄바꿈)
json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# 대상 디렉터리가 없는 경우
if [ ! -d "$TARGET_FILE" ]; then
  STATUS="FAIL"
  VULN_LINES="/var/log dir_not_found"
  ALL_LINES="/var/log dir_not_found"
else
  # 파일 단위로 owner/perm 확인 (확인 불가도 현재 설정 값으로 기록)
  while IFS= read -r -d '' f; do
    TOTAL_FILES=$((TOTAL_FILES+1))

    owner="$(stat -c %U "$f" 2>/dev/null)"
    perm="$(stat -c %a "$f" 2>/dev/null)"

    if [ -z "$owner" ] || [ -z "$perm" ]; then
      line="$f owner=unknown perm=unknown (stat_failed)"
      ALL_LINES+="$line\n"
      VULN_LINES+="$line\n"
      continue
    fi

    line="$f owner=$owner perm=$perm"
    ALL_LINES+="$line\n"

    if [ "$owner" != "root" ] || [ "$perm" -gt 644 ]; then
      VULN_LINES+="$line\n"
    fi
  done < <(find "$TARGET_FILE" -xdev -type f -print0 2>/dev/null)

  # 대상 파일이 0개인 경우
  if [ "$TOTAL_FILES" -eq 0 ]; then
    ALL_LINES="checked_files=0"
  fi
fi

# DETAIL_CONTENT는 구성
if [ "$TOTAL_FILES" -gt 0 ]; then
  SHOW_LIMIT=50
  SHOWN_LINES="$(printf "%b" "$ALL_LINES" | sed '/^[[:space:]]*$/d' | head -n "$SHOW_LIMIT")"
  REMAIN=$((TOTAL_FILES - $(printf "%s\n" "$SHOWN_LINES" | sed '/^[[:space:]]*$/d' | wc -l)))
  if [ "$REMAIN" -gt 0 ]; then
    DETAIL_CONTENT="$(printf "%s\n" "$SHOWN_LINES")
(총 ${TOTAL_FILES}개 중 일부만 표시, 생략 ${REMAIN}개)"
  else
    DETAIL_CONTENT="$(printf "%s\n" "$SHOWN_LINES")"
  fi
else
  DETAIL_CONTENT="$(printf "%b" "$ALL_LINES" | sed 's/[[:space:]]*$//')"
fi

# 상태에 따른 reason 구성
if [ -n "$VULN_LINES" ]; then
  STATUS="FAIL"
  FIRST_VULN="$(printf "%b" "$VULN_LINES" | sed '/^[[:space:]]*$/d' | head -n 1)"
  REASON_LINE="/var/log 내 로그 파일이 ${FIRST_VULN} 로 설정되어 있어 이 항목에 대해 취약합니다."
else
  REASON_LINE="/var/log 내 로그 파일이 owner=root, perm<=644 로 설정되어 있어 이 항목에 대해 양호합니다."
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE="이 항목에 대해서 로그 파일의 소유자/권한 변경으로 일부 애플리케이션 또는 로그 수집 에이전트의 기록·수집이 실패할 수 있는 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 /var/log 내 로그 파일의 소유자를 root로 변경하고 권한을 644 이하로 설정해 주시기 바랍니다.
예) chown root /var/log/<파일 이름>
예) chmod 644 /var/log/<파일 이름>"

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
