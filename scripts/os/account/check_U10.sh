#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-10
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 동일한 UID 금지
# @Description : /etc/passwd 파일 내 중복된 UID가 존재하는지 점검
# @Criteria_Good : 모든 계정의 UID가 고유하게 설정된 경우
# @Criteria_Bad : 하나 이상의 계정이 동일한 UID를 공유하고 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-10"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='[ -f /etc/passwd -a -r /etc/passwd ] && cut -d: -f1,3 /etc/passwd | sort -t: -k2,2n || echo "passwd_not_found_or_not_readable"'

REASON_LINE=""
DETAIL_CONTENT=""

DUPS=""
DUPLICATE_LINES=""

GUIDE_LINE="자동 조치 시 UID 변경으로 인해 파일/디렉터리 소유권 불일치, 서비스 계정 권한 문제, 로그인/프로세스 권한 오동작이 발생할 수 있어 수동 조치가 필요합니다.\n관리자가 직접 중복 UID 계정을 확인한 뒤, 중복 계정 중 하나의 UID를 변경하고 해당 UID로 소유된 파일/디렉터리의 소유권을 올바른 계정으로 재설정해 주시기 바랍니다."

# 분기 1) /etc/passwd 파일 존재 여부 확인
if [ -f "$TARGET_FILE" ]; then
  # 분기 2) /etc/passwd 읽기 가능 여부 확인(읽기 불가 시 점검 불가 처리)
  if [ ! -r "$TARGET_FILE" ]; then
    STATUS="FAIL"
    REASON_LINE="/etc/passwd 읽기 권한이 없어 점검할 수 있어 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="$(ls -l "$TARGET_FILE" 2>/dev/null || echo "ls_failed")"
  else
    # 분기 3) 현재 설정값 수집(사용자:UID 목록)
    PASSWD_UID_LINES="$(cut -d: -f1,3 "$TARGET_FILE" 2>/dev/null | sed '/^[[:space:]]*$/d')"
    if [ -z "$PASSWD_UID_LINES" ]; then
      STATUS="FAIL"
      REASON_LINE="/etc/passwd에서 사용자:UID 값을 추출하지 못해 점검할 수 있어 이 항목에 대해 취약합니다."
      DETAIL_CONTENT="passwd_uid_extract_failed"
    else
      # 분기 4) 중복 UID 탐지 및 결과 구성
      DUPS="$(printf "%s\n" "$PASSWD_UID_LINES" | cut -d: -f2 | sort -n | uniq -d)"

      if [ -z "$DUPS" ]; then
        STATUS="PASS"
        REASON_LINE="/etc/passwd에 중복 UID가 존재하지 않아 이 항목에 대해 양호합니다."
        DETAIL_CONTENT="$PASSWD_UID_LINES"
      else
        STATUS="FAIL"

        for uid in $DUPS; do
          ACCOUNTS="$(awk -F: -v u="$uid" '$3==u{print $1}' "$TARGET_FILE" 2>/dev/null | xargs)"
          DUPLICATE_LINES+="uid=$uid accounts=$ACCOUNTS"$'\n'
        done
        DUPLICATE_LINES="$(printf "%s" "$DUPLICATE_LINES" | sed 's/[[:space:]]*$//')"

        REASON_LINE="$DUPLICATE_LINES 이 설정으로 UID가 중복되어 있어 이 항목에 대해 취약합니다."
        DETAIL_CONTENT="$PASSWD_UID_LINES"
      fi
    fi
  fi
else
  # 분기 5) /etc/passwd 파일이 없는 경우(점검 불가 처리)
  STATUS="FAIL"
  REASON_LINE="/etc/passwd 파일이 없어 점검할 수 있어 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="passwd_not_found"
fi

# RAW_EVIDENCE 구성(각 문장은 줄바꿈으로 구분)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리(따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED="$(printf "%s" "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')"

# scan_history JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
