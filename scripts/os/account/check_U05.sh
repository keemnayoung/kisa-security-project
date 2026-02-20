#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-05
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : UID가 0인 일반 계정 존재
# @Description : root 계정 이외에 UID가 0인 계정이 존재하는지 점검
# @Criteria_Good : root 계정 이외에 UID가 0인 계정이 존재하지 않는 경우
# @Criteria_Bad : root 계정 이외에 UID가 0인 계정이 존재하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-05"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"

# 점검 명령
CHECK_COMMAND='(command -v getent >/dev/null 2>&1 && getent passwd | awk -F: '\''$3 == 0 && $1 != "root" {print $1 ":" $3 ":" $0}'\'') || ([ -f /etc/passwd ] && awk -F: '\''$3 == 0 && $1 != "root" {print $1 ":" $3 ":" $0}'\'' /etc/passwd 2>/dev/null) || echo "passwd_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""

EVID_TARGET=""
UID0_EXCEPT_ROOT=""
UID0_EXCEPT_ROOT_LINES=""
UID0_ROOT_LINE=""

# JSON escape (따옴표/역슬래시/줄바꿈)
json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# NSS(getent)가 있으면 실제 계정 DB 기준으로 수집
if command -v getent >/dev/null 2>&1; then
  EVID_TARGET="getent passwd"
  UID0_EXCEPT_ROOT=$(getent passwd 2>/dev/null | awk -F: '$3==0 && $1!="root" {print $1}' | sed 's/[[:space:]]*$//')
  UID0_EXCEPT_ROOT_LINES=$(getent passwd 2>/dev/null | awk -F: '$3==0 && $1!="root" {print $0}' | sed 's/[[:space:]]*$//')
  UID0_ROOT_LINE=$(getent passwd root 2>/dev/null | head -n 1 | sed 's/[[:space:]]*$//')

# getent가 없으면 로컬 /etc/passwd 기준으로 수집
elif [ -f "$TARGET_FILE" ]; then
  EVID_TARGET="/etc/passwd"
  UID0_EXCEPT_ROOT=$(awk -F: '$3==0 && $1!="root" {print $1}' "$TARGET_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')
  UID0_EXCEPT_ROOT_LINES=$(awk -F: '$3==0 && $1!="root" {print $0}' "$TARGET_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')
  UID0_ROOT_LINE=$(awk -F: '$1=="root" {print $0; exit}' "$TARGET_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')

# 둘 다 불가하면 점검 불가
else
  EVID_TARGET="passwd_not_found"
fi

# 수집 내용 + root 라인 + root 제외 UID0 계정 라인들
if [ "$EVID_TARGET" = "passwd_not_found" ]; then
  DETAIL_CONTENT="evidence_source=unavailable
uid0_root_entry=unavailable
uid0_except_root_entries=unavailable"
else
  DETAIL_CONTENT="evidence_source=${EVID_TARGET}
uid0_root_entry=${UID0_ROOT_LINE:-not_found}
uid0_except_root_entries:
${UID0_EXCEPT_ROOT_LINES:-none}"
fi

# 판정 및 detail 문장 구성
if [ "$EVID_TARGET" = "passwd_not_found" ]; then
  STATUS="FAIL"
  REASON_LINE="계정 정보 소스를 확인할 수 없어 uid0_except_root_entries=unavailable 상태이므로 이 항목에 대해 취약합니다."
elif [ -z "$UID0_EXCEPT_ROOT" ]; then
  STATUS="PASS"
  REASON_LINE="uid0_except_root_entries=none 으로 설정되어 있어 이 항목에 대해 양호합니다."
else
  STATUS="FAIL"
  REASON_LINE="uid0_except_root_accounts=$(printf "%s" "$UID0_EXCEPT_ROOT" | paste -sd',' -) 으로 설정되어 있어 이 항목에 대해 취약합니다."
fi

# 자동 조치 가이드
GUIDE_LINE="자동 조치:
root 이외 uid=0 계정을 중복되지 않는 일반 UID로 변경합니다.
계정이 사용 중이거나 PID 1 사용자 매핑에 영향이 있으면 자동 조치를 중단하고 수동 조치를 안내합니다.
UID 변경 후 기존 숫자 UID 소유 파일이 남지 않도록 소유권을 새 사용자로 정리합니다.
주의사항:
UID 변경은 해당 계정으로 실행 중인 프로세스/서비스에 영향을 줄 수 있어 서비스 장애가 발생할 수 있습니다.
주의사항으로 소유권 정리는 파일 수가 많은 환경에서 시간이 오래 걸리거나 권한 문제로 일부 변경이 누락될 수 있습니다."

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

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

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
