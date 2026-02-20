#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-21
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# @Description : /etc/(r)syslog.conf 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-21"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

LOG_FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")
TARGET_FILES=()
FOUND_ANY="N"
FOUND_VULN="N"

# 현재 설정값
DETAIL_CONTENT=""

# 취약 이유
VULN_REASON_ITEMS=""

# 존재하지 않는 파일 표시
NOT_FOUND_ITEMS=""

# target_file
TARGET_FILE=""

# 점검 명령
CHECK_COMMAND=$(cat <<'EOF'
for f in /etc/syslog.conf /etc/rsyslog.conf; do
  if [ -f "$f" ]; then
    stat -c "%n owner=%U perm=%a" "$f"
  else
    echo "$f not_found"
  fi
done
EOF
)

# 대상 파일을 순회하며 상태 수집
for FILE in "${LOG_FILES[@]}"; do
  if [ -f "$FILE" ]; then
    FOUND_ANY="Y"
    TARGET_FILES+=("$FILE")

    OWNER=$(stat -c %U "$FILE" 2>/dev/null)
    PERM=$(stat -c %a "$FILE" 2>/dev/null)

    # 현재 설정값 누적
    DETAIL_CONTENT="${DETAIL_CONTENT}file=$FILE
owner=$OWNER
perm=$PERM

"

    # 판정 기준 위반 시 취약으로 마킹
    if ! [[ "$OWNER" =~ ^(root|bin|sys)$ ]] || [ -n "$PERM" ] && [ "$PERM" -gt 640 ]; then
      STATUS="FAIL"
      FOUND_VULN="Y"

      # 취약 설정 누적
      if [ -n "$VULN_REASON_ITEMS" ]; then
        VULN_REASON_ITEMS="${VULN_REASON_ITEMS}, "
      fi
      VULN_REASON_ITEMS="${VULN_REASON_ITEMS}${FILE} owner=${OWNER} perm=${PERM}"
    fi
  else
    # 파일 미존재 정보
    if [ -n "$NOT_FOUND_ITEMS" ]; then
      NOT_FOUND_ITEMS="${NOT_FOUND_ITEMS}, "
    fi
    NOT_FOUND_ITEMS="${NOT_FOUND_ITEMS}${FILE}"
  fi
done

# 점검 대상 파일 없음
if [ "$FOUND_ANY" = "N" ]; then
  STATUS="PASS"
  TARGET_FILE=""

  REASON_SENTENCE="/etc/syslog.conf 및 /etc/rsyslog.conf 파일이 존재하지 않아 점검대상 없음으로 판단되어 이 항목에 대해 양호합니다."
  DETAIL_CONTENT="file_not_found: ${NOT_FOUND_ITEMS}"

else
  # 분기 2) 존재 파일 목록 구성
  TARGET_FILE=$(printf "%s " "${TARGET_FILES[@]}" | sed 's/[[:space:]]*$//')

  # 양호/취약에 따른 이유 문장 구성
  if [ "$FOUND_VULN" = "Y" ]; then
    # 취약
    REASON_SENTENCE="${VULN_REASON_ITEMS}로 설정되어 이 항목에 대해 취약합니다."

  else
    # 양호
    OK_ITEMS=""
    for FILE in "${TARGET_FILES[@]}"; do
      OWNER=$(stat -c %U "$FILE" 2>/dev/null)
      PERM=$(stat -c %a "$FILE" 2>/dev/null)
      if [ -n "$OK_ITEMS" ]; then
        OK_ITEMS="${OK_ITEMS}, "
      fi
      OK_ITEMS="${OK_ITEMS}${FILE} owner=${OWNER} perm=${PERM}"
    done
    REASON_SENTENCE="${OK_ITEMS}로 설정되어 이 항목에 대해 양호합니다."
  fi
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE=$(cat <<EOF
자동 조치:
/etc/(r)syslog.conf 파일의 소유자를 root(또는 bin/sys는 유지)로 설정하고 권한을 640으로 변경합니다.
주의사항: 
일부 레거시 운영 스크립트나 관리 도구가 해당 설정 파일을 직접 수정·조회하는 환경에서는 권한 변경으로 접근 오류가 발생할 수 있으니 적용 전 사용 여부를 확인합니다.
EOF
)

REASON_LINE="${REASON_SENTENCE}"
DETAIL_PAYLOAD="${REASON_LINE}
${DETAIL_CONTENT}"

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_PAYLOAD",
  "target_file": "$TARGET_FILE",
  "guide": "$GUIDE_LINE"
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
