#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-11
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 사용자 shell 점검
# @Description : 로그인이 필요하지 않은 시스템 계정에 로그인 제한 쉘이 설정되어 있는지 점검
# @Criteria_Good : 로그인이 불필요한 계정에 nologin 또는 false 쉘이 설정된 경우
# @Criteria_Bad : 로그인이 불필요한 계정에 bash, sh 등 로그인 가능한 쉘이 설정된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-11"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='[ -f /etc/passwd ] && egrep "^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher):" /etc/passwd || echo "passwd_not_found_or_no_targets"'

REASON_LINE=""
DETAIL_CONTENT=""

VULN_ACCOUNTS=()
CURRENT_SETTINGS=()

# 점검 대상 시스템 계정 목록
SYSTEM_ACCOUNTS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

# 허용 로그인 제한 쉘 목록
ALLOWED_SHELLS=("/bin/false" "/sbin/nologin" "/usr/sbin/nologin")

is_allowed_shell() {
  local shell="$1"
  for a in "${ALLOWED_SHELLS[@]}"; do
    [ "$shell" = "$a" ] && return 0
  done
  return 1
}

# guide 값(취약 조치 상황 가정)
GUIDE_LINE=$(cat <<'EOF'
자동 조치: 
로그인이 불필요한 시스템 계정의 로그인 쉘을 시스템에 존재하는 nologin 경로(/sbin/nologin 또는 /usr/sbin/nologin, 미존재 시 /bin/false)로 변경합니다.
주의사항: 
일부 환경에서는 서비스 계정이 운영/점검 목적으로 쉘을 사용하도록 구성될 수 있어, 쉘 변경 시 계정 기반 작업 흐름에 영향을 줄 수 있으므로 변경 전 계정 사용 여부를 확인해야 합니다.
EOF
)

# /etc/passwd 존재 여부에 따라 점검 분기
if [ -f "$TARGET_FILE" ]; then
  # 대상 계정이 /etc/passwd에 존재하는 경우에만 현재 쉘을 수집
  for acc in "${SYSTEM_ACCOUNTS[@]}"; do
    LINE=$(grep "^${acc}:" "$TARGET_FILE" 2>/dev/null)
    if [ -n "$LINE" ]; then
      CURRENT_SHELL=$(echo "$LINE" | awk -F: '{print $NF}')
      CURRENT_SETTINGS+=("${acc}:${CURRENT_SHELL}")

      # 허용 쉘이 아니면 취약 계정으로 분류
      if ! is_allowed_shell "$CURRENT_SHELL"; then
        VULN_ACCOUNTS+=("${acc}:${CURRENT_SHELL}")
      fi
    fi
  done

  # DETAIL_CONTENT는 양호/취약과 무관하게 현재 설정값만 출력
  if [ ${#CURRENT_SETTINGS[@]} -gt 0 ]; then
    DETAIL_CONTENT="$(printf "%s\n" "${CURRENT_SETTINGS[@]}")"
  else
    DETAIL_CONTENT="no_target_accounts_found_in_passwd"
  fi

  # 점검 결과 분기
  if [ ${#VULN_ACCOUNTS[@]} -gt 0 ]; then
    STATUS="FAIL"
    VULN_ONE_LINE="$(printf "%s, " "${VULN_ACCOUNTS[@]}")"
    VULN_ONE_LINE="${VULN_ONE_LINE%, }"
    REASON_LINE="${VULN_ONE_LINE}로 설정되어 있어 이 항목에 대해 취약합니다."
  else
    STATUS="PASS"
    ALLOW_ONE_LINE="$(printf "%s, " "${ALLOWED_SHELLS[@]}")"
    ALLOW_ONE_LINE="${ALLOW_ONE_LINE%, }"
    REASON_LINE="대상 시스템 계정의 쉘이 ${ALLOW_ONE_LINE} 중 하나로 설정되어 있어 이 항목에 대해 양호합니다."
  fi
else
  # /etc/passwd가 없으면 설정값 확인 자체가 불가하므로 취약으로 판단
  STATUS="FAIL"
  REASON_LINE="${TARGET_FILE} 파일이 존재하지 않아 설정 값을 확인할 수 있어 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="passwd_not_found"
fi

# raw_evidence 구성 (각 값은 줄바꿈으로 구분되도록 구성)
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
