#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-04
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 비밀번호 파일 보호
# @Description : /etc/passwd 파일의 패스워드 암호화 및 /etc/shadow 파일 사용 여부 점검
# @Criteria_Good : 상용 시스템에서 쉐도우 패스워드 정책을 사용하는 경우
# @Criteria_Bad : 쉐도우 패스워드 정책을 사용하지 않고 패스워드가 노출되는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-04"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
TARGET_FILE="$PASSWD_FILE $SHADOW_FILE"

# 점검 명령(참고 출력용)
CHECK_COMMAND='[ -f /etc/passwd ] && awk -F: '\''$2 != "x" && $2 !~ /^(\!|\*)+$/ {print $1 ":" $2}'\'' /etc/passwd || echo "passwd_not_found"; [ -f /etc/shadow ] && echo "shadow_exists" || echo "shadow_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""

UNSHADOWED_USERS=""
PASSWD_FIELDS=""
SHADOW_STATE=""

# 현재 설정값 수집(항상 DETAIL_CONTENT에 포함)
if [ -f "$PASSWD_FILE" ]; then
  PASSWD_FIELDS="$(awk -F: '{print $1 ":" $2}' "$PASSWD_FILE" 2>/dev/null | head -n 200)"
else
  PASSWD_FIELDS="passwd_not_found"
fi

if [ -f "$SHADOW_FILE" ]; then
  SHADOW_STATE="shadow_exists"
else
  SHADOW_STATE="shadow_not_found"
fi

# 파일 존재 여부에 따른 분기
if [ -f "$PASSWD_FILE" ] && [ -f "$SHADOW_FILE" ]; then
  # /etc/passwd 2필드가 x가 아니면서 !/* 계열이 아닌 계정만 취약 후보로 수집
  UNSHADOWED_USERS="$(awk -F: '$2 != "x" && $2 !~ /^(\!|\*)+$/ {print $1 ":" $2}' "$PASSWD_FILE" 2>/dev/null | head -n 200)"

  if [ -z "$UNSHADOWED_USERS" ]; then
    STATUS="PASS"
    # 설정 값만 이용해 “양호” 사유 문장을 한 줄로 구성
    REASON_LINE="모든 계정의 /etc/passwd 두 번째 필드가 x 또는 !/* 로 설정되어 있어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    # 취약일 때는 “취약한 설정”만 사유에 포함(한 줄)
    OFFENDING_ONE_LINE="$(echo "$UNSHADOWED_USERS" | head -n 20 | tr '\n' ',' | sed 's/,$//')"
    [ -z "$OFFENDING_ONE_LINE" ] && OFFENDING_ONE_LINE="unshadowed_users_found"
    REASON_LINE="/etc/passwd 두 번째 필드가 x가 아닌 값(예: ${OFFENDING_ONE_LINE})으로 설정되어 있어 이 항목에 대해 취약합니다."
  fi
else
  STATUS="FAIL"
  # 파일 부재 분기: “현재 상태(설정)”만으로 사유를 한 줄로 구성
  if [ ! -f "$PASSWD_FILE" ] && [ ! -f "$SHADOW_FILE" ]; then
    REASON_LINE="/etc/passwd 없음 및 /etc/shadow 없음 상태로 설정되어 있어 이 항목에 대해 취약합니다."
  elif [ ! -f "$PASSWD_FILE" ]; then
    REASON_LINE="/etc/passwd 없음 상태로 설정되어 있어 이 항목에 대해 취약합니다."
  else
    REASON_LINE="/etc/shadow 없음 상태로 설정되어 있어 이 항목에 대해 취약합니다."
  fi
fi

# DETAIL_CONTENT는 양호/취약과 관계 없이 현재 설정값만 표시
# - passwd 2필드 전체(상위 200)
# - shadow 존재 여부
# - 취약 후보(user:2field) 목록(상위 200, 없으면 none)
DETAIL_CONTENT=$(cat <<EOF
shadow_file=$SHADOW_STATE
passwd_second_field(user:field2)
$PASSWD_FIELDS
unshadowed_candidates(user:field2)
${UNSHADOWED_USERS:-none}
EOF
)

# 자동 조치 가이드(취약 시 조치를 가정한 설명 + 주의사항)
GUIDE_LINE=$(cat <<'EOF'
자동 조치:
/etc/passwd 및 /etc/shadow를 /var/tmp 경로에 타임스탬프로 백업한 뒤 pwconv를 실행하여 /etc/passwd의 비밀번호 필드를 x로 정규화하고 /etc/shadow에 해시를 분리 저장합니다.
조치 후 /etc/passwd의 두 번째 필드가 x 또는 !/* 인지 재점검하여 잔여 계정이 있으면 실패로 처리합니다.
주의사항:
파일 편집/동시 작업 중 자동 조치를 수행하면 계정 DB 불일치가 발생할 수 있으므로 조치 전 사용자/프로세스 변경 작업을 최소화하고 백업 파일로 즉시 원복 가능하도록 준비합니다.
특정 계정의 비정상 패스워드 필드가 강제로 정리되면 로그인이 제한될 수 있어 운영 계정은 사전 영향도 확인이 필요합니다.
EOF
)

# raw_evidence 구성(detail은 한 문장 + 줄바꿈 + 현재 설정값)
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
