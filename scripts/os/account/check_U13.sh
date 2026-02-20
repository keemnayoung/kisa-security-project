#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-13
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : 비밀번호 저장 시 안전한 암호화 알고리즘 사용 여부 점검
# @Criteria_Good : SHA-2 이상(예: SHA-256, SHA-512) 또는 yescrypt 적용
# @Criteria_Bad : 취약 알고리즘 사용 또는 설정 미비
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-13"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

DEFS_FILE="/etc/login.defs"
SHADOW_FILE="/etc/shadow"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

TARGET_FILE="$DEFS_FILE $SHADOW_FILE $PAM_SYSTEM_AUTH $PAM_PASSWORD_AUTH"

# 점검에 사용한 커맨드(대시보드 표시용)
CHECK_COMMAND='
[ -f /etc/login.defs ] && grep -Ei "^[[:space:]]*ENCRYPT_METHOD[[:space:]]+" /etc/login.defs | tail -n 1 || echo "login.defs_not_found";
[ -f /etc/shadow ] && awk -F: '\''$2 ~ /^\$/ {print $1 ":" $2}'\'' /etc/shadow | head -n 5 || echo "shadow_not_found";
[ -f /etc/pam.d/system-auth ] && grep -E "^[[:space:]]*password[[:space:]]+.*pam_unix\.so" /etc/pam.d/system-auth || echo "system-auth_not_found_or_no_pam_unix";
[ -f /etc/pam.d/password-auth ] && grep -E "^[[:space:]]*password[[:space:]]+.*pam_unix\.so" /etc/pam.d/password-auth || echo "password-auth_not_found_or_no_pam_unix"
'

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE=""

ENCRYPT_METHOD=""
INVALID_ALGO_ACCOUNTS=""
SYS_PAM_RES=""
PASS_PAM_RES=""

# PAM 파일에서 pam_unix.so password 라인에 안전 옵션(sha512/sha256/yescrypt) 존재 여부 확인
check_pam_file() {
  local file="$1"
  local lines=""

  if [ ! -f "$file" ]; then
    echo "NOT_FOUND"
    return
  fi

  lines=$(grep -E '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$file" 2>/dev/null)
  if [ -z "$lines" ]; then
    echo "NO_PAM_UNIX"
    return
  fi

  if echo "$lines" | grep -Eqi '(^|[[:space:]])(sha512|sha256|yescrypt)($|[[:space:]])'; then
    echo "OK"
  else
    echo "WEAK"
  fi
}

# 필수 파일 누락 여부 확인(누락 시 FAIL)
MISSING_FILES=""
[ -f "$DEFS_FILE" ] || MISSING_FILES="${MISSING_FILES}login.defs_not_found"$'\n'
[ -f "$SHADOW_FILE" ] || MISSING_FILES="${MISSING_FILES}shadow_not_found"$'\n'
[ -f "$PAM_SYSTEM_AUTH" ] || MISSING_FILES="${MISSING_FILES}system-auth_not_found"$'\n'

if [ -n "$MISSING_FILES" ]; then
  STATUS="FAIL"

  # 취약 사유(설정값만 포함)
  REASON_SETTINGS="missing_files=$(printf "%s" "$MISSING_FILES" | sed '/^$/d' | tr '\n' ',' | sed 's/,$//')"
  REASON_LINE="${REASON_SETTINGS}로 이 항목에 대해 취약합니다."

  # 현재 설정값(확인 불가 상태 포함)
  DETAIL_CONTENT="$(printf "%s" "$MISSING_FILES" | sed '/^$/d')"

  # 취약 가정 자동 조치
  GUIDE_LINE="/etc/login.defs에 ENCRYPT_METHOD를 SHA512로 설정합니다.
/etc/pam.d/system-auth(및 존재 시 password-auth)의 pam_unix.so password 라인에 sha512 옵션을 적용합니다."
else
  # /etc/login.defs에서 ENCRYPT_METHOD 값 수집
  ENCRYPT_METHOD=$(grep -Ei '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null | awk '{print $2}' | tail -n 1)

  # /etc/shadow에서 안전 접두어($5$/$6$/$y$) 외 사용 계정 수집
  INVALID_ALGO_ACCOUNTS=$(awk -F: '
    $2 ~ /^\$/ && $2 !~ /^\$5\$/ && $2 !~ /^\$6\$/ && $2 !~ /^\$y\$/ {print $1}
  ' "$SHADOW_FILE" 2>/dev/null)

  # PAM 설정 점검(system-auth 필수, password-auth는 존재 시 점검)
  SYS_PAM_RES=$(check_pam_file "$PAM_SYSTEM_AUTH")
  PASS_PAM_RES=$(check_pam_file "$PAM_PASSWORD_AUTH")

  # 현재 설정값만 DETAIL_CONTENT에 기록
  DETAIL_CONTENT="ENCRYPT_METHOD=${ENCRYPT_METHOD:-not_set}"$'\n'

  if [ -z "$INVALID_ALGO_ACCOUNTS" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}shadow_hash_prefix=only_\$5\$_\$6\$_\$y\$"$'\n'
  else
    DETAIL_CONTENT="${DETAIL_CONTENT}shadow_weak_accounts="$'\n'"$(printf "%s\n" "$INVALID_ALGO_ACCOUNTS" | sed 's/[[:space:]]*$//')"$'\n'
  fi

  DETAIL_CONTENT="${DETAIL_CONTENT}pam_system-auth=$SYS_PAM_RES"$'\n'
  if [ -f "$PAM_PASSWORD_AUTH" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}pam_password-auth=$PASS_PAM_RES"$'\n'
  else
    DETAIL_CONTENT="${DETAIL_CONTENT}pam_password-auth=not_found(skip)"$'\n'
  fi

  # 판정용 플래그 계산
  DEFS_OK="N"
  if [ -n "$ENCRYPT_METHOD" ] && echo "$ENCRYPT_METHOD" | grep -Eqi '^(SHA256|SHA512|YESCRYPT)$'; then
    DEFS_OK="Y"
  fi

  PAM_OK="Y"
  [ "$SYS_PAM_RES" = "OK" ] || PAM_OK="N"
  if [ -f "$PAM_PASSWORD_AUTH" ] && [ "$PASS_PAM_RES" != "OK" ]; then
    PAM_OK="N"
  fi

  SHADOW_OK="Y"
  [ -z "$INVALID_ALGO_ACCOUNTS" ] || SHADOW_OK="N"

  # 최종 판정 분기
  if [ "$DEFS_OK" = "Y" ] && [ "$PAM_OK" = "Y" ] && [ "$SHADOW_OK" = "Y" ]; then
    STATUS="PASS"
    REASON_SETTINGS="ENCRYPT_METHOD=${ENCRYPT_METHOD:-not_set}, pam_system-auth=$SYS_PAM_RES, shadow_prefix=only_\$5\$_\$6\$_\$y\$"
    REASON_LINE="${REASON_SETTINGS}로 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"

    # 취약 사유
    REASON_SETTINGS=""
    if [ "$DEFS_OK" != "Y" ]; then
      REASON_SETTINGS="ENCRYPT_METHOD=${ENCRYPT_METHOD:-not_set}"
    fi
    if [ "$PAM_OK" != "Y" ]; then
      if [ -n "$REASON_SETTINGS" ]; then REASON_SETTINGS="${REASON_SETTINGS}, "; fi
      if [ -f "$PAM_PASSWORD_AUTH" ]; then
        REASON_SETTINGS="${REASON_SETTINGS}pam_system-auth=$SYS_PAM_RES, pam_password-auth=$PASS_PAM_RES"
      else
        REASON_SETTINGS="${REASON_SETTINGS}pam_system-auth=$SYS_PAM_RES"
      fi
    fi
    if [ "$SHADOW_OK" != "Y" ]; then
      if [ -n "$REASON_SETTINGS" ]; then REASON_SETTINGS="${REASON_SETTINGS}, "; fi
      REASON_SETTINGS="${REASON_SETTINGS}shadow_weak_accounts=$(printf "%s" "$INVALID_ALGO_ACCOUNTS" | tr '\n' ',' | sed 's/,$//')"
    fi

    REASON_LINE="${REASON_SETTINGS}로 이 항목에 대해 취약합니다."

    # 취약 가정 자동 조치
    GUIDE_LINE="자동 조치:
/etc/login.defs에 ENCRYPT_METHOD를 SHA512로 설정합니다.
/etc/pam.d/system-auth(및 존재 시 password-auth)의 pam_unix.so password 라인에 sha512 옵션을 적용합니다.
주의사항: 
PAM 설정 오타나 비정상 편집은 인증 실패를 유발할 수 있어 적용 전 백업과 점검이 필요합니다.
ENCRYPT_METHOD 변경은 신규 비밀번호부터 적용되며 기존 계정은 비밀번호 재설정이 없으면 해시가 유지될 수 있습니다."
  fi
fi

# raw_evidence 구성
DETAIL_FIELD="${REASON_LINE}"$'\n'"${DETAIL_CONTENT}"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_FIELD",
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
