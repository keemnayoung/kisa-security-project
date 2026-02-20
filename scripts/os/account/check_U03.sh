#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-03
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 계정 잠금 임계값 설정
# @Description : 계정 탈취 공격(Brute Force 등) 방지를 위한 잠금 임계값 설정 여부 점검
# @Criteria_Good : 계정 잠금 임계값이 10회 이하로 설정된 경우
# @Criteria_Bad : 계정 잠금 임계값이 설정되지 않았거나 10회를 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-03"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/security/faillock.conf"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

# 점검 명령
CHECK_COMMAND="faillock.conf(deny/unlock_time), PAM(system-auth/password-auth)에서 pam_faillock/pam_tally(2) 적용 및 deny 값 확인, authselect with-faillock 여부 확인"

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE=""

DENY_FROM_FAILLOCK_CONF=""
UNLOCK_FROM_FAILLOCK_CONF=""
DENY_FROM_PAM=""
UNLOCK_FROM_PAM=""
PAM_MODULE_STATUS="not_checked"
AUTHSELECT_WITH_FAILLOCK="unknown"

EFFECTIVE_DENY=""
EFFECTIVE_UNLOCK=""
EFFECTIVE_SOURCE=""

trim() { sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

extract_conf_kv_last() {
  local file="$1"
  local key="$2"
  grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
    | sed 's/#.*$//' \
    | grep -E "^[[:space:]]*${key}[[:space:]]*=" \
    | tail -n 1 \
    | cut -d'=' -f2- \
    | trim
}

extract_pam_param_last() {
  local file="$1"
  local param="$2"
  grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
    | sed 's/#.*$//' \
    | grep -E 'pam_faillock\.so|pam_tally2\.so|pam_tally\.so' \
    | grep -E "${param}=" \
    | sed -nE "s/.*${param}=([0-9]+).*/\1/p" \
    | tail -n 1 \
    | trim
}

pam_has_lock_module() {
  local file="$1"
  grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
    | sed 's/#.*$//' \
    | grep -Eq 'pam_faillock\.so|pam_tally2\.so|pam_tally\.so'
}

# authselect 설치 여부에 따라 with-faillock 기능 활성 상태 확인
if command -v authselect >/dev/null 2>&1; then
  if authselect current 2>/dev/null | grep -Eq 'with-faillock'; then
    AUTHSELECT_WITH_FAILLOCK="enabled"
  else
    AUTHSELECT_WITH_FAILLOCK="disabled_or_unknown"
  fi
else
  AUTHSELECT_WITH_FAILLOCK="not_installed"
fi

# faillock.conf 파일 존재 여부에 따라 deny/unlock_time 값 수집
if [ -f "$TARGET_FILE" ]; then
  DENY_FROM_FAILLOCK_CONF="$(extract_conf_kv_last "$TARGET_FILE" "deny")"
  UNLOCK_FROM_FAILLOCK_CONF="$(extract_conf_kv_last "$TARGET_FILE" "unlock_time")"
else
  DENY_FROM_FAILLOCK_CONF="file_not_found"
  UNLOCK_FROM_FAILLOCK_CONF="file_not_found"
fi

# PAM 설정 파일(system-auth/password-auth)에서 잠금 모듈 적용 여부 및 deny/unlock_time 값을 수집
PAM_APPLIED="no"
PAM_FILES_EXIST="yes"

if [ ! -f "$PAM_SYSTEM_AUTH" ] && [ ! -f "$PAM_PASSWORD_AUTH" ]; then
  PAM_FILES_EXIST="no"
else
  if [ -f "$PAM_SYSTEM_AUTH" ] && pam_has_lock_module "$PAM_SYSTEM_AUTH"; then
    PAM_APPLIED="yes"
  fi
  if [ -f "$PAM_PASSWORD_AUTH" ] && pam_has_lock_module "$PAM_PASSWORD_AUTH"; then
    PAM_APPLIED="yes"
  fi
fi

if [ -f "$PAM_SYSTEM_AUTH" ]; then
  d1="$(extract_pam_param_last "$PAM_SYSTEM_AUTH" "deny")"
  u1="$(extract_pam_param_last "$PAM_SYSTEM_AUTH" "unlock_time")"
fi
if [ -f "$PAM_PASSWORD_AUTH" ]; then
  d2="$(extract_pam_param_last "$PAM_PASSWORD_AUTH" "deny")"
  u2="$(extract_pam_param_last "$PAM_PASSWORD_AUTH" "unlock_time")"
fi

if [ -n "${d2:-}" ]; then
  DENY_FROM_PAM="$d2"
elif [ -n "${d1:-}" ]; then
  DENY_FROM_PAM="$d1"
else
  DENY_FROM_PAM="not_set"
fi

if [ -n "${u2:-}" ]; then
  UNLOCK_FROM_PAM="$u2"
elif [ -n "${u1:-}" ]; then
  UNLOCK_FROM_PAM="$u1"
else
  UNLOCK_FROM_PAM="not_set"
fi

if [ "$PAM_FILES_EXIST" = "no" ]; then
  PAM_MODULE_STATUS="pam_files_not_found"
elif [ "$PAM_APPLIED" = "yes" ]; then
  PAM_MODULE_STATUS="applied"
else
  PAM_MODULE_STATUS="not_applied"
fi

# PAM 인자에 deny/unlock_time이 있으면 그 값을 우선, 없으면 faillock.conf 값을 사용해 실효값 결정
if is_int "$DENY_FROM_PAM"; then
  EFFECTIVE_DENY="$DENY_FROM_PAM"
  EFFECTIVE_SOURCE="pam"
elif is_int "$DENY_FROM_FAILLOCK_CONF"; then
  EFFECTIVE_DENY="$DENY_FROM_FAILLOCK_CONF"
  EFFECTIVE_SOURCE="faillock.conf"
else
  EFFECTIVE_DENY="not_set"
  EFFECTIVE_SOURCE="none"
fi

if is_int "$UNLOCK_FROM_PAM"; then
  EFFECTIVE_UNLOCK="$UNLOCK_FROM_PAM"
elif is_int "$UNLOCK_FROM_FAILLOCK_CONF"; then
  EFFECTIVE_UNLOCK="$UNLOCK_FROM_FAILLOCK_CONF"
else
  EFFECTIVE_UNLOCK="not_set"
fi

DENY_OK="no"
UNLOCK_OK="no"
PAM_OK="no"

if [ "$PAM_MODULE_STATUS" = "applied" ]; then
  PAM_OK="yes"
fi

if is_int "$EFFECTIVE_DENY" && [ "$EFFECTIVE_DENY" -ge 1 ] && [ "$EFFECTIVE_DENY" -le 10 ]; then
  DENY_OK="yes"
fi

if is_int "$EFFECTIVE_UNLOCK" && [ "$EFFECTIVE_UNLOCK" -ge 1 ]; then
  UNLOCK_OK="yes"
fi

DETAIL_CONTENT=$(cat <<EOF
authselect_with_faillock=$AUTHSELECT_WITH_FAILLOCK
pam_module_status=$PAM_MODULE_STATUS
faillock_conf_deny=${DENY_FROM_FAILLOCK_CONF}
faillock_conf_unlock_time=${UNLOCK_FROM_FAILLOCK_CONF}
pam_deny=${DENY_FROM_PAM}
pam_unlock_time=${UNLOCK_FROM_PAM}
effective_source=${EFFECTIVE_SOURCE}
effective_deny=${EFFECTIVE_DENY}
effective_unlock_time=${EFFECTIVE_UNLOCK}
EOF
)

# 취약/양호에 따라 reason 구성
if [ "$PAM_OK" = "yes" ] && [ "$DENY_OK" = "yes" ] && [ "$UNLOCK_OK" = "yes" ]; then
  STATUS="PASS"
  REASON_LINE="pam_module_status=${PAM_MODULE_STATUS}, effective_deny=${EFFECTIVE_DENY}, effective_unlock_time=${EFFECTIVE_UNLOCK} 로 설정되어 있어 이 항목에 대해 양호합니다."
else
  STATUS="FAIL"
  VULN_PARTS=()

  if [ "$PAM_OK" != "yes" ]; then
    VULN_PARTS+=("pam_module_status=${PAM_MODULE_STATUS}")
  fi
  if [ "$DENY_OK" != "yes" ]; then
    VULN_PARTS+=("effective_deny=${EFFECTIVE_DENY}")
  fi
  if [ "$UNLOCK_OK" != "yes" ]; then
    VULN_PARTS+=("effective_unlock_time=${EFFECTIVE_UNLOCK}")
  fi

  REASON_LINE="$(IFS=', '; echo "${VULN_PARTS[*]}") 로 설정되어 있어 이 항목에 대해 취약합니다."
fi

# 자동 조치 가이드
GUIDE_LINE=$(cat <<EOF
자동 조치:
/etc/security/faillock.conf 파일을 백업한 뒤 deny=10, unlock_time=120 값을 설정합니다.
authselect가 구성되어 있으면 with-faillock 기능을 활성화하고 적용합니다.
authselect가 구성되어 있지 않으면 /etc/pam.d/system-auth 및 /etc/pam.d/password-auth에 pam_faillock.so 설정을 추가합니다.
주의사항:
PAM 설정을 잘못 적용하면 로그인/인증이 실패할 수 있으므로 콘솔 접속 또는 스냅샷 환경에서 사전 테스트 후 적용해야 합니다.
system-auth/password-auth를 직접 수정하는 경우 배포/정책 도구(authselect 등)로 인해 설정이 덮어써질 수 있어 운영 정책과 충돌 여부를 확인해야 합니다.
EOF
)

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE, $PAM_SYSTEM_AUTH, $PAM_PASSWORD_AUTH"
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
