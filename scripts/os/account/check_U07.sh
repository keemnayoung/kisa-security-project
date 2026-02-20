#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-07
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 불필요한 계정 제거
# @Description : 시스템에 기본적으로 생성되어 있으나 사용하지 않는 계정(lp, uucp 등)의 존재 여부 점검
# @Criteria_Good : 불필요한 계정이 삭제되거나 잠금 설정된 경우
# @Criteria_Bad : 불필요한 계정이 활성화되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-07"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"

# 점검 명령
CHECK_COMMAND='[ -f /etc/passwd ] && egrep "^(lp|uucp|nuucp):" /etc/passwd || echo "passwd_not_found_or_no_matches"'

DETAIL_CONTENT=""
DETAIL_HEADER=""
GUIDE_LINE=""

DEFAULT_UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")
FOUND_ACCOUNTS=()

UNUSED_DAYS=90

NONLOGIN_SHELLS=(
  "/sbin/nologin"
  "/usr/sbin/nologin"
  "/bin/false"
  "/usr/bin/false"
)

DEFAULT_LOGINABLE_ACCOUNTS=()   # "user:shell"
DEFAULT_NONLOGIN_ACCOUNTS=()    # "user:shell"
UNUSED_INTERACTIVE_ACCOUNTS=()  # "user:uid:shell:lastlog_detail"
WARNINGS=()

is_nonlogin_shell() {
  local sh="$1"
  for s in "${NONLOGIN_SHELLS[@]}"; do
    [ "$sh" = "$s" ] && return 0
  done
  return 1
}

# 자동조치 위험 + 조치 방법
GUIDE_LINE="이 항목에 대해서 서비스 계정 또는 사용자 계정을 자동으로 삭제/잠금 처리할 경우 업무 서비스 장애, 인증 실패, 자동화 작업 중단, 권한 의존 서비스 오동작 등의 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 불필요 계정(lp/uucp/nuucp 등) 사용 여부를 검토하고, 불필요하면 삭제하거나 로그인 불가 쉘(/sbin/nologin 또는 /bin/false)로 변경해 주시기 바랍니다.
장기간 미사용으로 표시된 계정은 퇴직/휴직/전환 여부를 확인한 뒤 삭제 또는 잠금 처리하고, 조치 후 영향도(서비스/배치/권한)를 점검해 주시기 바랍니다."

# /etc/passwd 파일 존재 여부에 따라 점검 가능/불가를 결정
if [ -f "$TARGET_FILE" ]; then
    # 기본 불필요 계정(lp/uucp/nuucp) 존재 시 로그인 가능 여부(쉘)까지 수집
    for acc in "${DEFAULT_UNUSED_ACCOUNTS[@]}"; do
        if grep -q "^${acc}:" "$TARGET_FILE" 2>/dev/null; then
            FOUND_ACCOUNTS+=("$acc")
            shell="$(awk -F: -v u="$acc" '$1==u{print $7}' "$TARGET_FILE" 2>/dev/null | head -n 1)"
            [ -z "$shell" ] && shell="unknown"

            if is_nonlogin_shell "$shell"; then
                DEFAULT_NONLOGIN_ACCOUNTS+=("${acc}:${shell}")
            else
                DEFAULT_LOGINABLE_ACCOUNTS+=("${acc}:${shell}")
            fi
        fi
    done

    # lastlog 기반으로 장기간 미사용(UNUSED_DAYS) + 로그인 가능 계정 후보 수집
    if command -v lastlog >/dev/null 2>&1; then
        mapfile -t LL_USERS < <(lastlog -b "$UNUSED_DAYS" 2>/dev/null | awk 'NR>1 && $1!="" {print $1}' | sort -u)
        for u in "${LL_USERS[@]}"; do
            if ! grep -q "^${u}:" "$TARGET_FILE" 2>/dev/null; then
                continue
            fi
            uid="$(awk -F: -v user="$u" '$1==user{print $3}' "$TARGET_FILE" 2>/dev/null | head -n 1)"
            shell="$(awk -F: -v user="$u" '$1==user{print $7}' "$TARGET_FILE" 2>/dev/null | head -n 1)"
            [ -z "$uid" ] && continue
            [ -z "$shell" ] && shell="unknown"

            if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -ne 65534 ] 2>/dev/null; then
                if ! is_nonlogin_shell "$shell"; then
                    ll_detail="$(lastlog -u "$u" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]\+/ /g' | sed 's/^ //;s/ $//')"
                    [ -z "$ll_detail" ] && ll_detail="lastlog_detail_unavailable"
                    UNUSED_INTERACTIVE_ACCOUNTS+=("${u}:${uid}:${shell}:${ll_detail}")
                fi
            fi
        done
    else
        WARNINGS+=("lastlog_not_found")
        if ! command -v last >/dev/null 2>&1; then
            WARNINGS+=("last_not_found")
        fi
    fi

    DETAIL_CONTENT=$(
cat <<EOF
default_accounts_found=$(printf "%s" "$(printf "%s\n" "${FOUND_ACCOUNTS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd ',' -)" )
default_accounts_loginable=$(printf "%s" "$(printf "%s\n" "${DEFAULT_LOGINABLE_ACCOUNTS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd ',' -)" )
default_accounts_nonlogin=$(printf "%s" "$(printf "%s\n" "${DEFAULT_NONLOGIN_ACCOUNTS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd ',' -)" )
unused_days=$UNUSED_DAYS
unused_interactive_accounts_uid>=1000_loginable=$(printf "%s" "$(printf "%s\n" "${UNUSED_INTERACTIVE_ACCOUNTS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd '|' -)" )
nonlogin_shells=$(printf "%s" "$(printf "%s\n" "${NONLOGIN_SHELLS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd ',' -)" )
warnings=$(printf "%s" "$(printf "%s\n" "${WARNINGS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd ',' -)" )
EOF
)

    # PASS/FAIL 판정 및 “어떠한 이유”를 설정 값 기반으로 한 문장으로 구성
    if [ ${#DEFAULT_LOGINABLE_ACCOUNTS[@]} -gt 0 ] || [ ${#UNUSED_INTERACTIVE_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        VULN_DEFAULT="$(printf "%s\n" "${DEFAULT_LOGINABLE_ACCOUNTS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd ',' -)"
        VULN_UNUSED="$(printf "%s\n" "${UNUSED_INTERACTIVE_ACCOUNTS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd '|' -)"
        [ -z "$VULN_DEFAULT" ] && VULN_DEFAULT="(none)"
        [ -z "$VULN_UNUSED" ] && VULN_UNUSED="(none)"
        DETAIL_HEADER="default_accounts_loginable=${VULN_DEFAULT} unused_interactive_accounts_uid>=1000_loginable=${VULN_UNUSED}로 이 항목에 대해 취약합니다."
    else
        STATUS="PASS"
        GOOD_DEFAULT_NONLOGIN="$(printf "%s\n" "${DEFAULT_NONLOGIN_ACCOUNTS[@]}" 2>/dev/null | sed '/^$/d' | paste -sd ',' -)"
        [ -z "$GOOD_DEFAULT_NONLOGIN" ] && GOOD_DEFAULT_NONLOGIN="(none)"
        DETAIL_HEADER="default_accounts_loginable=(none) unused_interactive_accounts_uid>=1000_loginable=(none)이며 default_accounts_nonlogin=${GOOD_DEFAULT_NONLOGIN}로 이 항목에 대해 양호합니다."
    fi
else
    # /etc/passwd 미존재로 점검 불가 → 설정 값 기반으로 취약 판정
    STATUS="FAIL"
    DETAIL_CONTENT="target_file=${TARGET_FILE}
passwd_status=not_found"
    DETAIL_HEADER="target_file=${TARGET_FILE}가 존재하지 않아 이 항목에 대해 취약합니다."
fi

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_HEADER
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
