#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-02
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 비밀번호 관리정책 설정
# @Description : 패스워드 복잡성 및 유효기간 설정을 KISA 권고 수준으로 강화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-02"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PW_CONF="/etc/security/pwquality.conf"
PWH_CONF="/etc/security/pwhistory.conf"
LOGIN_DEFS="/etc/login.defs"

TARGET_FILE="$PW_CONF
$PWH_CONF
$LOGIN_DEFS"

CHECK_COMMAND="( [ -f /etc/security/pwquality.conf ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/security/pwquality.conf | grep -iE 'minlen|minclass|dcredit|ucredit|lcredit|ocredit|enforce_for_root' | tail -n 20 ); ( [ -f /etc/security/pwhistory.conf ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/security/pwhistory.conf | grep -iE 'remember|file|enforce_for_root' | tail -n 20 ); ( [ -f /etc/login.defs ] && grep -inE '^[[:space:]]*PASS_(MAX|MIN)_DAYS[[:space:]]+' /etc/login.defs | tail -n 5 )"

# 파라미터 설정 함수(pwquality/pwhistory: '=', login.defs: 공백)
set_param() {
  local file=$1
  local param=$2
  local val=$3
  local sep=$4

  if [ ! -f "$file" ]; then
    return 1
  fi

  if grep -qE "^[[:space:]]*#?[[:space:]]*${param}([[:space:]]*${sep}|[[:space:]]+)" "$file" 2>/dev/null; then
    if [ "$sep" = "=" ]; then
      sed -i -E "s|^[[:space:]]*#?[[:space:]]*${param}[[:space:]]*=.*|${param} = ${val}|I" "$file" 2>/dev/null
    else
      sed -i -E "s|^[[:space:]]*#?[[:space:]]*${param}[[:space:]]+.*|${param}   ${val}|I" "$file" 2>/dev/null
    fi
  else
    if [ "$sep" = "=" ]; then
      echo "${param} = ${val}" >> "$file"
    else
      echo "${param}   ${val}" >> "$file"
    fi
  fi

  return 0
}

# token(단독 라인) 보장 함수 (enforce_for_root)
ensure_token_line() {
  local file="$1"
  local token="$2"
  [ -f "$file" ] || return 1
  if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -Eq "^[[:space:]]*${token}[[:space:]]*$"; then
    return 0
  fi
  echo "$token" >> "$file"
  return 0
}

# 조치 수행
if [ -f "$PW_CONF" ]; then
  set_param "$PW_CONF" "minlen" "8" "="
  set_param "$PW_CONF" "minclass" "3" "="
  set_param "$PW_CONF" "dcredit" "-1" "="
  set_param "$PW_CONF" "ucredit" "-1" "="
  set_param "$PW_CONF" "lcredit" "-1" "="
  set_param "$PW_CONF" "ocredit" "-1" "="
  ensure_token_line "$PW_CONF" "enforce_for_root"
fi

if [ -f "$PWH_CONF" ]; then
  set_param "$PWH_CONF" "remember" "4" "="
  set_param "$PWH_CONF" "file" "/etc/security/opasswd" "="
  ensure_token_line "$PWH_CONF" "enforce_for_root"
fi

if [ -f "$LOGIN_DEFS" ]; then
  set_param "$LOGIN_DEFS" "PASS_MAX_DAYS" "90" "space"
  set_param "$LOGIN_DEFS" "PASS_MIN_DAYS" "1" "space"
fi

# 조치 후 상태 수집
PW_MINLEN=""
PW_MINCLASS=""
PW_DCREDIT=""
PW_UCREDIT=""
PW_LCREDIT=""
PW_OCREDIT=""
PW_ENFORCE="N"

PWH_REMEMBER=""
PWH_FILE=""
PWH_ENFORCE="N"

PASS_MAX_DAYS=""
PASS_MIN_DAYS=""

if [ -f "$PW_CONF" ]; then
  PW_MINLEN=$(grep -iE '^[[:space:]]*minlen[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_MINCLASS=$(grep -iE '^[[:space:]]*minclass[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_DCREDIT=$(grep -iE '^[[:space:]]*dcredit[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_UCREDIT=$(grep -iE '^[[:space:]]*ucredit[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_LCREDIT=$(grep -iE '^[[:space:]]*lcredit[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_OCREDIT=$(grep -iE '^[[:space:]]*ocredit[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$PW_CONF" 2>/dev/null | grep -Eq '^[[:space:]]*enforce_for_root[[:space:]]*$' && PW_ENFORCE="Y"
fi

if [ -f "$PWH_CONF" ]; then
  PWH_REMEMBER=$(grep -iE '^[[:space:]]*remember[[:space:]]*=' "$PWH_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PWH_FILE=$(grep -iE '^[[:space:]]*file[[:space:]]*=' "$PWH_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$PWH_CONF" 2>/dev/null | grep -Eq '^[[:space:]]*enforce_for_root[[:space:]]*$' && PWH_ENFORCE="Y"
fi

if [ -f "$LOGIN_DEFS" ]; then
  PASS_MAX_DAYS=$(grep -iE '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+' "$LOGIN_DEFS" 2>/dev/null | tail -n 1 | awk '{print $2}')
  PASS_MIN_DAYS=$(grep -iE '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$LOGIN_DEFS" 2>/dev/null | tail -n 1 | awk '{print $2}')
fi

DETAIL_CONTENT="minlen=$PW_MINLEN, minclass=$PW_MINCLASS, dcredit=$PW_DCREDIT, ucredit=$PW_UCREDIT, lcredit=$PW_LCREDIT, ocredit=$PW_OCREDIT, pwquality_enforce_for_root=$PW_ENFORCE, remember=$PWH_REMEMBER, pwhistory_file=$PWH_FILE, pwhistory_enforce_for_root=$PWH_ENFORCE, pass_max_days=$PASS_MAX_DAYS, pass_min_days=$PASS_MIN_DAYS"

# 결과 판정 및 REASON_LINE 구성
if [ -f "$PW_CONF" ] && [ -f "$PWH_CONF" ] && [ -f "$LOGIN_DEFS" ] \
   && [ "$PW_MINLEN" = "8" ] \
   && [ "$PW_DCREDIT" = "-1" ] && [ "$PW_UCREDIT" = "-1" ] && [ "$PW_LCREDIT" = "-1" ] && [ "$PW_OCREDIT" = "-1" ] \
   && [ "$PW_ENFORCE" = "Y" ] \
   && [ -n "$PWH_REMEMBER" ] && [ "$PWH_REMEMBER" -ge 4 ] 2>/dev/null \
   && [ "$PWH_FILE" = "/etc/security/opasswd" ] \
   && [ "$PWH_ENFORCE" = "Y" ] \
   && [ -n "$PASS_MAX_DAYS" ] && [ "$PASS_MAX_DAYS" -le 90 ] 2>/dev/null \
   && [ -n "$PASS_MIN_DAYS" ] && [ "$PASS_MIN_DAYS" -ge 1 ] 2>/dev/null; then
  IS_SUCCESS=1
  # 양호 시: 어떻게 바꿨는지 자연스럽게 연결
  REASON_LINE="패스워드 최소 길이 8자 이상, 4종류 문자 조합 사용, 루트 계정 강제 적용, 이전 패스워드 4개 기억 및 유효기간 90일 이하로 설정을 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  # 취약 시: 실패 원인 명시
  if [ ! -f "$PW_CONF" ] || [ ! -f "$PWH_CONF" ] || [ ! -f "$LOGIN_DEFS" ]; then
    REASON_LINE="패스워드 정책 관련 설정 파일이 시스템에 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  else
    REASON_LINE="필수 파라미터(minlen, dcredit, remember 등)의 설정 값이 가이드 기준에 미달하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF