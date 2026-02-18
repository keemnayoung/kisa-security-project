#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : 시스템 UMASK 값이 022 이상 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

## 기본 변수
ID="U-30"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

PROFILE_FILE="/etc/profile"
PROFILE_D_GLOB="/etc/profile.d/*.sh"
BASHRC_FILE="/etc/bashrc"
LOGIN_DEFS_FILE="/etc/login.defs"

TARGET_FILE="/etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/login.defs"

CHECK_COMMAND='
[ -f /etc/profile ] && grep -inE "^[[:space:]]*umask[[:space:]]+[0-9]+" /etc/profile || echo "/etc/profile:not_found";
ls -1 /etc/profile.d/*.sh 1>/dev/null 2>&1 && grep -inE "^[[:space:]]*umask[[:space:]]+[0-9]+" /etc/profile.d/*.sh || echo "/etc/profile.d/*.sh:not_found_or_no_matches";
[ -f /etc/bashrc ] && grep -inE "^[[:space:]]*umask[[:space:]]+[0-9]+" /etc/bashrc || echo "/etc/bashrc:not_found";
[ -f /etc/login.defs ] && grep -inE "^[[:space:]]*UMASK[[:space:]]+[0-9]+" /etc/login.defs || echo "/etc/login.defs:not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
FOUND_ANY="N"
FOUND_VULN="N"

FOUND_LIST=()

get_umask_from_file() {
  local file="$1"
  local mode="$2"  # lower=umask, upper=UMASK

  if [ ! -f "$file" ]; then
    return 0
  fi

  if [ "$mode" = "lower" ]; then
    local line lno val
    line=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$file" 2>/dev/null | tail -n 1)
    if [ -n "$line" ]; then
      lno=$(echo "$line" | cut -d: -f1)
      val=$(echo "$line" | awk '{print $2}')
      FOUND_LIST+=("${file}:${lno}:umask:${val}")
      FOUND_ANY="Y"
    fi
  else
    local line lno val
    line=$(grep -inE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' "$file" 2>/dev/null | tail -n 1)
    if [ -n "$line" ]; then
      lno=$(echo "$line" | cut -d: -f1)
      val=$(echo "$line" | awk '{print $2}')
      FOUND_LIST+=("${file}:${lno}:UMASK:${val}")
      FOUND_ANY="Y"
    fi
  fi
}

is_umask_ok() {
  local raw="$1"
  local v dec required

  v=$(echo "$raw" | grep -oE '^[0-9]+' || true)
  [ -z "$v" ] && return 1

  dec=$((8#$v))
  required=$((8#022))

  if [ $(( dec & required )) -eq "$required" ]; then
    return 0
  fi
  return 1
}

# 각 파일에서 마지막 설정(유효 라인 기준)을 수집합니다.
get_umask_from_file "$PROFILE_FILE" "lower"

if ls -1 $PROFILE_D_GLOB >/dev/null 2>&1; then
  for f in $PROFILE_D_GLOB; do
    get_umask_from_file "$f" "lower"
  done
fi

get_umask_from_file "$BASHRC_FILE" "lower"
get_umask_from_file "$LOGIN_DEFS_FILE" "upper"

# DETAIL_CONTENT는 양호/취약과 무관하게 현재 설정값 전체를 보여줍니다.
# reason(한 문장)은 양호면 양호 설정만, 취약이면 취약 설정(또는 미설정 상태)만 사용합니다.
if [ "$FOUND_ANY" = "N" ]; then
  STATUS="FAIL"
  FOUND_VULN="Y"

  # 취약 이유는 “설정이 확인되지 않음” 상태(취약 요소)만으로 1문장 구성
  REASON_LINE="/etc/profile, /etc/profile.d/*.sh, /etc/bashrc, /etc/login.defs에서 umask/UMASK 설정이 확인되지 않아 이 항목에 대해 취약합니다."

  # 현재 상태를 파일별로 보여줍니다.
  DETAIL_CONTENT="/etc/profile umask=not_set_or_file_missing\n/etc/profile.d/*.sh umask=not_set_or_no_matches\n/etc/bashrc umask=not_set_or_file_missing\n/etc/login.defs UMASK=not_set_or_file_missing"
else
  VULN_ITEMS=()
  OK_ITEMS=()
  ALL_ITEMS=()

  for item in "${FOUND_LIST[@]}"; do
    file=$(echo "$item" | cut -d: -f1)
    lno=$(echo "$item" | cut -d: -f2)
    key=$(echo "$item" | cut -d: -f3)
    val=$(echo "$item" | cut -d: -f4)

    ALL_ITEMS+=("${file}:${lno} ${key}=${val}")

    if is_umask_ok "$val"; then
      OK_ITEMS+=("${file}:${lno} ${key}=${val}")
    else
      FOUND_VULN="Y"
      VULN_ITEMS+=("${file}:${lno} ${key}=${val}")
    fi
  done

  # DETAIL_CONTENT: 현재 설정값 “전체”를 줄바꿈으로 보여줍니다.
  DETAIL_CONTENT=$(printf "%s\n" "${ALL_ITEMS[@]}" | sed ':a;N;$!ba;s/\n/\\n/g')

  if [ "$FOUND_VULN" = "Y" ]; then
    STATUS="FAIL"
    # 취약 이유는 취약 설정만 노출(요구사항)
    VULN_REASON=$(printf "%s; " "${VULN_ITEMS[@]}")
    REASON_LINE="${VULN_REASON}로 설정되어 있어 이 항목에 대해 취약합니다."
  else
    STATUS="PASS"
    # 양호 이유는 양호 설정만 노출(요구사항)
    OK_REASON=$(printf "%s; " "${OK_ITEMS[@]}")
    REASON_LINE="${OK_REASON}로 설정되어 있어 이 항목에 대해 양호합니다."
  fi

  # 위에서 DETAIL_CONTENT를 \n 문자열로 만들어뒀으니, 여기서는 실제 줄바꿈 형태로 다시 맞춥니다.
  # RAW_EVIDENCE 만들 때 최종적으로 \n escape를 다시 하므로, 내부 처리는 사람이 읽기 좋게 복원합니다.
  DETAIL_CONTENT=$(echo "$DETAIL_CONTENT" | sed 's/\\n/\n/g')
fi

# 취약 시 자동 조치 가정 가이드(주의사항 포함)
GUIDE_LINE="자동 조치:
/etc/profile과 /etc/login.defs(및 /etc/profile.d/*.sh,/etc/bashrc)에 약한 umask/UMASK 설정이 있으면 022(또는 더 제한적 값)으로 교정하고 마지막 적용 라인을 기준으로 재검증합니다.
주의사항:
일부 업무에서 그룹 공유 파일 생성/접근이 제한되어 경미한 권한 오류가 발생할 수 있으므로 운영 영향(공유 디렉터리/배포 스크립트 등)을 확인한 뒤 적용해야 합니다."

# raw_evidence 구성 (줄바꿈 유지 목적: detail/guide/command 모두 줄바꿈 가능한 구조)
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
