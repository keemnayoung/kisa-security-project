#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-12
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 세션 종료 시간 설정
# @Description : 사용자 셸에 대한 환경 설정 파일에서 세션 종료 시간 설정 여부 점검
# @Criteria_Good : 세션 종료 시간이 600초(10분) 이하로 설정되어 있는 경우
# @Criteria_Bad : 세션 종료 시간이 설정되지 않았거나 600초를 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-12"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 점검 대상(사용자 쉘 환경설정 파일)
TARGET_FILES=(
  "/etc/profile"
  "/etc/profile.d/*.sh"
  "/etc/bashrc"
)

TARGET_FILE="/etc/profile"

# 점검 명령
CHECK_COMMAND='grep -nEi "^[[:space:]]*TMOUT[[:space:]]*=" /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -nEv "^[[:space:]]*#" | head -n 5 || echo "tmout_not_found"'

DETAIL_CONTENT=""
GUIDE_LINE=""

TMOUT_VAL="not_set"
TMOUT_FOUND_LINE=""
EXPORT_FOUND="no"

FOUND_ANY_FILE="no"
CANDIDATE_LINES=()

for pattern in "${TARGET_FILES[@]}"; do
  for f in $pattern; do
    [ -e "$f" ] || continue
    FOUND_ANY_FILE="yes"

    if grep -nE '^[[:space:]]*(export[[:space:]]+TMOUT|typeset[[:space:]]+-x[[:space:]]+TMOUT)\b' "$f" 2>/dev/null | grep -qEv '^[[:space:]]*#'; then
      EXPORT_FOUND="yes"
    fi

    while IFS= read -r line; do
      [ -n "$line" ] && CANDIDATE_LINES+=("$f:$line")
    done < <(grep -nEi '^[[:space:]]*TMOUT[[:space:]]*=' "$f" 2>/dev/null | grep -Ev '^[[:space:]]*#')
  done
done

if [ "${#CANDIDATE_LINES[@]}" -gt 0 ]; then
  TMOUT_FOUND_LINE="${CANDIDATE_LINES[-1]}"
  TMOUT_VAL=$(echo "$TMOUT_FOUND_LINE" \
    | sed 's/.*TMOUT[[:space:]]*=[[:space:]]*//I' \
    | sed 's/[^0-9].*$//')
  [ -z "$TMOUT_VAL" ] && TMOUT_VAL="not_set"
fi

# TMOUT/EXPORT 설정 상태에 따라 상태 판정
if [ "$TMOUT_VAL" != "not_set" ] && echo "$TMOUT_VAL" | grep -qE '^[0-9]+$' && [ "$TMOUT_VAL" -gt 0 ] && [ "$TMOUT_VAL" -le 600 ] && [ "$EXPORT_FOUND" = "yes" ]; then
  STATUS="PASS"
else
  STATUS="FAIL"
fi

# 분기: 현재 설정값(양호/취약 공통)만 DETAIL_CONTENT에 기록
if [ -n "$TMOUT_FOUND_LINE" ]; then
  DETAIL_CONTENT="tmout_last_line=$TMOUT_FOUND_LINE"$'\n'"tmout_value=$TMOUT_VAL"$'\n'"export_tmout=$EXPORT_FOUND"
else
  DETAIL_CONTENT="tmout_last_line=not_found"$'\n'"tmout_value=$TMOUT_VAL"$'\n'"export_tmout=$EXPORT_FOUND"
fi

# 양호: 만족하는 설정값(T MOUT 값 + export 적용)을 이유로 사용
# 취약: 취약한 부분의 설정만 이유로 사용(미설정/범위초과/미export/점검불가)
if [ "$STATUS" = "PASS" ]; then
  DETAIL_HEAD="TMOUT=$TMOUT_VAL 및 export TMOUT가 적용되어 이 항목에 대해 양호합니다."
else
  if [ "$FOUND_ANY_FILE" = "no" ]; then
    DETAIL_HEAD="/etc/profile, /etc/profile.d/*.sh, /etc/bashrc를 확인할 수 없어 이 항목에 대해 취약합니다."
  elif [ "$TMOUT_VAL" = "not_set" ]; then
    DETAIL_HEAD="TMOUT 설정이 확인되지 않아 이 항목에 대해 취약합니다."
  elif ! echo "$TMOUT_VAL" | grep -qE '^[0-9]+$'; then
    DETAIL_HEAD="TMOUT=$TMOUT_VAL 로 확인되어 이 항목에 대해 취약합니다."
  elif [ "$TMOUT_VAL" -le 0 ] || [ "$TMOUT_VAL" -gt 600 ]; then
    DETAIL_HEAD="TMOUT=$TMOUT_VAL 로 설정되어 이 항목에 대해 취약합니다."
  elif [ "$EXPORT_FOUND" != "yes" ]; then
    DETAIL_HEAD="export TMOUT가 적용되지 않아 이 항목에 대해 취약합니다."
  else
    DETAIL_HEAD="TMOUT 및 export TMOUT 설정이 기준을 충족하지 않아 이 항목에 대해 취약합니다."
  fi
fi

# 취약 가정 자동 조치
GUIDE_LINE="자동 조치:
/etc/profile에서 TMOUT 관련 설정을 정리한 뒤 TMOUT=600과 export TMOUT를 추가하여 일괄 적용합니다.
주의사항: 
전역 세션 타임아웃이 모든 사용자/자동화 작업에 적용되어 장시간 무입력 작업(모니터링, 배치, 유지보수 세션 등)이 예기치 않게 종료될 수 있습니다.
/etc/profile.d/*.sh 또는 /etc/bashrc에 TMOUT override가 남아있으면 최종 적용값이 덮어써질 수 있으므로 함께 점검·정리해야 합니다."

# raw_evidence 구성(모든 값은 문장 단위 줄바꿈 유지)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_HEAD\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "/etc/profile\n/etc/profile.d/*.sh\n/etc/bashrc"
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
