#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-14
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : root 계정의 PATH 환경변수에 “.”(마침표)이 포함 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

# 기본 변수
ID="U-14"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="su - root -c 'echo \$PATH'"

# root 계정의 로그인 쉘 확인
ROOT_SHELL=$(getent passwd root | cut -d: -f7)
SHELL_NAME=$(basename "$ROOT_SHELL")

TARGET_FILES=()

# 쉘 종류에 따른 점검 대상 파일
case "$SHELL_NAME" in
  sh)
    TARGET_FILES=(/etc/profile /root/.profile)
    ;;
  csh)
    TARGET_FILES=(/etc/csh.cshrc /etc/csh.login /root/.cshrc /root/.login)
    ;;
  ksh)
    TARGET_FILES=(/etc/profile /root/.profile /root/.kshrc)
    ;;
  bash)
    TARGET_FILES=(/etc/profile /etc/bash.bashrc /root/.bash_profile /root/.bashrc)
    ;;
  *)
    # 예상하지 못한 쉘인 경우에도 최소한의 파일은 확인
    TARGET_FILES=(/etc/profile /root/.profile)
    ;;
esac

TARGET_FILE="$(printf "%s, " "${TARGET_FILES[@]}")"
TARGET_FILE="${TARGET_FILE%, }"

# 실제 root 로그인 기준의 최종 PATH 값 수집
ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)

IFS=':' read -ra PATH_ITEMS <<< "$ROOT_PATH"

INDEX=0
DOT_FOUND="N"
DOT_AT_START="N"
DOT_IN_MIDDLE="N"
DOT_AT_END="N"

# PATH를 ':' 기준으로 분리하여 '.'의 위치 판별
for ITEM in "${PATH_ITEMS[@]}"; do
  if [ "$ITEM" = "." ]; then
    DOT_FOUND="Y"
    # '.'이 첫 번째 항목이면 맨 앞 → 취약
    if [ "$INDEX" -eq 0 ]; then
      DOT_AT_START="Y"
    # '.'이 마지막이 아니면 중간 → 취약
    elif [ "$INDEX" -lt $((${#PATH_ITEMS[@]} - 1)) ]; then
      DOT_IN_MIDDLE="Y"
    # '.'이 마지막 항목이면 양호로 간주
    else
      DOT_AT_END="Y"
    fi
  fi
  INDEX=$((INDEX + 1))
done

FILE_TRACE=""

classify_path_dot_position() {
  local p="$1"
  IFS=':' read -ra parts <<< "$p"
  local n=${#parts[@]}
  local i=0
  local start="N" mid="N" end="N" found="N"

  for ((i=0; i<n; i++)); do
    if [ "${parts[$i]}" = "." ]; then
      found="Y"
      if [ "$i" -eq 0 ]; then
        start="Y"
      elif [ "$i" -eq $((n-1)) ]; then
        end="Y"
      else
        mid="Y"
      fi
    fi
  done

  # 파일 내 PATH 정의가 없는 경우
  if [ "$found" = "N" ]; then
    echo "DOT=NONE"
  # '.'이 맨 앞 또는 중간이면 취약
  elif [ "$start" = "Y" ] || [ "$mid" = "Y" ]; then
    echo "DOT=VULNERABLE(start=$start,mid=$mid,end=$end)"
  # '.'이 마지막에만 존재하면 양호
  else
    echo "DOT=SAFE(end_only=Y)"
  fi
}

# 각 환경설정 파일을 순회하며 PATH 정의 라인 추적
for F in "${TARGET_FILES[@]}"; do
  # 파일이 존재하지 않는 경우 정보만 기록
  if [ ! -f "$F" ]; then
    FILE_TRACE+="[INFO] $F (not found)\n"
    continue
  fi

  # 주석 제외 PATH 정의 라인만 수집
  LINES=$(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$F" 2>/dev/null | grep -v '^[[:space:]]*#')

  # PATH 정의 자체가 없는 경우 정보 기록
  if [ -z "$LINES" ]; then
    FILE_TRACE+="[INFO] $F (no PATH definition)\n"
    continue
  fi

  # 각 PATH 정의 라인에 대해 '.' 위치 판별
  while IFS= read -r line; do
    val=$(echo "$line" | sed -E 's/^[[:space:]]*(export[[:space:]]+)?PATH=//')
    val=$(echo "$val" | sed 's/"//g')
    pos=$(classify_path_dot_position "$val")
    FILE_TRACE+="[CHECK] $F | $line | $pos\n"
  done <<< "$LINES"
done

DETAIL_CONTENT=$(cat <<EOF
root_shell=$SHELL_NAME
root_path=$ROOT_PATH
dot_found=$DOT_FOUND
dot_at_start=$DOT_AT_START
dot_in_middle=$DOT_IN_MIDDLE
dot_at_end=$DOT_AT_END

[config_file_trace]
$FILE_TRACE
EOF
)

# 최종 상태 판정
# 1) '.' 자체가 없으면 양호
if [ "$DOT_FOUND" = "N" ]; then
  STATUS="PASS"
  REASON_LINE="root_path=$ROOT_PATH 에서 '.' 항목이 존재하지 않아 이 항목에 대해 양호합니다."

# 2) '.'이 마지막에만 존재하면 양호
elif [ "$DOT_AT_END" = "Y" ] && [ "$DOT_AT_START" = "N" ] && [ "$DOT_IN_MIDDLE" = "N" ]; then
  STATUS="PASS"
  REASON_LINE="root_path=$ROOT_PATH 에서 '.'이 마지막 항목에만 위치해 이 항목에 대해 양호합니다."

# 3) 그 외(맨 앞 또는 중간)는 취약
else
  STATUS="FAIL"
  if [ "$DOT_AT_START" = "Y" ]; then
    REASON_LINE="root_path 설정에서 '.'이 '.:’ 형태로 맨 앞에 위치해 이 항목에 대해 취약합니다."
  else
    REASON_LINE="root_path 설정에서 '.'이 ':.:’ 형태로 중간에 위치해 이 항목에 대해 취약합니다."
  fi
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE=$(cat <<'EOF'
이 항목에 대해서 PATH 탐색 순서가 의도치 않게 변경될 위험이 존재하여 수동 조치가 필요합니다.
자동 조치로 여러 환경설정 파일의 PATH 라인을 일괄 수정하면 로그인/비로그인 쉘 반영 시점 차이로 인해 작업 절차에 혼선이 생기거나, PATH 재구성 과정에서 오타·중복·누락이 발생해 관리자 작업 및 일부 스크립트 실행에 영향을 줄 수 있습니다.
관리자가 /etc/profile 및 root 계정 환경설정 파일에서 PATH 정의 라인을 직접 확인한 후 '.'이 맨 앞 또는 중간에 있으면 제거하고, 필요한 경우에만 '.'을 PATH의 맨 마지막에만 위치하도록 설정해 주시기 바랍니다.
변경 후에는 root로 새 로그인 세션에서 echo $PATH 결과를 확인하여 '.'이 맨 앞/중간에 존재하지 않는지 재검증해 주시기 바랍니다.
EOF
)

RAW_DETAIL="${REASON_LINE}\n${DETAIL_CONTENT}"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$RAW_DETAIL",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
