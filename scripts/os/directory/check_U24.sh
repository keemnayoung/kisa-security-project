#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-24
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# @Description : 홈 디렉터리 내의 환경변수 파일에 대한 소유자 및 접근 권한이 관리자 또는 해당 계정으로 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-24"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='while IFS=: read -r user _ _ _ _ home _; do [ -d "$home" ] || continue; for f in .profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc; do p="$home/$f"; [ -f "$p" ] || continue; stat -c "%U %A" "$p"; done; done < /etc/passwd'
TARGET_FILE=""

ENV_FILES=(
  ".profile"
  ".kshrc"
  ".cshrc"
  ".bashrc"
  ".bash_profile"
  ".login"
  ".exrc"
  ".netrc"
)

DETAIL_CONTENT=""
REASON_LINE=""
FOUND_VULN="N"
VULN_LINES=""
ALL_LINES=""

GUIDE_LINE="자동 조치 시 사용자 환경 설정(.bashrc 등) 변경으로 서비스/업무 스크립트 동작에 영향이 있을 수 있어 수동 조치가 필요합니다.
관리자가 직접 확인 후 환경변수 파일의 소유자를 root 또는 해당 계정으로 변경하고, group/other 쓰기 권한(g-w, o-w)을 제거해 주시기 바랍니다."

# /etc/passwd를 순회하며 홈 디렉터리 내 환경변수 파일 점검
while IFS=: read -r USER _ _ _ _ HOME_DIR _; do
  [ -d "$HOME_DIR" ] || continue

  for ENV_FILE in "${ENV_FILES[@]}"; do
    FILE_PATH="$HOME_DIR/$ENV_FILE"
    [ -f "$FILE_PATH" ] || continue

    OWNER="$(stat -c %U "$FILE_PATH" 2>/dev/null)"
    PERM="$(stat -c %A "$FILE_PATH" 2>/dev/null)"

    # stat 결과 확인이 불가한 경우는 취약으로 분류
    if [ -z "$OWNER" ] || [ -z "$PERM" ]; then
      STATUS="FAIL"
      FOUND_VULN="Y"
      VULN_LINES+="$FILE_PATH owner=${OWNER:-unknown} user=$USER perm=${PERM:-unknown} (stat_failed)"$'\n'
      ALL_LINES+="$FILE_PATH owner=${OWNER:-unknown} user=$USER perm=${PERM:-unknown} (stat_failed)"$'\n'
      TARGET_FILE+="$FILE_PATH "
      continue
    fi

    # 현재 설정값(전체) 누적
    ALL_LINES+="$FILE_PATH owner=$OWNER user=$USER perm=$PERM"$'\n'

    # 소유자(root 또는 해당 계정) 조건 위반
    if [[ "$OWNER" != "root" && "$OWNER" != "$USER" ]]; then
      STATUS="FAIL"
      FOUND_VULN="Y"
      VULN_LINES+="$FILE_PATH owner=$OWNER user=$USER perm=$PERM"$'\n'
      TARGET_FILE+="$FILE_PATH "
      continue
    fi

    # group/other 쓰기 권한 존재 여부 점검 (root/소유자 외 쓰기 금지)
    if [[ "${PERM:5:1}" == "w" || "${PERM:8:1}" == "w" ]]; then
      STATUS="FAIL"
      FOUND_VULN="Y"
      VULN_LINES+="$FILE_PATH owner=$OWNER user=$USER perm=$PERM"$'\n'
      TARGET_FILE+="$FILE_PATH "
    fi
  done
done < /etc/passwd

# 결과에 따른 평가 이유 및 detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
  TARGET_FILE="$(echo "$TARGET_FILE" | tr -s ' ' | sed 's/[[:space:]]*$//')"

  # 취약 근거 문장에는 취약 설정만(한 문장) 포함
  VULN_SUMMARY="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//' | tr '\n' '; ' | sed 's/;[[:space:]]*$//')"
  REASON_LINE="$VULN_SUMMARY 설정으로 이 항목에 대해 취약합니다."

  # DETAIL_CONTENT에는 양호/취약 관계 없이 현재 설정값(전체) 표시
  ALL_TRIMMED="$(printf "%s" "$ALL_LINES" | sed 's/[[:space:]]*$//')"
  DETAIL_CONTENT="${ALL_TRIMMED:-no_env_files_found}"
else
  STATUS="PASS"
  TARGET_FILE="user_home_env_files"

  # 양호 근거 문장(한 문장)
  REASON_LINE="모든 환경변수 파일이 owner=root 또는 owner=해당 계정이고 perm에서 g-w/o-w 미부여로 설정되어 있어 이 항목에 대해 양호합니다."

  # DETAIL_CONTENT에는 현재 설정값(전체) 표시
  ALL_TRIMMED="$(printf "%s" "$ALL_LINES" | sed 's/[[:space:]]*$//')"
  DETAIL_CONTENT="${ALL_TRIMMED:-no_env_files_found}"
fi

# raw_evidence 구성 (첫 줄: 평가 문장 / 다음 줄부터: 현재 설정값)
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
