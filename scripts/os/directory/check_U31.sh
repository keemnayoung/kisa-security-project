#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-31
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉토리의 소유자 외 타 사용자가 해당 홈 디렉토리를 수정할 수 없도록 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-31"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='while IFS=: read -r u _ _ _ _ h _; do [ -d "$h" ] && stat -c "%n owner=%U perm=%a" "$h"; done < /etc/passwd; for b in /home /export/home; do [ -d "$b" ] && find "$b" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null; done'

DETAIL_CONTENT=""
REASON_LINE=""
FOUND_VULN="N"

# 점검 결과 라인(현재 설정값 전체)
ALL_LINES=""

# 취약 라인
VULN_LINES=""

# /etc/passwd 홈 디렉터리 목록(추가 사용자 디렉터리 탐지용)
HOME_LIST=""

is_in_home_list() {
  local p="$1"
  printf "%s" "$HOME_LIST" | grep -Fxq "$p"
}

# /etc/passwd에 등록된 홈 디렉터리 점검
while IFS=: read -r USER _ _ _ _ HOME _; do
  [ -d "$HOME" ] || continue

  HOME_LIST+="$HOME"$'\n'

  OWNER=$(stat -c %U "$HOME" 2>/dev/null | tr -d '[:space:]')
  PERM=$(stat -c %a "$HOME" 2>/dev/null | tr -d '[:space:]')
  OTHER_DIGIT=$((PERM % 10))

  # 현재 설정값은 양호/취약과 관계없이 모두 기록
  ALL_LINES+="home_dir user=${USER} path=${HOME} owner=${OWNER} perm=${PERM}"$'\n'

  # 취약 조건(소유자 불일치 또는 other 쓰기 권한 존재)
  if [[ "$OWNER" != "$USER" || "$OTHER_DIGIT" -ge 2 ]]; then
    STATUS="FAIL"
    FOUND_VULN="Y"
    VULN_LINES+="home_dir user=${USER} path=${HOME} owner=${OWNER} perm=${PERM}"$'\n'
  fi
done < /etc/passwd

# 홈 외 개별 사용자 디렉터리 존재 여부 확인(/home/*, /export/home/*)
for BASE in /home /export/home; do
  [ -d "$BASE" ] || continue

  while IFS= read -r D; do
    [ -d "$D" ] || continue
    is_in_home_list "$D" && continue

    D_OWNER=$(stat -c %U "$D" 2>/dev/null | tr -d '[:space:]')
    D_PERM=$(stat -c %a "$D" 2>/dev/null | tr -d '[:space:]')
    D_OTHER_DIGIT=$((D_PERM % 10))

    # 현재 설정값은 모두 기록
    ALL_LINES+="extra_dir path=${D} owner=${D_OWNER} perm=${D_PERM}"$'\n'

    # extra_dir은 other 쓰기 권한이 있을 때만 취약으로 포함
    if [[ "$D_OTHER_DIGIT" -ge 2 ]]; then
      STATUS="FAIL"
      FOUND_VULN="Y"
      VULN_LINES+="extra_dir path=${D} owner=${D_OWNER} perm=${D_PERM}"$'\n'
    fi
  done < <(find "$BASE" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null)
done

# 결과 문장/DETAIL 구성
DETAIL_CONTENT="$(printf "%s" "$ALL_LINES" | sed 's/[[:space:]]*$//')"
[ -n "$DETAIL_CONTENT" ] || DETAIL_CONTENT="no_home_dirs_found"

if [ "$FOUND_VULN" = "Y" ]; then
  VULN_COUNT=$(printf "%s" "$VULN_LINES" | sed '/^[[:space:]]*$/d' | wc -l)
  REASON_LINE="홈 디렉터리 ${VULN_COUNT}건에서 소유자 불일치 또는 other 쓰기 권한이 발견되어 이 항목에 대해 취약합니다."
else
  REASON_LINE="각 홈 디렉터리의 owner가 해당 user와 일치하고 other 쓰기 권한(o+w)이 제거된 상태로 이 항목에 대해 양호합니다."
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE=$(
  cat <<'EOF'
자동으로 소유자/권한을 변경하면 기존에 공유 목적으로 사용되던 홈 디렉터리 접근이 차단되거나 서비스/배치/스크립트가 파일을 쓰지 못해 장애가 발생할 수 있어 수동 조치가 필요합니다.
관리자가 직접 /etc/passwd에서 사용자 홈 디렉터리를 확인한 뒤, 각 홈 디렉터리의 소유주를 해당 사용자로 변경하고(chown <사용자> <홈디렉터리>), 타 사용자(other) 쓰기 권한을 제거(chmod o-w <홈디렉터리>)해 주시기 바랍니다.
EOF
)

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
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

# JSON escape 처리(역슬래시/따옴표/줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g' \
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
