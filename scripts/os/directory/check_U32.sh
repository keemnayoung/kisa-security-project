#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-32
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 사용자 계정과 홈 디렉토리의 일치 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-32"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"

CHECK_COMMAND='while IFS=: read -r u _ _ _ _ h s; do case "$s" in */nologin|*/false) continue ;; esac; echo "$u:$h:$s"; done < /etc/passwd'

FOUND_VULN="N"
REASON_LINE=""
DETAIL_CONTENT=""

MISSING_HOME_USERS=()
ALL_LOGIN_USERS=()

json_escape() {
  # 백슬래시 → 따옴표 → 줄바꿈 순으로 escape (DB 저장/재조회 시 \n 유지 목적)
  echo "$1" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# 분기: 점검 대상 파일 존재 여부 확인
if [ ! -f "$TARGET_FILE" ]; then
  STATUS="FAIL"
  FOUND_VULN="Y"
  REASON_LINE="(/etc/passwd) 파일이 없어 현재 설정을 확인할 수 있어 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="passwd_file_missing"
else
  # 분기: /etc/passwd 기준 로그인 가능 계정의 홈 디렉터리 설정 및 실제 존재 여부 점검
  while IFS=: read -r username _ uid _ _ homedir shell; do
    case "$shell" in
      */nologin|*/false) continue ;;
    esac

    # 현재 설정값(로그인 가능 계정)은 양호/취약과 관계 없이 모두 DETAIL_CONTENT에 포함
    state="exists"
    if [ -z "$homedir" ] || [ "$homedir" = "-" ] || [[ "$homedir" != /* ]]; then
      state="invalid_home"
      FOUND_VULN="Y"
      MISSING_HOME_USERS+=("$username:$homedir")
    elif [ ! -d "$homedir" ]; then
      state="missing_home"
      FOUND_VULN="Y"
      MISSING_HOME_USERS+=("$username:$homedir")
    fi

    ALL_LOGIN_USERS+=("$username:$homedir:$shell:$state")
  done < "$TARGET_FILE"

  DETAIL_CONTENT="$(printf "%s\n" "${ALL_LOGIN_USERS[@]}" | sed 's/[[:space:]]*$//')"

  # 분기: 취약/양호에 따른 reason 문장(1문장) 구성
  if [ "$FOUND_VULN" = "Y" ]; then
    STATUS="FAIL"
    IFS=", " VULN_JOINED="${MISSING_HOME_USERS[*]}" ; unset IFS
    REASON_LINE="(/etc/passwd)에서 홈 디렉터리가 없거나 비정상으로 지정된 계정($VULN_JOINED)이 있어 이 항목에 대해 취약합니다."
  else
    STATUS="PASS"
    REASON_LINE="(/etc/passwd)에서 로그인 가능한 계정의 홈 디렉터리 경로가 모두 정상(절대경로)이며 실제 디렉터리가 존재하여 이 항목에 대해 양호합니다."
  fi
fi

# raw_evidence 구성: 각 값은 문장/라인 단위 줄바꿈 가능하도록 \n 포함
GUIDE_LINE="이 항목에 대해서 잘못된 홈 디렉터리 조치(계정 삭제, 홈 디렉터리 임의 생성/소유권 변경)로 서비스 계정이나 배치 작업 경로가 바뀌어 장애가 발생할 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 해당 계정의 사용 여부를 확인한 후 불필요하면 userdel로 계정을 제거하고, 사용 중이면 홈 디렉터리를 생성/할당하거나 /etc/passwd의 홈 경로를 올바르게 수정해 주시기 바랍니다."

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

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
