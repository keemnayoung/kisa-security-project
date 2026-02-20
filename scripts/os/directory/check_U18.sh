#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-18
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-18"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/shadow"
CHECK_COMMAND='stat -c "%U %a" /etc/shadow'

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE=""

# 권한 판정(400 이하) 함수: 3자리 u(4/0), g(0), o(0)만 허용
is_perm_ok() {
  local perm_raw="$1"
  [ -z "$perm_raw" ] && return 1
  local perm3 u g o
  perm3="$(printf "%03d" "$perm_raw" 2>/dev/null)" || return 1
  u="${perm3:0:1}"; g="${perm3:1:1}"; o="${perm3:2:1}"
  { [ "$u" = "4" ] || [ "$u" = "0" ]; } && [ "$g" = "0" ] && [ "$o" = "0" ]
}

# 파일 존재 여부
if [ ! -f "$TARGET_FILE" ]; then
  STATUS="FAIL"
  REASON_LINE="파일이 존재하지 않아 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="file_not_found"
  GUIDE_LINE="자동 조치:
  /etc/shadow 파일을 복구한 뒤 소유자를 root로 변경(chown root /etc/shadow)하고 권한을 400으로 설정(chmod 400 /etc/shadow)합니다.
  주의사항: 
  권한/소유자 설정이 잘못되면 인증 관련 서비스에서 로그인 오류가 발생할 수 있으므로 조치 후 즉시 상태를 재확인해야 합니다."
else
  # stat 정보 수집 및 실패 방어
  FILE_OWNER="$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)"
  FILE_PERM_RAW="$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)"

  if [ -z "$FILE_OWNER" ] || [ -z "$FILE_PERM_RAW" ]; then
    STATUS="FAIL"
    REASON_LINE="소유자/권한 값을 확인하지 못해 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="stat_failed"
    GUIDE_LINE="자동 조치:
    /etc/shadow 파일의 소유자를 root로 변경(chown root /etc/shadow)하고 권한을 400으로 설정(chmod 400 /etc/shadow)합니다.
    주의사항: 
    권한/소유자 설정이 잘못되면 인증 관련 서비스에서 로그인 오류가 발생할 수 있으므로 조치 전후로 상태 수집(stat)이 가능한지부터 확인해야 합니다."
  else
    # 권한 정규화 및 판정
    FILE_PERM="$(printf "%03d" "$FILE_PERM_RAW" 2>/dev/null)"

    PERM_OK=0
    if is_perm_ok "$FILE_PERM_RAW"; then PERM_OK=1; fi

    DETAIL_CONTENT="owner=$FILE_OWNER\nperm=$FILE_PERM"

    # 기준 충족 여부
    if [ "$FILE_OWNER" = "root" ] && [ "$PERM_OK" -eq 1 ]; then
      STATUS="PASS"
      REASON_LINE="owner=$FILE_OWNER, perm=$FILE_PERM로 설정되어 있어 이 항목에 대해 양호합니다."
    else
      STATUS="FAIL"
      VULN_PARTS=""
      if [ "$FILE_OWNER" != "root" ]; then
        VULN_PARTS="owner=$FILE_OWNER"
      fi
      if [ "$PERM_OK" -ne 1 ]; then
        [ -n "$VULN_PARTS" ] && VULN_PARTS="${VULN_PARTS}, "
        VULN_PARTS="${VULN_PARTS}perm=$FILE_PERM"
      fi
      REASON_LINE="${VULN_PARTS}로 설정되어 있어 이 항목에 대해 취약합니다."
      GUIDE_LINE="자동 조치:
      /etc/shadow 파일의 소유자를 root로 변경(chown root /etc/shadow)하고 권한을 400으로 설정(chmod 400 /etc/shadow)합니다.
      주의사항: 
      권한/소유자 설정이 잘못되면 인증 관련 서비스에서 로그인 오류가 발생할 수 있으므로 조치 후 즉시 owner/perm 값을 재검증해야 합니다."
    fi
  fi
fi

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리(따옴표, 줄바꿈)
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
