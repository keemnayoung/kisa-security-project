#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-04
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 비밀번호 파일 보호
# @Description : pwconv 명령어를 사용하여 쉐도우 패스워드 정책을 강제 적용
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-04"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"

TARGET_FILE="/etc/passwd
/etc/shadow"

CHECK_COMMAND="( command -v pwconv >/dev/null 2>&1 && echo pwconv_available=yes || echo pwconv_available=no ); \
[ -f /etc/passwd ] && awk -F: '\$2 != \"x\" && \$2 !~ /^(\\!|\\*)+\$/'\'' {print \$1\":\"\$2}'\'' /etc/passwd 2>/dev/null | head -n 50 || echo passwd_not_found; \
[ -f /etc/shadow ] && echo shadow_exists || echo shadow_not_found"

# 사전 체크 분기점
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아닌 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="현재 실행 권한: $(id -un)"
elif [ ! -f "$PASSWD_FILE" ]; then
  IS_SUCCESS=0
  REASON_LINE="/etc/passwd 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="대상 파일 미존재"
elif ! command -v pwconv >/dev/null 2>&1; then
  IS_SUCCESS=0
  REASON_LINE="pwconv 명령어가 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="명령어 미존재"
fi

# 조치 수행 및 백업 분기점
if [ -z "$REASON_LINE" ]; then
  TS="$(date '+%Y%m%d%H%M%S')"
  PASSWD_BAK="/var/tmp/passwd.U04.bak.${TS}"
  SHADOW_BAK="/var/tmp/shadow.U04.bak.${TS}"

  if cp -p "$PASSWD_FILE" "$PASSWD_BAK" 2>/dev/null; then
    :
  else
    IS_SUCCESS=0
    REASON_LINE="/etc/passwd 백업에 실패한 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="백업 경로: $PASSWD_BAK"
  fi

  if [ -z "$REASON_LINE" ] && [ -f "$SHADOW_FILE" ]; then
    if cp -p "$SHADOW_FILE" "$SHADOW_BAK" 2>/dev/null; then
      :
    else
      IS_SUCCESS=0
      REASON_LINE="/etc/shadow 백업에 실패한 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
      DETAIL_CONTENT="백업 경로: $SHADOW_BAK"
    fi
  fi

  if [ -z "$REASON_LINE" ]; then
    pwconv >/dev/null 2>&1
    if [ $? -ne 0 ]; then
      IS_SUCCESS=0
      REASON_LINE="pwconv 명령어 실행 중 오류가 발생한 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
      DETAIL_CONTENT="pwconv 실행 에러 발생"
    fi
  fi
fi

# 조치 후 상태 수집 및 최종 판정 분기점
if [ -z "$REASON_LINE" ]; then
  NOT_X_USERS=$(awk -F: '$2 != "x" && $2 !~ /^(\!|\*)+$/ {print $1 ":" $2}' /etc/passwd 2>/dev/null | head -n 200)
  COUNT_NOT_X=$(awk -F: '$2 != "x" && $2 !~ /^(\!|\*)+$/ {c++} END{print c+0}' /etc/passwd 2>/dev/null)

  if [ "$COUNT_NOT_X" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="pwconv 명령어를 통해 /etc/passwd의 비밀번호 필드를 'x'로 변환하고 쉐도우 패스워드 정책을 적용 완료하여 이 항목에 대해 양호합니다."
    DETAIL_CONTENT="passwd_shadow_sync=applied
not_x_field_count=$COUNT_NOT_X"
  else
    IS_SUCCESS=0
    REASON_LINE="일부 계정의 비밀번호 필드가 'x'로 변환되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="미변환 계정 리스트:
${NOT_X_USERS:-none}"
  fi
fi

# RAW_EVIDENCE 구성
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

# 최종 결과 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF