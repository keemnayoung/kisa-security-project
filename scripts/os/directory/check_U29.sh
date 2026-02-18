#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-29
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-29"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/hosts.lpd"
CHECK_COMMAND='[ -e /etc/hosts.lpd ] && stat -c "%F|%U|%a" /etc/hosts.lpd || echo "file_not_found"'

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE="N/A"

# 파일 존재 여부 판단
if [ ! -e "$TARGET_FILE" ]; then
  STATUS="PASS"
  DETAIL_CONTENT="file_not_found"
  REASON_LINE="file_not_found 상태로 확인되어 이 항목에 대해 양호합니다."
else
  # 파일 타입 확인(일반 파일이 아니면 취약)
  FILE_TYPE=$(stat -c %F "$TARGET_FILE" 2>/dev/null)

  if [ -z "$FILE_TYPE" ]; then
    STATUS="FAIL"
    DETAIL_CONTENT="stat_failed"
    REASON_LINE="stat_failed 상태로 확인되어 이 항목에 대해 취약합니다."
  elif [ "$FILE_TYPE" != "regular file" ]; then
    STATUS="FAIL"
    DETAIL_CONTENT="type=$FILE_TYPE"
    REASON_LINE="type=$FILE_TYPE 로 확인되어 이 항목에 대해 취약합니다."
  else
    # 일반 파일인 경우 소유자/권한을 확인하여 기준 충족 여부 판단
    OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ -z "$OWNER" ] || [ -z "$PERM" ] || ! [[ "$PERM" =~ ^[0-9]+$ ]]; then
      STATUS="FAIL"
      DETAIL_CONTENT="type=$FILE_TYPE"$'\n'"owner=$OWNER"$'\n'"perm=$PERM"
      REASON_LINE="owner=$OWNER, perm=$PERM 로 확인되어 이 항목에 대해 취약합니다."
    else
      DETAIL_CONTENT="type=$FILE_TYPE"$'\n'"owner=$OWNER"$'\n'"perm=$PERM"

      if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ]; then
        STATUS="PASS"
        REASON_LINE="owner=root, perm=$PERM(600 이하)로 설정되어 이 항목에 대해 양호합니다."
      else
        STATUS="FAIL"
        VULN_PARTS=""
        if [ "$OWNER" != "root" ]; then
          VULN_PARTS="owner=$OWNER"
        fi
        if [ "$PERM" -gt 600 ] 2>/dev/null; then
          if [ -n "$VULN_PARTS" ]; then
            VULN_PARTS="$VULN_PARTS, perm=$PERM(600 초과)"
          else
            VULN_PARTS="perm=$PERM(600 초과)"
          fi
        fi
        [ -z "$VULN_PARTS" ] && VULN_PARTS="owner=$OWNER, perm=$PERM"
        REASON_LINE="$VULN_PARTS 로 설정되어 이 항목에 대해 취약합니다."
      fi
    fi
  fi
fi

# 취약 시 자동 조치 가이드/주의사항 구성
if [ "$STATUS" = "FAIL" ]; then
  GUIDE_LINE="자동 조치:
  /etc/hosts.lpd 파일을 제거하거나, 불가피하게 사용 시 소유자/그룹을 root:root로 변경하고 권한을 600으로 설정합니다.
  주의사항: 
  레거시 LPD/프린트 서비스에서 해당 파일을 사용하는 경우 파일 제거 또는 권한 변경으로 인쇄/접근 제어 동작에 영향이 있을 수 있으므로 서비스 사용 여부를 확인한 후 적용합니다."
fi

# raw_evidence 구성(각 값은 문장/항목을 줄바꿈으로 구분)
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
