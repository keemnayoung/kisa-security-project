#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-16
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : /etc/passwd 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-16"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='stat -c "%U %a" /etc/passwd'

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE="N/A"

# /etc/passwd 파일이 없으면 즉시 취약 처리
if [ ! -f "$TARGET_FILE" ]; then
  STATUS="FAIL"

  REASON_LINE="/etc/passwd 파일이 존재하지 않아 file_not_found 상태이므로 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="current_status=file_not_found"

  GUIDE_LINE="자동 조치:
  /etc/passwd 파일을 정상 상태로 복구한 뒤 소유자(root:root)와 권한(644)으로 설정합니다.
  주의사항: 
  파일 복구/대체는 인증/계정 체계에 영향을 줄 수 있으므로 반드시 신뢰 가능한 백업/이미지에서 복구해야 합니다."
else
  # 파일의 현재 소유자/권한 수집
  FILE_OWNER="$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)"
  FILE_PERM_STR="$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)"

  # 권한 형식이 비정상이면 취약 처리
  if ! echo "$FILE_PERM_STR" | grep -Eq '^[0-7]{3,4}$'; then
    STATUS="FAIL"

    REASON_LINE="권한=($FILE_PERM_STR) 값이 정상 형식이 아니어서 perm=$FILE_PERM_STR 상태이므로 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="owner=$FILE_OWNER\nperm=$FILE_PERM_STR\nwrite_bits=unknown\nspecial_bits=unknown"

    GUIDE_LINE="자동 조치:
    chown root:root /etc/passwd 및 chmod 644 /etc/passwd를 수행해 기준 설정으로 맞춥니다.
    주의사항: 
    권한 값이 비정상으로 수집될 경우 파일시스템/권한/속성(immutable 등) 문제일 수 있으니 강제 변경 전 원인을 확인하고 백업을 권장합니다."
  else
    # 비트 기준으로 정확 판정
    FILE_PERM_DEC=$((8#$FILE_PERM_STR))

    # 기준 판정 값 산출
    OWNER_OK=0
    WRITE_OK=0
    SPECIAL_OK=0

    [ "$FILE_OWNER" = "root" ] && OWNER_OK=1
    [ $((FILE_PERM_DEC & 022)) -eq 0 ] && WRITE_OK=1
    [ $((FILE_PERM_DEC & 07000)) -eq 0 ] && SPECIAL_OK=1

    if [ "$WRITE_OK" -eq 1 ]; then
      WRITE_DESC="no"
    else
      WRITE_DESC="yes"
    fi

    if [ "$SPECIAL_OK" -eq 1 ]; then
      SPECIAL_DESC="no"
    else
      SPECIAL_DESC="yes"
    fi

    DETAIL_CONTENT="owner=$FILE_OWNER\nperm=$FILE_PERM_STR\ngroup_or_other_write=$WRITE_DESC\nspecial_bits=$SPECIAL_DESC"

    if [ "$OWNER_OK" -eq 1 ] && [ "$WRITE_OK" -eq 1 ] && [ "$SPECIAL_OK" -eq 1 ] && [ "$FILE_PERM_STR" -le 644 ]; then
      STATUS="PASS"
      REASON_LINE="소유자=root, 권한=$FILE_PERM_STR(그룹/기타 쓰기 없음, 특수권한 없음)으로 설정되어 있어 이 항목에 대해 양호합니다."
      GUIDE_LINE="자동 조치:
      /etc/passwd에 대해 chown root:root /etc/passwd로 소유자/그룹을 root로 통일하고 chmod 644 /etc/passwd로 권한을 표준화합니다.
      주의사항: 
      /etc/passwd가 심볼릭 링크이거나 파일시스템이 읽기 전용/immutable 속성인 경우 변경이 실패할 수 있으니 조치 전 파일 유형과 속성(lsattr 등) 확인 및 백업을 권장합니다."
    else
      STATUS="FAIL"

      BAD_PARTS=""
      if [ "$OWNER_OK" -ne 1 ]; then
        BAD_PARTS="소유자=$FILE_OWNER"
      fi
      if [ "$FILE_PERM_STR" -gt 644 ]; then
        [ -n "$BAD_PARTS" ] && BAD_PARTS="${BAD_PARTS}, "
        BAD_PARTS="${BAD_PARTS}권한=$FILE_PERM_STR"
      fi
      if [ "$WRITE_OK" -ne 1 ]; then
        [ -n "$BAD_PARTS" ] && BAD_PARTS="${BAD_PARTS}, "
        BAD_PARTS="${BAD_PARTS}그룹/기타 쓰기 허용"
      fi
      if [ "$SPECIAL_OK" -ne 1 ]; then
        [ -n "$BAD_PARTS" ] && BAD_PARTS="${BAD_PARTS}, "
        BAD_PARTS="${BAD_PARTS}특수권한 존재"
      fi
      [ -z "$BAD_PARTS" ] && BAD_PARTS="설정값 확인 필요"

      REASON_LINE="$BAD_PARTS 상태로 설정되어 있어 이 항목에 대해 취약합니다."

      GUIDE_LINE="자동 조치:
      /etc/passwd에 대해 chown root:root /etc/passwd로 소유자/그룹을 root로 통일하고 chmod 644 /etc/passwd로 권한을 표준화합니다.
      주의사항: 
      /etc/passwd가 심볼릭 링크이거나 파일시스템이 읽기 전용/immutable 속성인 경우 변경이 실패할 수 있으니 조치 전 파일 유형과 속성(lsattr 등) 확인 및 백업을 권장합니다."
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
