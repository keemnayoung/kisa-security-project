#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-27
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-27"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

LOG_FILE_FIXED=0
FAIL_FLAG=0
FOUND=0

CHECK_COMMAND="( [ -f /etc/hosts.equiv ] && stat -c '%U %G %a %n' /etc/hosts.equiv && grep -nE '^[[:space:]]*\\+' /etc/hosts.equiv 2>/dev/null ) ; find /home -name .rhosts -type f -print -exec stat -c '%U %G %a %n' {} \\; -exec grep -nE '^[[:space:]]*\\+' {} \\; 2>/dev/null"

# 시스템 내의 대상 파일(/etc/hosts.equiv 및 각 사용자 홈 디렉토리의 .rhosts)을 수집
TARGET_LIST=()

if [ -f "/etc/hosts.equiv" ]; then
  TARGET_LIST+=("/etc/hosts.equiv")
fi

while IFS= read -r rf; do
  [ -f "$rf" ] && TARGET_LIST+=("$rf")
done < <(find /home -name ".rhosts" -type f 2>/dev/null)

if [ "${#TARGET_LIST[@]}" -gt 0 ]; then
  FOUND=1
fi

TARGET_FILE=$(printf "%s\n" "${TARGET_LIST[@]}")

# 수집된 파일들에 대해 소유자 변경, 권한 축소(600), 설정 내 '+' 문자 제거를 수행
if [ "$FOUND" -eq 1 ]; then
  for file in "${TARGET_LIST[@]}"; do
    [ -f "$file" ] || continue

    if [ "$file" = "/etc/hosts.equiv" ]; then
      OWNER=$(stat -c "%U" "$file" 2>/dev/null)
      if [ "$OWNER" != "root" ]; then
        chown root:root "$file" 2>/dev/null || FAIL_FLAG=1
      fi
    else
      EXPECT_USER=$(basename "$(dirname "$file")")
      if [ -n "$EXPECT_USER" ] && id "$EXPECT_USER" >/dev/null 2>&1; then
        chown "$EXPECT_USER":"$EXPECT_USER" "$file" 2>/dev/null || FAIL_FLAG=1
      else
        FAIL_FLAG=1
      fi
    fi

    chmod 600 "$file" 2>/dev/null || FAIL_FLAG=1
    sed -i '/^[[:space:]]*\+/d' "$file" 2>/dev/null || FAIL_FLAG=1
  done
fi

# 조치 후 각 파일의 최종 상태를 확인하고 상세 내용 구성
DETAIL_ITEMS=()

if [ "$FOUND" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="대상 파일이 존재하지 않아 조치를 완료하여 이 항목에 대해 양호합니다."
  DETAIL_CONTENT="상태: 파일 없음"
else
  for file in "${TARGET_LIST[@]}"; do
    [ -f "$file" ] || continue

    AFTER_OWNER=$(stat -c "%U" "$file" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$file" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$file" 2>/dev/null)
    PLUS_AFTER=$(grep -nE '^[[:space:]]*\+' "$file" 2>/dev/null | head -n 1)

    # 개별 파일 상태 정보 생성
    DETAIL_ITEMS+=("file=$file
owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM
plus_setting=$( [ -n "$PLUS_AFTER" ] && echo "found($PLUS_AFTER)" || echo "not_found" )
")

    # 가이드 기준 준수 여부 최종 검증
    if [ "$file" = "/etc/hosts.equiv" ]; then
      [ "$AFTER_OWNER" != "root" ] && FAIL_FLAG=1
    else
      EXPECT_USER=$(basename "$(dirname "$file")")
      if [ -n "$EXPECT_USER" ] && id "$EXPECT_USER" >/dev/null 2>&1; then
        [ "$AFTER_OWNER" != "$EXPECT_USER" ] && FAIL_FLAG=1
      else
        FAIL_FLAG=1
      fi
    fi

    if [ -z "$AFTER_PERM" ] || [ "$AFTER_PERM" -gt 600 ] || [ -n "$PLUS_AFTER" ]; then
      FAIL_FLAG=1
    fi
  done

  # DETAIL_CONTENT 줄바꿈 조립
  DETAIL_CONTENT=$(printf "%s\n" "${DETAIL_ITEMS[@]}")

  # 조치 성공 및 실패에 따른 REASON_LINE 확정
  if [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="소유자를 해당 계정으로 변경하고 권한을 600 이하로 설정하며 '+' 설정을 제거하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    REASON_LINE="허용되지 않은 소유자나 권한이 설정되어 있거나 '+' 설정이 존재하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
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
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF