#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-06
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : su 명령 사용 제한
# @Description : 특정 그룹(wheel)만 su 명령을 사용할 수 있도록 제한 설정 여부 점검
# @Criteria_Good : su 명령 사용 권한이 특정 그룹에만 부여되어 있는 경우
# @Criteria_Bad : su 명령 사용 권한이 모든 사용자에게 개방되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-06"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/pam.d/su"
SU_BIN="$(command -v su 2>/dev/null)"
[ -z "$SU_BIN" ] && SU_BIN="/usr/bin/su"

CHECK_COMMAND='(
  if [ -f /etc/pam.d/su ]; then
    grep -nEv "^[[:space:]]*#" /etc/pam.d/su | grep -nE "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so" || echo "su_pam_rule_missing"
  else
    echo "su_pam_file_not_found"
  fi
  SU_PATH="$(command -v su 2>/dev/null)"; [ -z "$SU_PATH" ] && SU_PATH="/usr/bin/su";
  if [ -e "$SU_PATH" ]; then
    ls -l "$SU_PATH"
    stat -c "perm=%a group=%G path=%n" "$SU_PATH"
  else
    echo "su_binary_not_found"
  fi
)'

REASON_LINE=""
DETAIL_CONTENT=""

PAM_ACTIVE_LINE=""
PAM_RULE_OK="no"

WHEEL_GROUP_LINE="$(getent group wheel 2>/dev/null)"
WHEEL_EXISTS="no"
WHEEL_MEMBERS=""
if [ -n "$WHEEL_GROUP_LINE" ]; then
  WHEEL_EXISTS="yes"
  WHEEL_MEMBERS="$(echo "$WHEEL_GROUP_LINE" | awk -F: '{print $4}')"
  [ -z "$WHEEL_MEMBERS" ] && WHEEL_MEMBERS="(none)"
else
  WHEEL_MEMBERS="(wheel group not found)"
fi

SU_EXISTS="no"
SU_PERM_OCT="N/A"
SU_GROUP="N/A"
SU_ALT_OK="no"
if [ -e "$SU_BIN" ]; then
  SU_EXISTS="yes"
  SU_PERM_OCT="$(stat -c '%a' "$SU_BIN" 2>/dev/null)"
  SU_GROUP="$(stat -c '%G' "$SU_BIN" 2>/dev/null)"
  if [ "$WHEEL_EXISTS" = "yes" ] && [ "$SU_PERM_OCT" = "4750" ] && [ "$SU_GROUP" = "wheel" ]; then
    SU_ALT_OK="yes"
  fi
fi

# 분기 1: /etc/pam.d/su 존재 시, pam_wheel.so 설정 유무 및 옵션 확인
if [ -f "$TARGET_FILE" ]; then
  PAM_ACTIVE_LINE="$(grep -Ev '^[[:space:]]*#' "$TARGET_FILE" 2>/dev/null \
    | grep -E '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' \
    | head -n 1)"

  if [ -n "$PAM_ACTIVE_LINE" ]; then
    if echo "$PAM_ACTIVE_LINE" | grep -qE '(^|[[:space:]])use_uid([[:space:]]|$)'; then
      PAM_RULE_OK="yes"
    elif echo "$PAM_ACTIVE_LINE" | grep -qE '(^|[[:space:]])group=wheel([[:space:]]|$)'; then
      PAM_RULE_OK="yes"
    else
      PAM_RULE_OK="no"
    fi

    if [ "$PAM_RULE_OK" = "yes" ] && [ "$WHEEL_EXISTS" = "yes" ]; then
      STATUS="PASS"
      REASON_LINE="$(echo "$PAM_ACTIVE_LINE" | sed 's/[[:space:]]*$//') 및 wheel 그룹이 존재하여 이 항목에 대해 양호합니다."
    else
      STATUS="FAIL"
      if [ "$WHEEL_EXISTS" != "yes" ]; then
        REASON_LINE="$(echo "$PAM_ACTIVE_LINE" | sed 's/[[:space:]]*$//') 이나 wheel 그룹이 존재하지 않아 이 항목에 대해 취약합니다."
      else
        REASON_LINE="$(echo "$PAM_ACTIVE_LINE" | sed 's/[[:space:]]*$//') 이나 use_uid 또는 group=wheel 옵션이 없어 이 항목에 대해 취약합니다."
      fi
    fi

    DETAIL_CONTENT="$(cat <<EOF
pam_active_line=$(echo "$PAM_ACTIVE_LINE" | sed 's/[[:space:]]*$//')
wheel_exists=$WHEEL_EXISTS
wheel_members=$WHEEL_MEMBERS
su_bin=$SU_BIN
su_perm_octal=$SU_PERM_OCT
su_group=$SU_GROUP
EOF
)"
  else
    # 분기 2: PAM 규칙이 없을 때, su 바이너리 대체 통제 여부 확인
    if [ "$SU_ALT_OK" = "yes" ]; then
      STATUS="PASS"
      REASON_LINE="su_bin=$SU_BIN, perm=$SU_PERM_OCT, group=$SU_GROUP 로 설정되어 이 항목에 대해 양호합니다."
    else
      STATUS="FAIL"
      REASON_LINE="pam_wheel_rule=missing 및 su_bin=$SU_BIN, perm=$SU_PERM_OCT, group=$SU_GROUP 로 설정되어 이 항목에 대해 취약합니다."
    fi

    DETAIL_CONTENT="$(cat <<EOF
pam_wheel_rule=missing
wheel_exists=$WHEEL_EXISTS
wheel_members=$WHEEL_MEMBERS
su_bin=$SU_BIN
su_perm_octal=$SU_PERM_OCT
su_group=$SU_GROUP
EOF
)"
  fi
else
  # 분기 3: /etc/pam.d/su 없을 때, su 바이너리 대체 통제 여부 확인
  if [ "$SU_ALT_OK" = "yes" ]; then
    STATUS="PASS"
    REASON_LINE="pam_su_file_not_found 및 su_bin=$SU_BIN, perm=$SU_PERM_OCT, group=$SU_GROUP 로 설정되어 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    REASON_LINE="pam_su_file_not_found 및 su_bin=$SU_BIN, perm=$SU_PERM_OCT, group=$SU_GROUP 로 설정되어 이 항목에 대해 취약합니다."
  fi

  DETAIL_CONTENT="$(cat <<EOF
pam_su_file_not_found
wheel_exists=$WHEEL_EXISTS
wheel_members=$WHEEL_MEMBERS
su_bin=$SU_BIN
su_perm_octal=$SU_PERM_OCT
su_group=$SU_GROUP
EOF
)"
fi

GUIDE_LINE="자동 조치 시 관리자 권한 정책 및 운영 절차(허용 사용자/그룹, sudo 정책, 접근통제 체계)에 영향을 주어 서비스 접근 장애 또는 권한 설정 오류 위험이 존재하여 수동 조치가 필요합니다.\n관리자가 직접 확인 후 /etc/pam.d/su에 pam_wheel.so 설정(use_uid 또는 group=wheel)을 적용하거나 su 바이너리의 그룹을 wheel로 변경하고 권한을 4750으로 제한해 주시기 바랍니다."

# raw_evidence 구성 (각 문장 줄바꿈 구분 유지)
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
  | sed 's/\\/\\\\/g' \
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
