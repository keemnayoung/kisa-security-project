#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-13
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : 비밀번호 암호화 알고리즘을 강력한 SHA512로 설정하여 보안 강화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-13"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""     
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

DEFS_FILE="/etc/login.defs"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

TARGET_FILE="$DEFS_FILE $PAM_SYSTEM_AUTH $PAM_PASSWORD_AUTH"
CHECK_COMMAND='
grep -nE "^[[:space:]]*ENCRYPT_METHOD[[:space:]]+" /etc/login.defs 2>/dev/null;
grep -nE "^[[:space:]]*password[[:space:]]+.*pam_unix\.so" /etc/pam.d/system-auth 2>/dev/null;
grep -nE "^[[:space:]]*password[[:space:]]+.*pam_unix\.so" /etc/pam.d/password-auth 2>/dev/null
' | tr '\n' '; ' | sed 's/[[:space:]]\+/ /g'

MODIFIED=0
ERR_FLAG=0

# PAM 파일 내 SHA512 옵션 적용 여부 확인 및 추가 함수
ensure_pam_sha512() {
  local file="$1"

  [ -f "$file" ] || return 2
  if ! grep -Eqi '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$file" 2>/dev/null; then
    return 3
  fi

  if grep -Ei '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$file" 2>/dev/null | grep -Eqi '(^|[[:space:]])(sha512|sha256|yescrypt)($|[[:space:]])'; then
    return 0
  fi

  sed -i -E '/^[[:space:]]*password[[:space:]]+.*pam_unix\.so/ s/[[:space:]]*$/ sha512/' "$file" 2>/dev/null
  return 1
}

# 조치 수행: login.defs 및 PAM 설정 수정 분기점
if [ -f "$DEFS_FILE" ]; then
  # 1) login.defs 암호화 알고리즘 수정
  CURRENT_VAL=$(grep -E '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}' | tr -d '[:space:]')

  if [ "$CURRENT_VAL" != "SHA512" ]; then
    MODIFIED=1
  fi

  if grep -qE '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null; then
    sed -i 's/^[[:space:]]*ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' "$DEFS_FILE" 2>/dev/null
  else
    echo "ENCRYPT_METHOD SHA512" >> "$DEFS_FILE" 2>/dev/null
    MODIFIED=1
  fi

  # 2) PAM 설정 파일 수정 분기점
  PAM_MOD_MSGS=""

  ensure_pam_sha512 "$PAM_SYSTEM_AUTH"
  PAM_RES=$?
  if [ $PAM_RES -eq 1 ]; then
    MODIFIED=1
    PAM_MOD_MSGS="${PAM_MOD_MSGS}system-auth: sha512 옵션 추가"$'\n'
  elif [ $PAM_RES -eq 3 ]; then
    ERR_FLAG=1
    PAM_MOD_MSGS="${PAM_MOD_MSGS}system-auth: pam_unix.so password 라인 없음"$'\n'
  elif [ $PAM_RES -eq 2 ]; then
    ERR_FLAG=1
    PAM_MOD_MSGS="${PAM_MOD_MSGS}system-auth: 파일 없음"$'\n'
  fi

  if [ -f "$PAM_PASSWORD_AUTH" ]; then
    ensure_pam_sha512 "$PAM_PASSWORD_AUTH"
    PAM_RES2=$?
    if [ $PAM_RES2 -eq 1 ]; then
      MODIFIED=1
      PAM_MOD_MSGS="${PAM_MOD_MSGS}password-auth: sha512 옵션 추가"$'\n'
    elif [ $PAM_RES2 -eq 3 ]; then
      ERR_FLAG=1
      PAM_MOD_MSGS="${PAM_MOD_MSGS}password-auth: pam_unix.so password 라인 없음"$'\n'
    fi
  else
    PAM_MOD_MSGS="${PAM_MOD_MSGS}password-auth: 파일 없음"$'\n'
  fi

  # 조치 후 최종 설정 상태 데이터 수집 분기점
  AFTER_LINE_DEFS=$(grep -nE '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null | tail -n 1 | sed '/^[[:space:]]*$/d')
  RESULT_VAL=$(grep -E '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}' | tr -d '[:space:]')

  AFTER_LINE_SYS=$(grep -nE '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$PAM_SYSTEM_AUTH" 2>/dev/null | sed '/^[[:space:]]*$/d' | tail -n 3)
  AFTER_LINE_PW=""
  if [ -f "$PAM_PASSWORD_AUTH" ]; then
    AFTER_LINE_PW=$(grep -nE '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$PAM_PASSWORD_AUTH" 2>/dev/null | sed '/^[[:space:]]*$/d' | tail -n 3)
  fi

  # DETAIL_CONTENT 구성 (현재 설정값 정보만 나열)
  DETAIL_CONTENT="login_defs_setting: $AFTER_LINE_DEFS
system_auth_setting: $AFTER_LINE_SYS
password_auth_setting: ${AFTER_LINE_PW:-not_found/skip}"

  # 최종 성공 판정 및 REASON_LINE 구성 분기점
  SYS_HAS_SAFE=$(grep -Ei '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$PAM_SYSTEM_AUTH" 2>/dev/null | grep -Eqi '(^|[[:space:]])(sha512|sha256|yescrypt)($|[[:space:]])'; echo $?)
  
  if [ "$RESULT_VAL" = "SHA512" ] && [ $SYS_HAS_SAFE -eq 0 ] && [ $ERR_FLAG -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="암호화 알고리즘을 SHA512로 변경하고 PAM 모듈의 password 설정에 sha512 옵션을 추가하여 조치를 완료하여 이 항목에 대해 양호합니다."
  else
    IS_SUCCESS=0
    if [ "$RESULT_VAL" != "SHA512" ]; then
      REASON_LINE="login.defs 파일에 알고리즘이 SHA512로 정상 반영되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    elif [ $SYS_HAS_SAFE -ne 0 ]; then
      REASON_LINE="PAM 설정 파일에 안전한 암호화 알고리즘 옵션이 누락된 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    else
      REASON_LINE="PAM 모듈 내 필수 설정 라인을 찾을 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
    fi
    
    if [ -n "$PAM_MOD_MSGS" ]; then
      DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"action_error_note: $(printf "%s" "$PAM_MOD_MSGS" | tr '\n' ' ')"
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="/etc/login.defs 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="target_file_not_found"
fi

# RAW_EVIDENCE 구성 및 JSON 이스케이프
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

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