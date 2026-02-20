#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-05
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : UID가 0인 일반 계정 존재
# @Description : 관리자 권한(UID 0)을 가진 일반 계정의 UID를 일반 사용자 번호로 변경
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-05"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PASSWD_FILE="/etc/passwd"
TARGET_FILE="$PASSWD_FILE"

CHECK_COMMAND="(command -v getent >/dev/null 2>&1 && getent passwd | awk -F: '\$3==0 && \$1!=\"root\" {print \$1\":\"\$3\":\"\$0}') || ([ -f /etc/passwd ] && awk -F: '\$3==0 && \$1!=\"root\" {print \$1\":\"\$3\":\"\$0}' /etc/passwd 2>/dev/null) || echo \"passwd_not_found\""

MODIFIED=0
FAIL_FLAG=0
DETAIL_CONTENT=""

# 사용 중이지 않은 신규 UID 추출 함수
get_unused_uid() {
  local uid=2000
  while getent passwd "$uid" >/dev/null 2>&1; do
    uid=$((uid+1))
  done
  echo "$uid"
}

# UID 변경에 따른 파일 소유권 재설정 함수
fix_file_ownership_by_uid() {
  local old_uid="$1"
  local user="$2"

  find / -xdev \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
    -uid "$old_uid" -exec chown -h "$user" {} + 2>/dev/null
}

# 계정의 프로세스 점유 여부 확인 함수
is_user_in_use() {
  local user="$1"
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -u "$user" >/dev/null 2>&1
    return $?
  else
    ps -u "$user" >/dev/null 2>&1
    return $?
  fi
}

# PID 1(systemd/init)과 계정 매핑 여부 확인 함수
is_pid1_mapped_to_user() {
  local user="$1"
  local u
  u=$(ps -p 1 -o user= 2>/dev/null | awk '{print $1}')
  [ "$u" = "$user" ]
}

# 조치 수행 가능 여부 확인 분기점
if [ ! -f "$PASSWD_FILE" ]; then
  IS_SUCCESS=0
  REASON_LINE="/etc/passwd 파일을 확인할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="passwd_not_found"
else
  EXTRA_ROOT_LOCAL=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$PASSWD_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')

  if [ -z "$EXTRA_ROOT_LOCAL" ]; then
    IS_SUCCESS=1
    REASON_LINE="root 이외에 UID가 0인 계정이 존재하지 않아 별도의 변경 없이 이 항목에 대해 양호합니다."
    DETAIL_CONTENT="UID 0 사용자: root"
  else
    # 프로세스 사용 여부 및 PID 1 매핑에 따른 조치 중단
    BLOCKED_USERS=""
    for user in $EXTRA_ROOT_LOCAL; do
      if is_pid1_mapped_to_user "$user"; then
        BLOCKED_USERS="${BLOCKED_USERS}${user}:pid1_mapped"$'\n'
      elif is_user_in_use "$user"; then
        BLOCKED_USERS="${BLOCKED_USERS}${user}:in_use"$'\n'
      fi
    done
    BLOCKED_USERS=$(printf "%s" "$BLOCKED_USERS" | sed '/^$/d')

    if [ -n "$BLOCKED_USERS" ]; then
      IS_SUCCESS=0
      FAIL_FLAG=1
      REASON_LINE="해당 계정이 프로세스에서 사용 중이거나 시스템 핵심 서비스에 매핑되어 있는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
      DETAIL_CONTENT="$BLOCKED_USERS"
    else
      # 실제 UID 변경 수행
      for user in $EXTRA_ROOT_LOCAL; do
        OLD_UID=$(awk -F: -v U="$user" '$1==U {print $3}' "$PASSWD_FILE" 2>/dev/null)
        NEW_UID=$(get_unused_uid)

        USERMOD_ERR=""
        USERMOD_ERR=$(usermod -u "$NEW_UID" "$user" 2>&1 >/dev/null)
        RC=$?

        if [ $RC -eq 0 ]; then
          MODIFIED=1
          if [ -n "$OLD_UID" ]; then
            fix_file_ownership_by_uid "$OLD_UID" "$user"
          fi
        else
          FAIL_FLAG=1
          DETAIL_CONTENT="${DETAIL_CONTENT}${user}:usermod_failed:${USERMOD_ERR}"$'\n'
        fi
      done

      # 조치 결과 재수집 및 최종 판정
      REMAIN_USERS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$PASSWD_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')

      if [ -z "$REMAIN_USERS" ] && [ "$FAIL_FLAG" -eq 0 ]; then
        IS_SUCCESS=1
        REASON_LINE="root 이외의 UID 0 계정을 미사용 중인 일반 UID 번호로 변경 완료하여 이 항목에 대해 양호합니다."
        DETAIL_CONTENT="모든 일반 계정 UID 변경 완료 (root 계정만 UID 0 유지)"
      else
        IS_SUCCESS=0
        REASON_LINE="usermod 실행 중 오류가 발생했거나 일부 계정의 UID가 변경되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
        
        if [ -z "$(printf "%s" "$DETAIL_CONTENT" | sed '/^$/d')" ] && [ -n "$REMAIN_USERS" ]; then
          DETAIL_CONTENT="남아있는 UID 0 계정: $REMAIN_USERS"
        else
          if [ -n "$REMAIN_USERS" ]; then
            DETAIL_CONTENT="$(printf "%s\n남아있는 계정: %s" "$(printf "%s" "$DETAIL_CONTENT" | sed '/^$/d')" "$REMAIN_USERS" | sed '/^$/d')"
          else
            DETAIL_CONTENT="$(printf "%s" "$DETAIL_CONTENT" | sed '/^$/d')"
          fi
        fi
      fi
    fi
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