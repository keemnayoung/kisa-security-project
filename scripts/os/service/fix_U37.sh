#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-37
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : crontab 설정파일 권한 설정 미흡
# @Description : crontab 및 at 서비스 관련 파일의 권한 설정 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정 분기점
ID="U-37"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""

CRONTAB_CMD="/usr/bin/crontab"
AT_CMD="/usr/bin/at"

CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
CRON_ETC_FILES=("/etc/crontab")
CRON_ETC_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")

CRON_ALLOW="/etc/cron.allow"
CRON_DENY="/etc/cron.deny"
AT_ALLOW="/etc/at.allow"
AT_DENY="/etc/at.deny"

TARGET_FILE="$CRONTAB_CMD
$AT_CMD
${CRON_SPOOL_DIRS[*]}
${CRON_ETC_FILES[*]}
${CRON_ETC_DIRS[*]}
${AT_SPOOL_DIRS[*]}
$CRON_ALLOW
$CRON_DENY
$AT_ALLOW
$AT_DENY"

CHECK_COMMAND='
for p in /usr/bin/crontab /usr/bin/at /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
  [ -e "$p" ] && stat -c "%U %G %a %n" "$p" 2>/dev/null || echo "not_found:$p";
done;
for d in /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs; do
  [ -d "$d" ] && (stat -c "%U %G %a %n" "$d" 2>/dev/null; find "$d" -maxdepth 1 -type f -exec stat -c "%U %G %a %n" {} \; 2>/dev/null | head -n 50) || echo "dir_not_found:$d";
done;
for f in /etc/crontab; do
  [ -f "$f" ] && stat -c "%U %G %a %n" "$f" 2>/dev/null || echo "not_found:$f";
done;
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] && stat -c "%U %G %a %n" "$d" 2>/dev/null || echo "dir_not_found:$d";
done;
'

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MODIFIED=0
FAIL_FLAG=0

# 유틸리티 함수 정의 분기점
append_err() {
  if [ -n "$ACTION_ERR_LOG" ]; then
    ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
  else
    ACTION_ERR_LOG="$1"
  fi
}

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

perm_exceeds() {
  local cur="$1"
  local max="$2"
  [ -z "$cur" ] && return 1
  [ -z "$max" ] && return 1
  echo "$cur" | grep -Eq '^[0-7]{3,4}$' || return 1
  echo "$max" | grep -Eq '^[0-7]{3,4}$' || return 1
  [ "$cur" -gt "$max" ]
}

ensure_owner_root_root() {
  local path="$1"
  [ -e "$path" ] || return 0
  chown root:root "$path" 2>/dev/null || { append_err "$path 소유자 변경 실패"; FAIL_FLAG=1; }
}

ensure_mode() {
  local path="$1"
  local mode="$2"
  [ -e "$path" ] || return 0
  chmod "$mode" "$path" 2>/dev/null || { append_err "$path 권한 변경 실패"; FAIL_FLAG=1; }
}

remove_suid_sgid() {
  local path="$1"
  [ -e "$path" ] || return 0
  chmod u-s,g-s "$path" 2>/dev/null || { append_err "$path SUID/SGID 제거 실패"; FAIL_FLAG=1; }
}

verify_file_max() {
  local path="$1"
  local max="$2"
  [ -f "$path" ] || return 0
  local owner group perm
  owner="$(stat -c '%U' "$path" 2>/dev/null)" || owner=""
  group="$(stat -c '%G' "$path" 2>/dev/null)" || group=""
  perm="$(stat -c '%a' "$path" 2>/dev/null)" || perm=""

  if [ -z "$owner" ] || [ -z "$group" ] || [ -z "$perm" ]; then
    append_detail "$path: stat_failed"
    FAIL_FLAG=1
    return 0
  fi

  append_detail "$path: $owner:$group $perm"
  [ "$owner" = "root" ] || FAIL_FLAG=1
  [ "$group" = "root" ] || FAIL_FLAG=1
  if perm_exceeds "$perm" "$max"; then
    FAIL_FLAG=1
  fi
}

verify_dir_max() {
  local path="$1"
  local max="$2"
  [ -d "$path" ] || return 0
  local owner group perm
  owner="$(stat -c '%U' "$path" 2>/dev/null)" || owner=""
  group="$(stat -c '%G' "$path" 2>/dev/null)" || group=""
  perm="$(stat -c '%a' "$path" 2>/dev/null)" || perm=""

  if [ -z "$owner" ] || [ -z "$group" ] || [ -z "$perm" ]; then
    append_detail "$path: stat_failed"
    FAIL_FLAG=1
    return 0
  fi

  append_detail "$path: $owner:$group $perm"
  [ "$owner" = "root" ] || FAIL_FLAG=1
  [ "$group" = "root" ] || FAIL_FLAG=1
  if perm_exceeds "$perm" "$max"; then
    FAIL_FLAG=1
  fi
}

# 실행 권한 사전 체크 분기점
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 crontab 및 at 관련 파일 권한 조치를 수행할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="current_user_uid=$(id -u)"
  RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)
  RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
  echo ""
  cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF
  exit 1
fi

# 1) 명령어 파일 조치 분기점
if [ -f "$CRONTAB_CMD" ]; then
  cp -a "$CRONTAB_CMD" "${CRONTAB_CMD}.bak_${TIMESTAMP}" 2>/dev/null || true
  ensure_owner_root_root "$CRONTAB_CMD"
  ensure_mode "$CRONTAB_CMD" 750
  remove_suid_sgid "$CRONTAB_CMD"
  MODIFIED=1
fi

if [ -f "$AT_CMD" ]; then
  cp -a "$AT_CMD" "${AT_CMD}.bak_${TIMESTAMP}" 2>/dev/null || true
  ensure_owner_root_root "$AT_CMD"
  ensure_mode "$AT_CMD" 750
  remove_suid_sgid "$AT_CMD"
  MODIFIED=1
fi

# 2) Cron 스풀 디렉터리 조치 분기점
for dir in "${CRON_SPOOL_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    ensure_owner_root_root "$dir"
    ensure_mode "$dir" 750
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      ensure_owner_root_root "$f"
      ensure_mode "$f" 640
    done
    MODIFIED=1
  fi
done

# 3) /etc/crontab 조치 분기점
for f in "${CRON_ETC_FILES[@]}"; do
  if [ -f "$f" ]; then
    cp -a "$f" "${f}.bak_${TIMESTAMP}" 2>/dev/null || true
    ensure_owner_root_root "$f"
    ensure_mode "$f" 640
    MODIFIED=1
  fi
done

# 4) /etc/cron.d 등 디렉터리 조치 분기점
for d in "${CRON_ETC_DIRS[@]}"; do
  if [ -d "$d" ]; then
    ensure_owner_root_root "$d"
    ensure_mode "$d" 750
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      ensure_owner_root_root "$f"
      ensure_mode "$f" 640
    done
    MODIFIED=1
  fi
done

# 5) At 스풀 디렉터리 조치 분기점
for dir in "${AT_SPOOL_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    ensure_owner_root_root "$dir"
    ensure_mode "$dir" 750
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      ensure_owner_root_root "$f"
      ensure_mode "$f" 640
    done
    MODIFIED=1
  fi
done

# 6) 접근제어 파일 조치 분기점
if [ -f "$CRON_DENY" ]; then
  rm -f "$CRON_DENY" 2>/dev/null && MODIFIED=1
fi
if [ -f "$AT_DENY" ]; then
  rm -f "$AT_DENY" 2>/dev/null && MODIFIED=1
fi

echo "root" > "$CRON_ALLOW" 2>/dev/null
ensure_owner_root_root "$CRON_ALLOW"
ensure_mode "$CRON_ALLOW" 640

echo "root" > "$AT_ALLOW" 2>/dev/null
ensure_owner_root_root "$AT_ALLOW"
ensure_mode "$AT_ALLOW" 640
MODIFIED=1

# 7) 조치 후 검증 및 상태 수집 분기점
verify_file_max "$CRONTAB_CMD" 750
verify_file_max "$AT_CMD" 750

for dir in "${CRON_SPOOL_DIRS[@]}"; do
  verify_dir_max "$dir" 750
  if [ -d "$dir" ]; then
    for f in "$dir"/*; do [ -f "$f" ] && verify_file_max "$f" 640; done
  fi
done

for f in "${CRON_ETC_FILES[@]}"; do verify_file_max "$f" 640; done

for d in "${CRON_ETC_DIRS[@]}"; do
  verify_dir_max "$d" 750
  if [ -d "$d" ]; then
    for f in "$d"/*; do [ -f "$f" ] && verify_file_max "$f" 640; done
  fi
done

verify_file_max "$CRON_ALLOW" 640
verify_file_max "$AT_ALLOW" 640
[ -f "$CRON_DENY" ] && { append_detail "$CRON_DENY: exists"; FAIL_FLAG=1; }
[ -f "$AT_DENY" ] && { append_detail "$AT_DENY: exists"; FAIL_FLAG=1; }

# 최종 판정 및 REASON_LINE 확정 분기점
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="crontab 및 at 관련 파일의 소유자를 root로 변경하고 권한을 기준에 맞게 제한하여 조치를 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  REASON_LINE="일부 파일의 소유자가 root가 아니거나 허용된 권한 범위를 초과하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="${DETAIL_CONTENT}\n[Error_Log]\n${ACTION_ERR_LOG}"
fi

# RAW_EVIDENCE 구성 분기점
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 결과 출력 분기점
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF