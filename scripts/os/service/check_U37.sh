#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-37
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : crontab 설정파일 권한 설정 미흡
# @Description : crontab 및 at 서비스 관련 파일의 권한 적절성 여부 점검
# @Criteria_Good : crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우
# @Criteria_Bad :  crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며, cron 및 at 관련 파일 권한이 640 이상인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-37 crontab 설정파일 권한 설정 미흡

# 기본 변수
ID="U-37"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/usr/bin/crontab /usr/bin/at /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny"

# 점검 명령
CHECK_COMMAND='
stat -c "%U %a %A %n" /usr/bin/crontab /usr/bin/at /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null;
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs; do
  [ -d "$d" ] && stat -c "%U %a %A %n" "$d" 2>/dev/null;
  [ -e "$d" ] && find "$d" -maxdepth 1 -type f -print -exec stat -c "%U %a %A %n" {} \; 2>/dev/null;
done;
( [ -f /etc/cron.allow ] && echo "[cron.allow]" && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/cron.allow 2>/dev/null ) || echo "cron.allow_not_found_or_empty";
( [ -f /etc/at.allow ] && echo "[at.allow]" && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/at.allow 2>/dev/null ) || echo "at.allow_not_found_or_empty";
'

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE=""

VULN_LIST=()
INFO_LIST=()

# 권한 비교 함수
perm_exceeds() {
  local cur="$1"
  local max="$2"
  [ -n "$cur" ] && [ "$cur" -gt "$max" ]
}

# 취약 근거 누적 함수
add_vuln() {
  local path="$1"
  local owner="$2"
  local perm="$3"
  local why="$4"
  VULN_LIST+=("${path} (owner=${owner}, perm=${perm}) - ${why}")
}

# 현재 상태 누적 함수
add_info() {
  local msg="$1"
  INFO_LIST+=("$msg")
}

# SUID/SGID/Sticky 포함 여부 확인 함수
has_suid_sgid_bits() {
  local mode="$1"
  if [[ "$mode" =~ ^[0-7]{4}$ ]]; then
    local high="${mode:0:1}"
    [ "$high" -ge 1 ] && return 0
  fi
  return 1
}

# 접근제어 파일(.allow/.deny) 구성을 점검 함수
check_access_control() {
  local allow_file="$1"
  local deny_file="$2"
  local svc_name="$3"

  local allow_ok=0

  if [ -f "$allow_file" ]; then
    local ao ap
    ao=$(stat -c '%U' "$allow_file" 2>/dev/null)
    ap=$(stat -c '%a' "$allow_file" 2>/dev/null)
    add_info "${allow_file}: owner=${ao}, perm=${ap}"

    [ "$ao" != "root" ] && { STATUS="FAIL"; add_vuln "$allow_file" "${ao:-unknown}" "${ap:-unknown}" "owner!=root"; }
    perm_exceeds "$ap" 640 && { STATUS="FAIL"; add_vuln "$allow_file" "${ao:-unknown}" "${ap:-unknown}" "perm>640"; }

    local users non_root
    users=$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$allow_file" 2>/dev/null | tr -d '\r')
    if [ -z "$users" ]; then
      STATUS="FAIL"
      add_vuln "$allow_file" "${ao:-unknown}" "${ap:-unknown}" "users=empty"
    else
      non_root=$(echo "$users" | awk 'tolower($0)!="root"{print}' | head -n 1)
      if [ -n "$non_root" ]; then
        STATUS="FAIL"
        add_vuln "$allow_file" "${ao:-unknown}" "${ap:-unknown}" "users_include_non_root(${non_root})"
      else
        allow_ok=1
      fi
    fi
  else
    add_info "${allow_file}: not_found"
  fi

  if [ "$allow_ok" -eq 0 ]; then
    if [ -f "$deny_file" ]; then
      local doo dp
      doo=$(stat -c '%U' "$deny_file" 2>/dev/null)
      dp=$(stat -c '%a' "$deny_file" 2>/dev/null)
      add_info "${deny_file}: owner=${doo}, perm=${dp}"

      [ "$doo" != "root" ] && { STATUS="FAIL"; add_vuln "$deny_file" "${doo:-unknown}" "${dp:-unknown}" "owner!=root"; }
      perm_exceeds "$dp" 640 && { STATUS="FAIL"; add_vuln "$deny_file" "${doo:-unknown}" "${dp:-unknown}" "perm>640"; }

      STATUS="FAIL"
      add_vuln "$deny_file" "${doo:-unknown}" "${dp:-unknown}" "${svc_name}.allow_not_found"
    else
      add_info "${deny_file}: not_found"
      STATUS="FAIL"
      add_vuln "${allow_file}/${deny_file}" "N/A" "N/A" "${svc_name}.allow_and_deny_not_found"
    fi
  fi
}

# 명령 파일 점검 
CRONTAB_CMD="/usr/bin/crontab"
if [ -f "$CRONTAB_CMD" ]; then
  O=$(stat -c '%U' "$CRONTAB_CMD" 2>/dev/null)
  P=$(stat -c '%a' "$CRONTAB_CMD" 2>/dev/null)
  add_info "${CRONTAB_CMD}: owner=${O}, perm=${P}"

  [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$CRONTAB_CMD" "${O:-unknown}" "${P:-unknown}" "owner!=root"; }
  perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$CRONTAB_CMD" "${O:-unknown}" "${P:-unknown}" "perm>750"; }
  if has_suid_sgid_bits "$P"; then
    STATUS="FAIL"
    add_vuln "$CRONTAB_CMD" "${O:-unknown}" "${P:-unknown}" "special_bits_on"
  fi
else
  add_info "${CRONTAB_CMD}: not_found"
fi

AT_CMD="/usr/bin/at"
if [ -f "$AT_CMD" ]; then
  O=$(stat -c '%U' "$AT_CMD" 2>/dev/null)
  P=$(stat -c '%a' "$AT_CMD" 2>/dev/null)
  add_info "${AT_CMD}: owner=${O}, perm=${P}"

  [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$AT_CMD" "${O:-unknown}" "${P:-unknown}" "owner!=root"; }
  perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$AT_CMD" "${O:-unknown}" "${P:-unknown}" "perm>750"; }
  if has_suid_sgid_bits "$P"; then
    STATUS="FAIL"
    add_vuln "$AT_CMD" "${O:-unknown}" "${P:-unknown}" "special_bits_on"
  fi
else
  add_info "${AT_CMD}: not_found"
fi

# 스풀 디렉터리/파일 점검
CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
for d in "${CRON_SPOOL_DIRS[@]}"; do
  if [ -d "$d" ]; then
    Od=$(stat -c '%U' "$d" 2>/dev/null)
    Pd=$(stat -c '%a' "$d" 2>/dev/null)
    add_info "${d}: owner=${Od}, perm=${Pd}"

    [ "$Od" != "root" ] && { STATUS="FAIL"; add_vuln "$d" "${Od:-unknown}" "${Pd:-unknown}" "dir_owner!=root"; }
    perm_exceeds "$Pd" 750 && { STATUS="FAIL"; add_vuln "$d" "${Od:-unknown}" "${Pd:-unknown}" "dir_perm>750"; }

    while IFS= read -r f; do
      O=$(stat -c '%U' "$f" 2>/dev/null)
      P=$(stat -c '%a' "$f" 2>/dev/null)
      add_info "${f}: owner=${O}, perm=${P}"

      [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "${O:-unknown}" "${P:-unknown}" "owner!=root"; }
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$f" "${O:-unknown}" "${P:-unknown}" "perm>640"; }
    done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
  else
    add_info "${d}: not_found_or_not_dir"
  fi
done

AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")
for d in "${AT_SPOOL_DIRS[@]}"; do
  if [ -d "$d" ]; then
    Od=$(stat -c '%U' "$d" 2>/dev/null)
    Pd=$(stat -c '%a' "$d" 2>/dev/null)
    add_info "${d}: owner=${Od}, perm=${Pd}"

    [ "$Od" != "root" ] && { STATUS="FAIL"; add_vuln "$d" "${Od:-unknown}" "${Pd:-unknown}" "dir_owner!=root"; }
    perm_exceeds "$Pd" 750 && { STATUS="FAIL"; add_vuln "$d" "${Od:-unknown}" "${Pd:-unknown}" "dir_perm>750"; }

    while IFS= read -r f; do
      O=$(stat -c '%U' "$f" 2>/dev/null)
      P=$(stat -c '%a' "$f" 2>/dev/null)
      add_info "${f}: owner=${O}, perm=${P}"

      [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "${O:-unknown}" "${P:-unknown}" "owner!=root"; }
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$f" "${O:-unknown}" "${P:-unknown}" "perm>640"; }
    done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
  else
    add_info "${d}: not_found_or_not_dir"
  fi
done

# /etc/cron* 점검
CRON_ETC_ITEMS=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for it in "${CRON_ETC_ITEMS[@]}"; do
  if [ -e "$it" ]; then
    O=$(stat -c '%U' "$it" 2>/dev/null)
    P=$(stat -c '%a' "$it" 2>/dev/null)
    add_info "${it}: owner=${O}, perm=${P}"

    [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$it" "${O:-unknown}" "${P:-unknown}" "owner!=root"; }

    if [ -d "$it" ]; then
      perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$it" "${O:-unknown}" "${P:-unknown}" "dir_perm>750"; }
      while IFS= read -r f; do
        O2=$(stat -c '%U' "$f" 2>/dev/null)
        P2=$(stat -c '%a' "$f" 2>/dev/null)
        add_info "${f}: owner=${O2}, perm=${P2}"

        [ "$O2" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "${O2:-unknown}" "${P2:-unknown}" "owner!=root"; }
        perm_exceeds "$P2" 640 && { STATUS="FAIL"; add_vuln "$f" "${O2:-unknown}" "${P2:-unknown}" "perm>640"; }
      done < <(find "$it" -maxdepth 1 -type f 2>/dev/null)
    else
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$it" "${O:-unknown}" "${P:-unknown}" "perm>640"; }
    fi
  else
    add_info "${it}: not_found"
  fi
done

# 접근제어 파일 점검
check_access_control "/etc/cron.allow" "/etc/cron.deny" "cron"
check_access_control "/etc/at.allow"   "/etc/at.deny"   "at"


# 취약 가정 자동 조치
GUIDE_LINE="자동 조치:
/usr/bin/crontab 및 /usr/bin/at의 소유자와 그룹을 root:root로 맞추고 권한을 750으로 설정하며 SUID/SGID 비트를 제거합니다.
/etc/crontab, /etc/cron.d 및 /etc/cron.* 디렉터리 내부 파일, /var/spool/cron 및 /var/spool/at 하위 작업 파일의 소유자와 그룹을 root:root로 맞추고 파일 권한을 640, 관련 디렉터리 권한을 750으로 표준화합니다.
/etc/cron.allow 및 /etc/at.allow를 생성 또는 정규화하여 root만 포함하도록 설정하고 /etc/cron.deny 및 /etc/at.deny는 제거합니다.
주의사항:
root 외 계정이 cron 또는 at 사용이 필요했던 환경에서는 예약 작업 등록 또는 실행이 제한되어 운영 작업이 중단될 수 있습니다.
파일 소유자나 권한을 표준화하는 과정에서 기존 운영 도구나 배포 정책이 기대하던 권한과 달라져 접근 오류가 발생할 수 있으므로 적용 전 영향 범위를 확인해야 합니다."


DETAIL_CONTENT=$(printf "%s\n" "${INFO_LIST[@]}")

if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="/usr/bin/crontab 및 /usr/bin/at의 owner=root, perm<=750이며 특수비트가 없고 /etc/cron.allow 및 /etc/at.allow가 root만 허용하며 cron/at 관련 파일은 perm<=640 및 관련 디렉터리는 perm<=750으로 설정되어 있어 이 항목에 대해 양호합니다."
else
  VULN_SUMMARY=$(printf "%s\n" "${VULN_LIST[@]}" | head -n 5 | sed ':a;N;$!ba;s/\n/; /g')
  [ -z "$VULN_SUMMARY" ] && VULN_SUMMARY="설정 값이 기준을 충족하지 않습니다."
  REASON_LINE="$VULN_SUMMARY 로 설정되어 있어 이 항목에 대해 취약합니다."
fi

# raw_evidence 구성
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
