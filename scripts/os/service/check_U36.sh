#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-36
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : r 계열 서비스 비활성화
# @Description : r-command 서비스 비활성화 여부 점검
# @Criteria_Good : 불필요한 r 계열 서비스가 비활성화된 경우
# @Criteria_Bad : 불필요한 r 계열 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-36"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/inetd.conf /etc/xinetd.d/(rsh|rlogin|rexec|shell|login|exec) systemd(unit/service/socket) /etc/hosts.equiv /home/*/.rhosts"
CHECK_COMMAND='( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)" || echo "inetd_conf_not_found_or_no_r_services" ); ( for f in /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec; do [ -f "$f" ] && grep -nEv "^[[:space:]]*#" "$f" | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" && echo "xinetd_disable_no:$f"; done ); ( systemctl list-units --type=service --all 2>/dev/null | grep -E "(rlogin|rsh|rexec|shell|login|exec)\.service" | awk "{print \$1}" ); ( systemctl list-units --type=socket --all 2>/dev/null | grep -E "(rlogin|rsh|rexec|shell|login|exec)\.socket" | awk "{print \$1}" ); ( systemctl list-unit-files 2>/dev/null | grep -E "^(rlogin|rsh|rexec|shell|login|exec)\.(service|socket)[[:space:]]+" || echo "no_r_unit_files" ); ( [ -f /etc/hosts.equiv ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.equiv || echo "hosts_equiv_not_found_or_empty" ); ( find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null -print -exec sh -c '"'"'grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$1" >/dev/null 2>&1 && echo "rhosts_has_entries:$1" || echo "rhosts_empty_or_commented:$1"'"'"' _ {} \; 2>/dev/null || echo "no_rhosts_found" )'

DETAIL_CONTENT=""
REASON_LINE=""

VULNERABLE=0
DETAIL_LINES=""
REASONS=""

R_SERVICES=("rsh" "rlogin" "rexec" "shell" "login" "exec")

append_reason() {
  if [ -n "$REASONS" ]; then
    REASONS="${REASONS}; $1"
  else
    REASONS="$1"
  fi
}

append_detail_line() {
  if [ -n "$DETAIL_LINES" ]; then
    DETAIL_LINES="${DETAIL_LINES}"$'\n'"$1"
  else
    DETAIL_LINES="$1"
  fi
}

# [inetd] /etc/inetd.conf: r 계열 활성 라인(주석 제외) 수집
INETD_POST="inetd_conf_missing"
INETD_HITS=""
if [ -f "/etc/inetd.conf" ]; then
  INETD_HITS="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)' | head -n 20)"
  if [ -n "$INETD_HITS" ]; then
    INETD_POST="$INETD_HITS"
    VULNERABLE=1
    append_reason "/etc/inetd.conf에서 r 계열 활성 라인이 존재(${INETD_HITS%%$'\n'*})"
  else
    INETD_POST="no_active_r_services"
  fi
fi
append_detail_line "inetd_active_lines=$INETD_POST"

# [xinetd] /etc/xinetd.d/<svc>: disable 설정 수집 및 disable=no 여부 확인
XINETD_DISABLE_NO_FOUND=0
for svc in "${R_SERVICES[@]}"; do
  XFILE="/etc/xinetd.d/${svc}"
  if [ -f "$XFILE" ]; then
    DISABLE_LINE="$(grep -nEv '^[[:space:]]*#' "$XFILE" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
    [ -z "$DISABLE_LINE" ] && DISABLE_LINE="disable_setting_not_found"
    if grep -nEv '^[[:space:]]*#' "$XFILE" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)'; then
      XINETD_DISABLE_NO_FOUND=1
      VULNERABLE=1
      append_reason "${XFILE}에 disable=no 설정이 존재(${DISABLE_LINE})"
    fi
    append_detail_line "xinetd_${svc}_disable_line=$DISABLE_LINE"
  else
    append_detail_line "xinetd_${svc}_disable_line=file_missing"
  fi
done

# [systemd] unit-files/active/enabled 상태 수집(존재하는 것만)
SYSTEMD_BAD=0
SYSTEMD_UNITS="$(systemctl list-unit-files 2>/dev/null | awk '$1 ~ /^(rsh|rlogin|rexec|shell|login|exec)\.(service|socket)$/ {print $1" "$2}' | head -n 100)"
[ -z "$SYSTEMD_UNITS" ] && SYSTEMD_UNITS="systemd_units_not_found"

append_detail_line "systemd_unit_files=$SYSTEMD_UNITS"

if command -v systemctl >/dev/null 2>&1; then
  for base in "${R_SERVICES[@]}"; do
    for u in "${base}.service" "${base}.socket"; do
      if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
        ENA="$(systemctl is-enabled "$u" 2>/dev/null || echo 'unknown')"
        ACT="$(systemctl is-active  "$u" 2>/dev/null || echo 'unknown')"
        append_detail_line "systemd_${u}_is_enabled=$ENA"
        append_detail_line "systemd_${u}_is_active=$ACT"
        if echo "$ENA" | grep -qiE '^enabled' || echo "$ACT" | grep -qiE '^active'; then
          SYSTEMD_BAD=1
          VULNERABLE=1
          append_reason "systemd에서 ${u} 상태가 enabled/active(${ENA}/${ACT})"
        fi
      fi
    done
  done
else
  append_detail_line "systemctl=not_found"
fi

# [trust] /etc/hosts.equiv 및 /home/*/.rhosts 유효 설정(주석/공백 제외) 수집
HOSTS_EQ_AFTER="hosts_equiv_missing"
if [ -f "/etc/hosts.equiv" ]; then
  HOSTS_EQ_LINES="$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts.equiv 2>/dev/null | head -n 20)"
  if [ -n "$HOSTS_EQ_LINES" ]; then
    HOSTS_EQ_AFTER="$HOSTS_EQ_LINES"
    VULNERABLE=1
    append_reason "/etc/hosts.equiv에 유효 설정이 존재(${HOSTS_EQ_LINES%%$'\n'*})"
  else
    HOSTS_EQ_AFTER="no_effective_entries"
  fi
fi
append_detail_line "hosts_equiv_effective_lines=$HOSTS_EQ_AFTER"

RHOSTS_AFTER_SUMMARY=""
RHOSTS_LIST="$(find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null | head -n 50)"
if [ -n "$RHOSTS_LIST" ]; then
  while IFS= read -r rf; do
    [ -z "$rf" ] && continue
    RH_EFF="$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$rf" 2>/dev/null | head -n 5)"
    if [ -n "$RH_EFF" ]; then
      VULNERABLE=1
      append_reason "${rf}에 유효 설정이 존재(${RH_EFF%%$'\n'*})"
      if [ -n "$RHOSTS_AFTER_SUMMARY" ]; then
        RHOSTS_AFTER_SUMMARY="${RHOSTS_AFTER_SUMMARY}"$'\n'"${rf}:$RH_EFF"
      else
        RHOSTS_AFTER_SUMMARY="${rf}:$RH_EFF"
      fi
    else
      if [ -n "$RHOSTS_AFTER_SUMMARY" ]; then
        RHOSTS_AFTER_SUMMARY="${RHOSTS_AFTER_SUMMARY}"$'\n'"${rf}:no_effective_entries"
      else
        RHOSTS_AFTER_SUMMARY="${rf}:no_effective_entries"
      fi
    fi
  done <<< "$RHOSTS_LIST"
else
  RHOSTS_AFTER_SUMMARY="no_rhosts_files"
fi
append_detail_line "rhosts_effective_lines=$RHOSTS_AFTER_SUMMARY"

# DETAIL_CONTENT: 양호/취약과 무관하게 현재 설정 값만 출력
DETAIL_CONTENT="$(printf "%s" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

# PASS/FAIL 문장(한 문장) + detail 구성
if [ "$VULNERABLE" -eq 1 ]; then
  STATUS="FAIL"
  if [ -z "$REASONS" ]; then
    REASON_LINE="취약으로 판정되는 설정이 확인되어 이 항목에 대해 취약합니다."
  else
    REASON_LINE="${REASONS}로 설정되어 있어 이 항목에 대해 취약합니다."
  fi
else
  STATUS="PASS"
  REASON_LINE="inetd에서 r 계열 활성 라인이 없고 xinetd에 disable=no 설정이 없으며 systemd에서 enabled/active 상태가 없고 /etc/hosts.equiv 및 /home/*/.rhosts에 유효 설정이 없어 이 항목에 대해 양호합니다."
fi

# guide: 취약 시 자동 조치 가정(조치 방법 + 주의사항)
GUIDE_LINE="자동 조치:
/etc/inetd.conf에서 rsh,rlogin,rexec,shell,login,exec 활성 라인을 주석 처리하고 inetd가 존재하면 재시작합니다.
/etc/xinetd.d/*에서 disable=no를 disable=yes로 변경하고 xinetd가 존재하면 재시작합니다.
systemd에서 rsh/rlogin/rexec/shell/login/exec의 service 및 socket을 stop 후 disable 및 mask 처리합니다.
/etc/hosts.equiv 및 /home/*/.rhosts의 유효 설정을 주석 처리하여 신뢰 기반 접속을 무력화합니다.
주의사항: 
r 계열 서비스가 백업/클러스터링/레거시 운영에 사용 중인 환경에서는 접속/연동이 중단될 수 있으므로 사전 사용 여부 확인과 설정 백업이 필요합니다.
inetd/xinetd/systemd 재시작 또는 유닛 비활성화는 운영 중인 서비스에 일시적인 영향이 있을 수 있으므로 점검 창구/점검 시간에 수행하는 것이 안전합니다."

# raw_evidence 구성 (모든 값은 \n 기준으로 문장 구분 가능)
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

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
