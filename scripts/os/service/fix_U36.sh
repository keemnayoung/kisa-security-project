#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-36
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : r 계열 서비스 비활성화
# @Description : r-command 서비스 비활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-36"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

R_SERVICES=("rsh" "rlogin" "rexec" "shell" "login" "exec")

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)" ) || echo "inetd_no_active_r_services";
for s in rsh rlogin rexec shell login exec; do
  [ -f "/etc/xinetd.d/$s" ] && echo "xinetd_file:$s" && grep -nEv "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=" | head -n 1 || true;
done;
(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -Ei "^(rsh|rlogin|rexec|shell|login|exec)\.(service|socket)[[:space:]]") || echo "systemd_units_not_found";
( [ -f /etc/hosts.equiv ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.equiv ) || echo "hosts_equiv_not_found_or_empty";
( find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null -print ) || echo "no_rhosts_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/(rsh,rlogin,rexec,shell,login,exec)
systemd(rsh/rlogin/rexec/shell/login/exec)
 /etc/hosts.equiv
/home/*/.rhosts"

ACTION_ERR_LOG=""

# 실행 권한 체크
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 sed/systemctl 조치가 실패할 수 있습니다."
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MODIFIED=0

# 유틸리티 함수 정의
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

restart_inetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^inetd\.service" || return 0
  systemctl restart inetd 2>/dev/null || append_err "systemctl restart inetd 실패"
}

restart_xinetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^xinetd\.service" || return 0
  systemctl restart xinetd 2>/dev/null || append_err "systemctl restart xinetd 실패"
}

disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

neutralize_trust_file() {
  local f="$1"
  [ -f "$f" ] || return 0

  if ! grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$f" >/dev/null 2>&1; then
    return 0
  fi

  cp -a "$f" "${f}.bak_${TIMESTAMP}" 2>/dev/null || append_err "$f 백업 실패"
  sed -i -e '/^[[:space:]]*#/b' -e '/^[[:space:]]*$/b' -e 's/^[[:space:]]*/# /' "$f" 2>/dev/null \
    || append_err "$f 설정 주석 처리 실패"
  MODIFIED=1
}

# 1) inetd 설정 조치
if [ -f "/etc/inetd.conf" ]; then
  INETD_ACTIVE=0
  if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)" ; then
    INETD_ACTIVE=1
  fi

  if [ "$INETD_ACTIVE" -eq 1 ]; then
    cp -a /etc/inetd.conf "/etc/inetd.conf.bak_${TIMESTAMP}" 2>/dev/null || append_err "inetd.conf 백업 실패"
    for s in "${R_SERVICES[@]}"; do
      sed -i "s/^\([[:space:]]*${s}\([[:space:]]\|$\)\)/#\1/g" /etc/inetd.conf 2>/dev/null || true
    done
    MODIFIED=1
    restart_inetd_if_exists
  fi
fi

# 2) xinetd 설정 조치
XINETD_CHANGED=0
for s in "${R_SERVICES[@]}"; do
  if [ -f "/etc/xinetd.d/$s" ]; then
    if grep -Ev "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      cp -a "/etc/xinetd.d/$s" "/etc/xinetd.d/${s}.bak_${TIMESTAMP}" 2>/dev/null || append_err "/etc/xinetd.d/$s 백업 실패"
      sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' "/etc/xinetd.d/$s" 2>/dev/null \
        || append_err "/etc/xinetd.d/$s disable=yes 변경 실패"
      XINETD_CHANGED=1
      MODIFIED=1
    fi
  fi
done

if [ "$XINETD_CHANGED" -eq 1 ]; then
  restart_xinetd_if_exists
fi

# 3) systemd 유닛 조치
for base in rsh rlogin rexec shell login exec; do
  disable_systemd_unit_if_exists "${base}.service"
  disable_systemd_unit_if_exists "${base}.socket"
done

# 4) 신뢰 기반 파일 무력화
neutralize_trust_file "/etc/hosts.equiv"

RHOSTS_FILES=$(find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null | head -n 200)
if [ -n "$RHOSTS_FILES" ]; then
  while IFS= read -r rf; do
    [ -n "$rf" ] && neutralize_trust_file "$rf"
  done <<< "$RHOSTS_FILES"
fi

# 5) 조치 후 상태 검증
FAIL_FLAG=0

INETD_POST="inetd_conf_not_found"
if [ -f "/etc/inetd.conf" ]; then
  INETD_POST="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)' | head -n 5)"
  [ -z "$INETD_POST" ] && INETD_POST="no_active_r_services"
fi
[ "$INETD_POST" != "no_active_r_services" ] && FAIL_FLAG=1

XINETD_BAD=0
for s in "${R_SERVICES[@]}"; do
  if [ -f "/etc/xinetd.d/$s" ]; then
    if grep -Ev "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      XINETD_BAD=1
    fi
  fi
done
[ "$XINETD_BAD" -eq 1 ] && FAIL_FLAG=1

SYSTEMD_BAD=0
if command -v systemctl >/dev/null 2>&1; then
  for base in rsh rlogin rexec shell login exec; do
    for u in "${base}.service" "${base}.socket"; do
      if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
        if systemctl is-enabled "$u" 2>/dev/null | grep -qiE "enabled" || systemctl is-active "$u" 2>/dev/null | grep -qiE "active"; then
          SYSTEMD_BAD=1
        fi
      fi
    done
  done
fi
[ "$SYSTEMD_BAD" -eq 1 ] && FAIL_FLAG=1

TRUST_BAD=0
HOSTS_EQ_AFTER="hosts_equiv_not_found"
if [ -f "/etc/hosts.equiv" ]; then
  HOSTS_EQ_AFTER="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.equiv 2>/dev/null | head -n 5)"
  [ -z "$HOSTS_EQ_AFTER" ] && HOSTS_EQ_AFTER="no_effective_entries"
fi
[ "$HOSTS_EQ_AFTER" != "no_effective_entries" ] && [ "$HOSTS_EQ_AFTER" != "hosts_equiv_not_found" ] && TRUST_BAD=1

RHOSTS_AFTER_SUMMARY=""
RHOSTS_FILES2=$(find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null | head -n 50)
if [ -n "$RHOSTS_FILES2" ]; then
  while IFS= read -r rf; do
    eff="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$rf" 2>/dev/null | head -n 1)"
    if [ -n "$eff" ]; then
      TRUST_BAD=1
      RHOSTS_AFTER_SUMMARY="${RHOSTS_AFTER_SUMMARY}${rf}:active; "
    else
      RHOSTS_AFTER_SUMMARY="${RHOSTS_AFTER_SUMMARY}${rf}:inactive; "
    fi
  done <<< "$RHOSTS_FILES2"
else
  RHOSTS_AFTER_SUMMARY="no_rhosts_files"
fi
[ "$TRUST_BAD" -eq 1 ] && FAIL_FLAG=1

# 상세 근거 수집
append_detail "inetd_status: $INETD_POST"
XINETD_POST_SUMMARY=""
for s in "${R_SERVICES[@]}"; do
  if [ -f "/etc/xinetd.d/$s" ]; then
    line="$(grep -nEv '^[[:space:]]*#' "/etc/xinetd.d/$s" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
    [ -z "$line" ] && line="disable_not_found"
    XINETD_POST_SUMMARY="${XINETD_POST_SUMMARY}${s}:${line}; "
  fi
done
[ -z "$XINETD_POST_SUMMARY" ] && XINETD_POST_SUMMARY="no_files"
append_detail "xinetd_status: $XINETD_POST_SUMMARY"

if command -v systemctl >/dev/null 2>&1; then
  for base in rsh rlogin rexec shell login exec; do
    for u in "${base}.service" "${base}.socket"; do
      if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
        S_EN=$(systemctl is-enabled "$u" 2>/dev/null || echo 'unknown')
        S_AC=$(systemctl is-active "$u" 2>/dev/null || echo 'unknown')
        append_detail "${u}: enabled=${S_EN}, active=${S_AC}"
      fi
    done
  done
fi

append_detail "hosts_equiv_status: $HOSTS_EQ_AFTER"
append_detail "rhosts_status: $RHOSTS_AFTER_SUMMARY"

# 최종 판정 및 REASON_LINE 구성
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="r 계열 서비스를 중지 및 비활성화하고 신뢰 기반 접속 설정 파일의 유효 라인을 모두 주석 처리하여 조치를 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  REASON_LINE="일부 r 계열 서비스가 여전히 활성화되어 있거나 신뢰 기반 접속 설정 파일 내에 인증 없는 접근 허용 옵션이 남아 있는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="${DETAIL_CONTENT}\n[Error Log]\n${ACTION_ERR_LOG}"
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

# JSON 데이터 이스케이프 처리
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