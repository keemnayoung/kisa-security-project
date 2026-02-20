#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-45
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 메일 서비스 버전 점검
# @Description : 취약한 버전의 메일 서비스 이용 여부 점검
# @Criteria_Good :  메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 패치 관리 정책을 수립하여 주기적으로 패치 적용 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-45 메일 서비스 버전 점검

# 기본 변수
ID="U-45"
CATEGORY="서비스 관리"
TITLE="메일 서비스 버전 점검"
IMPORTANCE="상"
TARGET_FILE="/etc/mail/sendmail.cf"

SENDMAIL_REQUIRED_VERSION="8.18.2"
POSTFIX_REQUIRED_VERSION="3.10.7"
EXIM_REQUIRED_VERSION="4.99.1"

STATUS="PASS"
VULNERABLE=0
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# JSON escape 처리 (따옴표, 줄바꿈)
escape_json_str() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

# 버전 비교: 0 동일, 1 현재>요구, 2 현재<요구, 3 파싱 실패
version_compare() {
  local ver1 ver2
  ver1=$(echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  ver2=$(echo "$2" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [ -z "$ver1" ] || [ -z "$ver2" ] && return 3

  local IFS='.'
  local a=($ver1) b=($ver2)

  if [ "${a[0]}" -gt "${b[0]}" ]; then return 1; fi
  if [ "${a[0]}" -lt "${b[0]}" ]; then return 2; fi
  if [ "${a[1]}" -gt "${b[1]}" ]; then return 1; fi
  if [ "${a[1]}" -lt "${b[1]}" ]; then return 2; fi
  if [ "${a[2]}" -gt "${b[2]}" ]; then return 1; fi
  if [ "${a[2]}" -lt "${b[2]}" ]; then return 2; fi
  return 0
}

# 파일 해시 수집(존재 시), target_file/상세 표시에 공통 활용
hash_of_file() {
  local f="$1"
  local h="NOT_FOUND"
  if [ -n "$f" ] && [ -f "$f" ]; then
    h=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    [ -z "$h" ] && h="HASH_ERROR"
  fi
  printf '%s' "$h"
}

# 누적 정보(현재 설정값/상태값), 취약 이유(취약 부분만), target 파일 목록
CURRENT_LINES=()
VULN_REASONS=()
TARGET_FILES=()

# 점검 명령
CHECK_COMMAND='
(systemctl list-units --type=service 2>/dev/null | grep -Ei "sendmail(\.service)?([[:space:]]|$)" || true);
(systemctl is-active sendmail 2>/dev/null || true);
(command -v sendmail >/dev/null 2>&1 && sendmail -d0 -bt </dev/null 2>/dev/null | grep -i Version || true);

(systemctl is-active postfix 2>/dev/null || true);
(command -v postconf >/dev/null 2>&1 && postconf mail_version 2>/dev/null || true);
(ps -ef 2>/dev/null | grep -v grep | grep -i postfix || true);

(systemctl list-units --type=service 2>/dev/null | grep -Ei "exim4?(\.service)?([[:space:]]|$)" || true);
(systemctl is-active exim4 2>/dev/null || true);
(command -v exim >/dev/null 2>&1 && exim --version 2>/dev/null | head -1 || true);
(ps -ef 2>/dev/null | grep -v grep | grep -i exim || true);
'

# Sendmail: list-units/is-active로 실행 여부 확인 후 버전 확인
check_sendmail() {
  if ! command -v sendmail >/dev/null 2>&1; then
    CURRENT_LINES+=("(sendmail) installed=no")
    return 0
  fi

  local listed active running ver cmp
  listed=$(systemctl list-units --type=service 2>/dev/null | grep -Ei "sendmail(\.service)?([[:space:]]|$)" | head -n 1)
  systemctl is-active sendmail >/dev/null 2>&1
  active=$?

  running=0
  if [ -n "$listed" ] || [ $active -eq 0 ]; then
    running=1
  fi

  ver=$(sendmail -d0 -bt </dev/null 2>/dev/null | grep -i "Version" | awk '{print $2}' | head -n 1)
  local cf="/etc/mail/sendmail.cf"
  local h
  h="$(hash_of_file "$cf")"
  TARGET_FILES+=("$cf")

  CURRENT_LINES+=("(sendmail) installed=yes")
  CURRENT_LINES+=("(sendmail) unit_listed=$( [ -n "$listed" ] && echo yes || echo no )")
  CURRENT_LINES+=("(sendmail) unit_active=$( [ $active -eq 0 ] && echo active || echo inactive )")
  CURRENT_LINES+=("(sendmail) version=${ver:-UNKNOWN} required>=${SENDMAIL_REQUIRED_VERSION}")
  CURRENT_LINES+=("(sendmail) config_file=${cf} hash=${h}")

  if [ $running -eq 1 ]; then
    if [ -n "$ver" ]; then
      version_compare "$ver" "$SENDMAIL_REQUIRED_VERSION"
      cmp=$?
      if [ $cmp -eq 2 ]; then
        VULNERABLE=1
        VULN_REASONS+=("sendmail_version=${ver}<${SENDMAIL_REQUIRED_VERSION}")
      elif [ $cmp -eq 3 ]; then
        VULNERABLE=1
        VULN_REASONS+=("sendmail_version_parse_failed=${ver}")
      fi
    else
      VULNERABLE=1
      VULN_REASONS+=("sendmail_version_unknown")
    fi
  fi
}

# Postfix: is-active 확인, inactive인데 ps에 잔존 프로세스 있으면 비정상
check_postfix() {
  if ! command -v postconf >/dev/null 2>&1; then
    CURRENT_LINES+=("(postfix) postconf_installed=no")
    return 0
  fi

  local active ver cmp proc_alive
  systemctl is-active postfix >/dev/null 2>&1
  active=$?

  ver=$(postconf mail_version 2>/dev/null | cut -d= -f2 | xargs)
  proc_alive="no"
  if ps -ef 2>/dev/null | grep -v grep | grep -qi postfix; then
    proc_alive="yes"
  fi

  local cf="/etc/postfix/main.cf"
  local h
  h="$(hash_of_file "$cf")"
  TARGET_FILES+=("$cf")

  CURRENT_LINES+=("(postfix) postconf_installed=yes")
  CURRENT_LINES+=("(postfix) unit_active=$( [ $active -eq 0 ] && echo active || echo inactive )")
  CURRENT_LINES+=("(postfix) process_present=${proc_alive}")
  CURRENT_LINES+=("(postfix) version=${ver:-UNKNOWN} required>=${POSTFIX_REQUIRED_VERSION}")
  CURRENT_LINES+=("(postfix) config_file=${cf} hash=${h}")

  if [ $active -eq 0 ]; then
    if [ -n "$ver" ]; then
      version_compare "$ver" "$POSTFIX_REQUIRED_VERSION"
      cmp=$?
      if [ $cmp -eq 2 ]; then
        VULNERABLE=1
        VULN_REASONS+=("postfix_version=${ver}<${POSTFIX_REQUIRED_VERSION}")
      elif [ $cmp -eq 3 ]; then
        VULNERABLE=1
        VULN_REASONS+=("postfix_version_parse_failed=${ver}")
      fi
    else
      VULNERABLE=1
      VULN_REASONS+=("postfix_version_unknown")
    fi
  else
    if [ "$proc_alive" = "yes" ]; then
      VULNERABLE=1
      VULN_REASONS+=("postfix_process_resident=present")
    fi
  fi
}

# Exim: list-units/is-active로 실행 여부 확인, inactive인데 ps 잔존 시 비정상
check_exim() {
  if ! (command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1); then
    CURRENT_LINES+=("(exim) installed=no")
    return 0
  fi

  local listed active running ver cmp proc_alive
  listed=$(systemctl list-units --type=service 2>/dev/null | grep -Ei "exim4?(\.service)?([[:space:]]|$)" | head -n 1)
  systemctl is-active exim4 >/dev/null 2>&1
  active=$?

  running=0
  if [ -n "$listed" ] || [ $active -eq 0 ]; then
    running=1
  fi

  ver=$(exim --version 2>/dev/null | head -1 | awk '{print $3}' | head -n 1)
  proc_alive="no"
  if ps -ef 2>/dev/null | grep -v grep | grep -qi exim; then
    proc_alive="yes"
  fi

  local cf="/etc/exim4/exim4.conf"
  local h
  h="$(hash_of_file "$cf")"
  TARGET_FILES+=("$cf")

  CURRENT_LINES+=("(exim) installed=yes")
  CURRENT_LINES+=("(exim) unit_listed=$( [ -n "$listed" ] && echo yes || echo no )")
  CURRENT_LINES+=("(exim) unit_active=$( [ $active -eq 0 ] && echo active || echo inactive )")
  CURRENT_LINES+=("(exim) process_present=${proc_alive}")
  CURRENT_LINES+=("(exim) version=${ver:-UNKNOWN} required>=${EXIM_REQUIRED_VERSION}")
  CURRENT_LINES+=("(exim) config_file=${cf} hash=${h}")

  if [ $running -eq 1 ]; then
    if [ -n "$ver" ]; then
      version_compare "$ver" "$EXIM_REQUIRED_VERSION"
      cmp=$?
      if [ $cmp -eq 2 ]; then
        VULNERABLE=1
        VULN_REASONS+=("exim_version=${ver}<${EXIM_REQUIRED_VERSION}")
      elif [ $cmp -eq 3 ]; then
        VULNERABLE=1
        VULN_REASONS+=("exim_version_parse_failed=${ver}")
      fi
    else
      VULNERABLE=1
      VULN_REASONS+=("exim_version_unknown")
    fi
  else
    if [ "$proc_alive" = "yes" ]; then
      VULNERABLE=1
      VULN_REASONS+=("exim_process_resident=present")
    fi
  fi
}

# 점검 수행
check_sendmail
check_postfix
check_exim

# 취약 여부 최종 판정
if [ $VULNERABLE -eq 1 ]; then
  STATUS="FAIL"
else
  STATUS="PASS"
fi

# target_file: 존재/비존재와 무관하게 관련 파일 경로를 보여주되, 중복 제거
if [ ${#TARGET_FILES[@]} -gt 0 ]; then
  TARGET_FILE=$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF && !seen[$0]++' | paste -sd' ' -)
else
  TARGET_FILE="N/A"
fi

# DETAIL_CONTENT 구성
DETAIL_CONTENT="$(cat <<EOF
(현재 설정/상태)
$(printf "%s\n" "${CURRENT_LINES[@]}")
(요구 버전)
sendmail>=${SENDMAIL_REQUIRED_VERSION}
postfix>=${POSTFIX_REQUIRED_VERSION}
exim>=${EXIM_REQUIRED_VERSION}
EOF
)"

# REASON_LINE 구성
REASON_LINE=""
if [ "$STATUS" = "PASS" ]; then
  if [ ${#CURRENT_LINES[@]} -eq 0 ]; then
    REASON_LINE="메일 서비스 관련 설정/상태가 확인되지 않아 이 항목에 대해 양호합니다."
  else
    REASON_LINE="$(printf "%s, " "${CURRENT_LINES[@]}" | sed 's/, $//')로 확인되어 이 항목에 대해 양호합니다."
  fi
else
  if [ ${#VULN_REASONS[@]} -gt 0 ]; then
    REASON_LINE="$(printf "%s, " "${VULN_REASONS[@]}" | sed 's/, $//')로 확인되어 이 항목에 대해 취약합니다."
  else
    REASON_LINE="요구 버전 미만 또는 비정상 프로세스 잔존 상태로 확인되어 이 항목에 대해 취약합니다."
  fi
fi

# 자동조치 위험 + 조치 방법
GUIDE_LINE="메일 서비스 버전 조치(패치/업그레이드/중지)는 서비스 중단, 메일 큐 처리 영향, 연동 시스템(NMS/애플리케이션 메일 발송) 장애 등 운영 리스크가 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 사용 중인 메일 서비스(sendmail/postfix/exim)의 벤더 권고에 따라 최신 보안 패치를 적용하거나 최신 버전으로 업그레이드한 뒤 서비스 재기동 후 버전을 재확인해 주시기 바랍니다.
불필요한 메일 서비스는 중지 및 비활성화하고, 서비스가 비활성인데 프로세스가 잔존하는 경우 정상 종료 후 잔존 프로세스를 정리해 주시기 바랍니다."

# raw_evidence 구성
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command":"$CHECK_COMMAND",
  "detail":"${REASON_LINE}\n${DETAIL_CONTENT}",
  "guide":"$GUIDE_LINE",
  "target_file":"$TARGET_FILE_FOR_EVIDENCE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# scan_history 저장용 JSON 출력
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF
