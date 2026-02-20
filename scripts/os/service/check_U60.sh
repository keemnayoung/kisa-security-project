#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-60
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String 복잡성 설정 여부 점검
# @Criteria_Good : SNMP Community String 기본값인 "public", "private"이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우
# @Criteria_Bad :  아래의 내용 중 하나라도 해당되는 경우
#                1. SNMP Community String 기본값인 "public", "private"일 경우
#                2. 영문자, 숫자 포함 10자리 미만인 경우
#                3. 영문자, 숫자, 특수문자 포함 8자리 미만인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-60"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='systemctl is-active snmpd 2>/dev/null; systemctl is-enabled snmpd 2>/dev/null; pgrep -a -x snmpd 2>/dev/null; grep -nE "^[[:space:]]*(com2sec|rocommunity|rwcommunity|createUser)\b" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf /var/lib/net-snmp/snmpd.conf 2>/dev/null'

DETAIL_LINES=""
WEAK_REASON=""

append_detail() {
  [ -z "${1:-}" ] && return 0
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$1"
  else
    DETAIL_LINES="${DETAIL_LINES}"$'\n'"$1"
  fi
}

add_target() {
  [ -n "${1:-}" ] || return 0
  case ",$TARGET_FILE," in
    *,"$1",*) : ;;
    *) TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1" ;;
  esac
}

mask_token() {
  local s="${1:-}" n="${#s}"
  if [ "$n" -le 3 ]; then
    echo "***"
  else
    echo "${s:0:2}***${s: -2}"
  fi
}

# public/private 또는 (길이<8) 또는 (영문+숫자만이고 길이<10)
is_weak_token() {
  local s="${1:-}" low
  low="$(echo "$s" | tr '[:upper:]' '[:lower:]')"
  [[ "$low" =~ ^(public|private)$ ]] && return 0
  [ "${#s}" -lt 8 ] && return 0
  echo "$s" | grep -qE '^[A-Za-z0-9]+$' && [ "${#s}" -lt 10 ] && return 0
  return 1
}

set_weak_reason_once() {
  [ -n "$WEAK_REASON" ] && return 0
  WEAK_REASON="$1"
}

# SNMP 실행 여부 판단
SNMP_RUNNING=0
ACTIVE="N"; ENABLED="N"; PROC="N"

if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet snmpd 2>/dev/null && ACTIVE="Y" && SNMP_RUNNING=1
  systemctl is-enabled --quiet snmpd 2>/dev/null && ENABLED="Y"
fi
pgrep -x snmpd >/dev/null 2>&1 && PROC="Y" && SNMP_RUNNING=1

append_detail "[systemd] snmpd_active=$ACTIVE snmpd_enabled=$ENABLED"
append_detail "[process] snmpd_running=$PROC"

# SNMP 미실행(점검 대상 없음)
if [ "$SNMP_RUNNING" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="snmpd_active=$ACTIVE snmpd_running=$PROC 로 이 항목에 대해 양호합니다."
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf, /var/lib/net-snmp/snmpd.conf"
  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
else
  # 설정 파일에서 v1/v2c community 및 v3 createUser 파싱
  CONF_LIST="/etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf /var/lib/net-snmp/snmpd.conf"
  FOUND_ANY_CONF=0
  FOUND_V12=0
  FOUND_V3=0
  WEAK_FOUND=0

  for conf in $CONF_LIST; do
    if [ -f "$conf" ]; then
      FOUND_ANY_CONF=1
      add_target "$conf"

      LINES="$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$conf" 2>/dev/null | grep -nE '^[[:space:]]*(com2sec|rocommunity|rwcommunity|createUser)\b' || true)"
      if [ -z "$LINES" ]; then
        append_detail "[conf] $conf relevant_lines=NOT_FOUND"
        continue
      fi

      append_detail "[conf] $conf relevant_lines=FOUND (count=$(echo "$LINES" | wc -l | tr -d ' '))"

      while IFS= read -r line; do
        body="${line#*:}"
        key="$(echo "$body" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"

        if [[ "$key" =~ ^(com2sec|rocommunity|rwcommunity)$ ]]; then
          FOUND_V12=1
          if [ "$key" = "com2sec" ]; then
            comm="$(echo "$body" | awk '{print $4}')"
          else
            comm="$(echo "$body" | awk '{print $2}')"
          fi
          [ -z "${comm:-}" ] && append_detail "[parse] $conf | $key community=NOT_PARSED" && continue

          if is_weak_token "$comm"; then
            WEAK_FOUND=1
            m="$(mask_token "$comm")"
            set_weak_reason_once "$conf $key community=$m"
            append_detail "[check] $conf | $key community=WEAK($m)"
          else
            append_detail "[check] $conf | $key community=OK($(mask_token "$comm"))"
          fi

        elif [ "$key" = "createuser" ]; then
          FOUND_V3=1
          authpass="$(echo "$body" | awk '{print $4}')"
          privpass="$(echo "$body" | awk '{print $6}')"

          if [ -n "${authpass:-}" ]; then
            if is_weak_token "$authpass"; then
              WEAK_FOUND=1
              m="$(mask_token "$authpass")"
              set_weak_reason_once "$conf createUser authpass=$m"
              append_detail "[check] $conf | createUser authpass=WEAK($m)"
            else
              append_detail "[check] $conf | createUser authpass=OK($(mask_token "$authpass"))"
            fi
          else
            append_detail "[parse] $conf | createUser authpass=NOT_FOUND"
          fi

          if [ -n "${privpass:-}" ]; then
            if is_weak_token "$privpass"; then
              WEAK_FOUND=1
              m="$(mask_token "$privpass")"
              set_weak_reason_once "$conf createUser privpass=$m"
              append_detail "[check] $conf | createUser privpass=WEAK($m)"
            else
              append_detail "[check] $conf | createUser privpass=OK($(mask_token "$privpass"))"
            fi
          fi
        fi
      done <<< "$LINES"
    else
      append_detail "[conf] $conf=NOT_FOUND"
    fi
  done

  # 최종 판정
  if [ "$FOUND_ANY_CONF" -eq 0 ]; then
    STATUS="FAIL"
    REASON_LINE="snmpd_active=$ACTIVE snmpd_running=$PROC snmp_conf=NOT_FOUND 로 이 항목에 대해 취약합니다."
    TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf, /var/lib/net-snmp/snmpd.conf"
  elif [ "$FOUND_V12" -eq 0 ] && [ "$FOUND_V3" -eq 0 ]; then
    STATUS="FAIL"
    REASON_LINE="snmpd_active=$ACTIVE snmpd_running=$PROC directives=NOT_FOUND 로 이 항목에 대해 취약합니다."
  elif [ "$WEAK_FOUND" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="${WEAK_REASON:-weak_setting_found} 로 이 항목에 대해 취약합니다."
  else
    STATUS="PASS"
    REASON_LINE="snmpd_active=$ACTIVE snmpd_running=$PROC weak_setting=NO 로 이 항목에 대해 양호합니다."
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

# 최종 RAW_EVIDENCE(detail/guide) 구성
if [ "$STATUS" = "PASS" ]; then
  DETAIL_LINE="${REASON_LINE}"$'\n'"${DETAIL_CONTENT}"
else
  DETAIL_LINE="${REASON_LINE}"$'\n'"${DETAIL_CONTENT}"
fi

GUIDE_LINE="이 항목은 SNMP 연동 장비(NMS/모니터링/백업/자산관리 등)에서 Community String 또는 SNMPv3 인증정보를 동일하게 사용하고 있을 수 있어 자동으로 변경하면 모니터링 장애, 알람 누락, 자산 수집/장비 제어 실패 등 운영 중단 위험이 발생할 수 있어 수동 조치가 필요합니다.
관리자가 직접 SNMP 사용 여부와 연동 대상(IP/장비/계정)을 확인한 뒤 /etc/snmp/snmpd.conf(또는 /var/lib/net-snmp/snmpd.conf)에서 public/private 및 단순 문자열을 제거하고 (영문+숫자 10자 이상) 또는 (영문/숫자/특수문자 포함 8자 이상)으로 변경한 후 연동 장비의 설정도 동일하게 갱신하고 snmpd를 재시작해 주시기 바랍니다."

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_LINE",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
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
