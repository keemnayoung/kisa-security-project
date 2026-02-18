#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-49
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS 보안 버전 패치
# @Description : BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검
# @Criteria_Good : 주기적으로 패치를 관리하는 경우
# @Criteria_Bad : 주기적으로 패치를 관리하고 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-49"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REQUIRED_VERSION="9.20.18"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/usr/sbin/named"
CHECK_COMMAND='systemctl is-active named; systemctl is-active named-chroot; systemctl list-unit-files | grep -E "^(named|named-chroot)\.service"; named -v; command -v named; rpm -q bind bind-chroot; (command -v dnf && dnf -q check-update "bind*" || command -v yum && yum -q check-update "bind*") 2>/dev/null'

FOUND_ANY=0
DETAIL_LINES=""

append_detail() {
  local line="$1"
  [ -z "$line" ] && return 0
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

json_escape() {
  echo "$1" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

extract_ver() {
  echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

ver_is_ge() {
  local cur_raw="$1" req_raw="$2"
  local cur req first
  cur="$(extract_ver "$cur_raw")"
  req="$(extract_ver "$req_raw")"
  [ -z "$cur" ] || [ -z "$req" ] && return 2

  first="$(printf "%s\n%s\n" "$cur" "$req" | sort -V | head -n1)"
  if [ "$cur" = "$req" ]; then
    return 0
  elif [ "$first" = "$cur" ]; then
    return 1
  else
    return 0
  fi
}

# 분기 1: DNS 서비스 활성(실행) 여부와 활성 유닛 식별
DNS_ACTIVE="N"
ACTIVE_UNIT="none"
if systemctl is-active --quiet named 2>/dev/null; then
  DNS_ACTIVE="Y"
  ACTIVE_UNIT="named.service"
elif systemctl is-active --quiet named-chroot 2>/dev/null; then
  DNS_ACTIVE="Y"
  ACTIVE_UNIT="named-chroot.service"
fi

UNIT_FILE_HIT="N"
systemctl list-unit-files 2>/dev/null | grep -qE '^(named|named-chroot)\.service' && UNIT_FILE_HIT="Y"

# 분기 2: named 바이너리/버전/패키지 정보 수집(설치 여부 판단 포함)
DNS_VER_RAW=""
NAMED_PATH=""
BIND_RPM=""

if command -v named >/dev/null 2>&1; then
  FOUND_ANY=1
  NAMED_PATH="$(command -v named 2>/dev/null)"
  [ -n "$NAMED_PATH" ] && TARGET_FILE="$NAMED_PATH"

  DNS_VER_RAW="$(named -v 2>/dev/null)"
  [ -z "$DNS_VER_RAW" ] && DNS_VER_RAW="unknown"

  BIND_RPM="$(rpm -q bind bind-chroot 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/[[:space:]]$//')"
  [ -z "$BIND_RPM" ] && BIND_RPM="not_installed_or_unknown"

  append_detail "[bind] named_path=$NAMED_PATH"
  append_detail "[bind] named_version_raw=$DNS_VER_RAW"
  append_detail "[bind] required_version=$REQUIRED_VERSION"
  append_detail "[bind] rpm=$BIND_RPM"
else
  append_detail "[bind] named_command=NOT_FOUND"
fi

# 분기 3: 최신 패치 관리 여부 확인(업데이트 대기 유무)
UPDATE_PENDING="unknown"
UPDATE_LINES=""

if [ $FOUND_ANY -eq 1 ]; then
  if command -v dnf >/dev/null 2>&1; then
    UPDATE_LINES="$(dnf -q check-update "bind*" 2>/dev/null | head -n 30)"
    rc=$?
    if [ $rc -eq 100 ]; then
      UPDATE_PENDING="yes"
    elif [ $rc -eq 0 ]; then
      UPDATE_PENDING="no"
    else
      UPDATE_PENDING="unknown"
    fi
  elif command -v yum >/dev/null 2>&1; then
    UPDATE_LINES="$(yum -q check-update "bind*" 2>/dev/null | head -n 30)"
    rc=$?
    if [ $rc -eq 100 ]; then
      UPDATE_PENDING="yes"
    elif [ $rc -eq 0 ]; then
      UPDATE_PENDING="no"
    else
      UPDATE_PENDING="unknown"
    fi
  fi

  append_detail "[patch] update_pending=$UPDATE_PENDING"
  [ -n "$UPDATE_LINES" ] && append_detail "[patch] check_update_head=$(echo "$UPDATE_LINES" | tr '\n' ';' | sed 's/[[:space:]]\+/ /g' | sed 's/;/ | /g')"
fi

# 분기 4: 최종 판정(양호/취약) 및 RAW_EVIDENCE의 이유 문장 구성
REASON_SETTING=""
if [ "$DNS_ACTIVE" = "N" ] && [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_SETTING="active_unit=none, named_command=NOT_FOUND"
  DETAIL_CONTENT="none"
else
  append_detail "[service] named_active=$DNS_ACTIVE (active_unit=$ACTIVE_UNIT, unit_file_hit=$UNIT_FILE_HIT)"
  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

  if [ "$UPDATE_PENDING" = "yes" ]; then
    STATUS="FAIL"
    REASON_SETTING="update_pending=yes"
  else
    if [ "$DNS_ACTIVE" = "Y" ]; then
      if [ $FOUND_ANY -eq 0 ] || [ -z "$DNS_VER_RAW" ] || [ "$DNS_VER_RAW" = "unknown" ]; then
        STATUS="FAIL"
        REASON_SETTING="active_unit=$ACTIVE_UNIT, named_version_raw=unknown"
      else
        ver_is_ge "$DNS_VER_RAW" "$REQUIRED_VERSION"
        rc=$?
        if [ $rc -eq 1 ]; then
          STATUS="FAIL"
          REASON_SETTING="active_unit=$ACTIVE_UNIT, named_version=$(extract_ver "$DNS_VER_RAW") < required=$REQUIRED_VERSION"
          append_detail "[result] version_check=LOW (current=$(extract_ver "$DNS_VER_RAW") < required=$REQUIRED_VERSION)"
        elif [ $rc -eq 2 ]; then
          STATUS="FAIL"
          REASON_SETTING="active_unit=$ACTIVE_UNIT, named_version_raw=$(echo "$DNS_VER_RAW" | tr '\n' ' ')"
          append_detail "[result] version_check=UNKNOWN (parse_failed)"
        else
          STATUS="PASS"
          REASON_SETTING="active_unit=$ACTIVE_UNIT, named_version=$(extract_ver "$DNS_VER_RAW") >= required=$REQUIRED_VERSION, update_pending=no"
          append_detail "[result] version_check=OK (current=$(extract_ver "$DNS_VER_RAW") >= required=$REQUIRED_VERSION)"
        fi
      fi
    else
      STATUS="PASS"
      REASON_SETTING="named_active=N"
    fi
  fi
fi

# 분기 5: detail/guide 문자열(줄바꿈 유지)을 최종 RAW_EVIDENCE에 반영
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="${REASON_SETTING}로 이 항목에 대해 양호합니다."
else
  REASON_LINE="${REASON_SETTING}로 이 항목에 대해 취약합니다."
fi

GUIDE_LINE="이 항목에 대해서 DNS 서비스 운영 환경별 영향 차이로 자동 조치 시 서비스 중단, 질의 실패, 연동 시스템 장애가 발생할 수 있는 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 bind 패키지 최신 보안 업데이트 적용 여부를 점검하고 필요 시 업데이트를 적용하며, DNS 서비스를 사용 중이면 ${ACTIVE_UNIT} 재시작 또는 미사용이면 서비스 중지/비활성화를 조치해 주시기 바랍니다."

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

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
