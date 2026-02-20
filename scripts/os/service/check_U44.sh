#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-44
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : tftp, talk 서비스 비활성화
# @Description : tftp, talk, ntalk 서비스의 활성화 여부 점검
# @Criteria_Good : tftp, talk, ntalk 서비스가 비활성화된 경우
# @Criteria_Bad : tftp, talk, ntalk 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-44"
CATEGORY="서비스 관리"
TITLE="tftp, talk 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직
STATUS="PASS"
VULNERABLE=0

SERVICES=("tftp" "talk" "ntalk")

# systemd에서 점검할 수 있는 대표 유닛 후보(서비스/소켓)
SYSTEMD_UNITS=(
  "tftp.service"
  "tftp.socket"
  "talk.service"
  "ntalk.service"
  "talkd.service"
  "ntalkd.service"
)

CHECK_PATHS="/etc/inetd.conf, /etc/xinetd.d/{tftp,talk,ntalk}, systemd(service/socket)"

# 현재 설정 값 수집 변수
INETD_ACTIVE_LINES=""
XINETD_SUMMARY_LINES=""
XINETD_DISABLE_NO_LINES=""
SYSTEMD_UNITS_FOUND=""
SYSTEMD_BAD_UNITS=""

# 취약 설정 값
BAD_SUMMARY=""

# [inetd] /etc/inetd.conf 내 tftp/talk/ntalk 활성 라인(주석/공백 제외) 수집
if [ -f "/etc/inetd.conf" ]; then
  INETD_ACTIVE_LINES="$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*(tftp|talk|ntalk)\b' 2>/dev/null || true)"
else
  INETD_ACTIVE_LINES="파일 없음"
fi

if [ -n "$INETD_ACTIVE_LINES" ] && [ "$INETD_ACTIVE_LINES" != "파일 없음" ]; then
  VULNERABLE=1
  BAD_SUMMARY="${BAD_SUMMARY}/etc/inetd.conf 활성 라인: $(printf '%s' "$INETD_ACTIVE_LINES" | head -n 3 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')\n"
fi

# [xinetd] /etc/xinetd.d/{tftp,talk,ntalk} 현재 설정 값 수집 (disable 라인/파일 존재 여부)
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${SERVICES[@]}"; do
    CONF="/etc/xinetd.d/${svc}"
    if [ -f "$CONF" ]; then
      DISABLE_LINES="$(grep -niE '^[[:space:]]*disable[[:space:]]*=' "$CONF" 2>/dev/null || true)"
      if [ -n "$DISABLE_LINES" ]; then
        XINETD_SUMMARY_LINES="${XINETD_SUMMARY_LINES}${CONF} disable 설정:\n${DISABLE_LINES}\n"
      else
        XINETD_SUMMARY_LINES="${XINETD_SUMMARY_LINES}${CONF} disable 설정: (설정 없음)\n"
      fi

      DISABLE_NO="$(grep -niE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b' "$CONF" 2>/dev/null || true)"
      if [ -n "$DISABLE_NO" ]; then
        VULNERABLE=1
        XINETD_DISABLE_NO_LINES="${XINETD_DISABLE_NO_LINES}${CONF} disable=no:\n${DISABLE_NO}\n"
        BAD_SUMMARY="${BAD_SUMMARY}${CONF} disable=no: $(printf '%s' "$DISABLE_NO" | head -n 3 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')\n"
      fi
    else
      XINETD_SUMMARY_LINES="${XINETD_SUMMARY_LINES}${CONF}: 파일 없음\n"
    fi
  done
else
  XINETD_SUMMARY_LINES="/etc/xinetd.d 디렉터리 없음\n"
fi

# [systemd] 후보 유닛의 현재 상태(enabled/active) 수집
if command -v systemctl >/dev/null 2>&1; then
  for unit in "${SYSTEMD_UNITS[@]}"; do
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
      SYSTEMD_UNITS_FOUND="${SYSTEMD_UNITS_FOUND}${unit}\n"
      EN_STATE="$(systemctl is-enabled "$unit" 2>/dev/null || echo "unknown")"
      AC_STATE="$(systemctl is-active "$unit" 2>/dev/null || echo "unknown")"

      if [ "$EN_STATE" = "enabled" ] || [ "$AC_STATE" = "active" ]; then
        VULNERABLE=1
        SYSTEMD_BAD_UNITS="${SYSTEMD_BAD_UNITS}${unit}: enabled=${EN_STATE}, active=${AC_STATE}\n"
        BAD_SUMMARY="${BAD_SUMMARY}systemd ${unit}: enabled=${EN_STATE}, active=${AC_STATE}\n"
      fi
    fi
  done
else
  SYSTEMD_UNITS_FOUND="systemctl 없음"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
  STATUS="FAIL"
else
  STATUS="PASS"
fi


SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 점검 명령
CHECK_COMMAND="$(cat <<'EOF'
( [ -f /etc/inetd.conf ] && grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf | grep -nE '^[[:space:]]*(tftp|talk|ntalk)\b' || echo "inetd_conf: none_or_missing" );
( [ -d /etc/xinetd.d ] && for f in /etc/xinetd.d/tftp /etc/xinetd.d/talk /etc/xinetd.d/ntalk; do
    if [ -f "$f" ]; then
      echo "### $f";
      grep -niE '^[[:space:]]*disable[[:space:]]*=' "$f" || echo "disable: (none)";
      grep -niE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b' "$f" || true;
    else
      echo "### $f (missing)";
    fi
  done ) || echo "xinetd_dir: missing" );
( command -v systemctl >/dev/null 2>&1 && (
    systemctl list-unit-files 2>/dev/null | egrep '^(tftp\.(service|socket)|talk(.*)\.service|ntalk(.*)\.service)[[:space:]]' || true;
    for u in tftp.service tftp.socket talk.service ntalk.service talkd.service ntalkd.service; do
      systemctl is-enabled "$u" 2>/dev/null | sed "s/^/$u enabled: /" || true;
      systemctl is-active  "$u" 2>/dev/null | sed "s/^/$u active: /"  || true;
    done
  ) ) || echo "systemctl: missing"
EOF
)"

REASON_LINE=""
DETAIL_CONTENT=""

# DETAIL_CONTENT 구성
DETAIL_CONTENT="$(cat <<EOF
(점검 경로)
${CHECK_PATHS}

/etc/inetd.conf 활성 라인
${INETD_ACTIVE_LINES:-없음}

/etc/xinetd.d 설정 요약
${XINETD_SUMMARY_LINES:-없음}

systemd 유닛 존재 여부(후보)
${SYSTEMD_UNITS_FOUND:-없음}

systemd enabled/active(취약 판단 대상)
${SYSTEMD_BAD_UNITS:-없음}
EOF
)"

# REASON_LINE 구성
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="/etc/inetd.conf에 tftp/talk/ntalk 활성 라인이 없고 /etc/xinetd.d에서 disable=no 설정이 없으며 systemd 관련 유닛이 enabled 또는 active가 아니어서 이 항목에 대해 양호합니다."
else
  BAD_ONE_LINE="$(printf '%s' "$BAD_SUMMARY" | sed ':a;N;$!ba;s/\n/ /g;s/[[:space:]]\+/ /g')"
  [ -z "$BAD_ONE_LINE" ] && BAD_ONE_LINE="tftp/talk/ntalk 관련 활성 설정이 확인되어"
  REASON_LINE="${BAD_ONE_LINE} 이 항목에 대해 취약합니다."
fi

# 취약 가정 자동 조치
GUIDE_LINE=$(cat <<EOF
자동 조치: 
/etc/inetd.conf에서 tftp/talk/ntalk 활성 라인을 주석 처리합니다.
/etc/xinetd.d/{tftp,talk,ntalk}에서 disable=no를 disable=yes로 변경하고 disable 설정이 없으면 disable=yes를 추가합니다.
systemd에서 관련 service/socket 유닛이 enabled 또는 active이면 stop 후 disable 처리합니다.
주의사항: 
tftp는 PXE 부팅, 초기 배포, 장비 펌웨어/설정 전송 등에 사용될 수 있어 비활성화 시 관련 절차가 중단될 수 있습니다.
talk/ntalk는 레거시 통신 환경에서 사용될 수 있어 비활성화 시 해당 기능이 필요했던 사용자/프로세스에 영향이 있을 수 있습니다.
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
escape_json_str() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

TARGET_FILE_FOR_EVIDENCE="$CHECK_PATHS"

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
