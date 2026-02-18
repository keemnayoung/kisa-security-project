#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-34
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 점검
# @Criteria_Good : Finger 서비스가 비활성화된 경우
# @Criteria_Bad : Finger 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-34 Finger 서비스 비활성화

# 기본 변수
ID="U-34"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

INETD_CONF="/etc/inetd.conf"
XINETD_FINGER="/etc/xinetd.d/finger"

TARGET_FILE="$INETD_CONF $XINETD_FINGER finger.socket finger.service"

CHECK_COMMAND='( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*finger([[:space:]]|$)" || echo "inetd_finger_not_found_or_commented" ); ( [ -f /etc/xinetd.d/finger ] && grep -nEv "^[[:space:]]*#" /etc/xinetd.d/finger | grep -niE "^[[:space:]]*disable[[:space:]]*=" || echo "xinetd_finger_disable_line_not_found_or_file_missing" ); ( command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | awk '\''tolower($1) ~ /^finger\.(socket|service)$/ {print $1,$2}'\'' || echo "systemd_finger_unit_not_found" ); ( command -v systemctl >/dev/null 2>&1 && (systemctl is-enabled finger.socket 2>/dev/null || true) && (systemctl is-active finger.socket 2>/dev/null || true) && (systemctl is-enabled finger.service 2>/dev/null || true) && (systemctl is-active finger.service 2>/dev/null || true) || echo "systemctl_not_available" )'

REASON_LINE=""
DETAIL_CONTENT=""

VULN=0
DETAIL_LINES=""

# 1) inetd 기반 점검: 주석 제외 영역에서 finger 라인이 존재하면 취약
if [ -f "$INETD_CONF" ]; then
  INETD_ACTIVE_LINES=$(grep -nEv "^[[:space:]]*#" "$INETD_CONF" 2>/dev/null | grep -nE "^[[:space:]]*finger([[:space:]]|$)" || true)
  if [ -n "$INETD_ACTIVE_LINES" ]; then
    VULN=1
    DETAIL_LINES+="$INETD_CONF: finger 활성 라인 확인\n"
    DETAIL_LINES+="$INETD_ACTIVE_LINES\n"
  else
    DETAIL_LINES+="$INETD_CONF: finger 활성 라인 없음(없음 또는 주석)\n"
  fi
else
  DETAIL_LINES+="$INETD_CONF: 파일 없음\n"
fi

# 2) xinetd 기반 점검: 파일이 존재할 때 disable=yes가 명시되지 않으면 취약
if [ -f "$XINETD_FINGER" ]; then
  # CRLF(\r) 제거 후 검사
  DISABLE_LINE_RAW=$(
    tr -d '\r' < "$XINETD_FINGER" \
      | grep -nEv '^[[:space:]]*#' \
      | grep -niE '^[[:space:]]*disable[[:space:]]*=' \
      | tail -n 1 || true
  )
  DISABLE_VAL=$(printf "%s" "$DISABLE_LINE_RAW" | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}')

  if [ -z "$DISABLE_LINE_RAW" ]; then
    VULN=1
    DETAIL_LINES+="$XINETD_FINGER: disable 라인 없음\n"
  else
    DETAIL_LINES+="$XINETD_FINGER: $DISABLE_LINE_RAW\n"
    if [ "$DISABLE_VAL" != "yes" ]; then
      VULN=1
    fi
  fi
else
  DETAIL_LINES+="$XINETD_FINGER: 파일 없음\n"
fi

# 3) systemd 기반 점검: finger 유닛이 enabled/active면 취약
if command -v systemctl >/dev/null 2>&1; then
  HAS_FINGER_UNIT=$(systemctl list-unit-files 2>/dev/null | awk 'tolower($1) ~ /^finger\.(socket|service)$/{print $1}' | head -n 1 || true)
  if [ -n "$HAS_FINGER_UNIT" ]; then
    for u in finger.socket finger.service; do
      if systemctl list-unit-files 2>/dev/null | awk '{print tolower($1)}' | grep -qx "$(echo "$u" | tr 'A-Z' 'a-z')"; then
        ENA=$(systemctl is-enabled "$u" 2>/dev/null || echo "unknown")
        ACT=$(systemctl is-active "$u" 2>/dev/null || echo "unknown")
        DETAIL_LINES+="systemd: $u\n"
        DETAIL_LINES+="is-enabled=$ENA\n"
        DETAIL_LINES+="is-active=$ACT\n"
        if [ "$ENA" = "enabled" ] || [ "$ACT" = "active" ]; then
          VULN=1
        fi
      fi
    done
  else
    DETAIL_LINES+="systemd: finger 유닛 없음\n"
  fi
else
  DETAIL_LINES+="systemctl: 사용 불가\n"
fi

# DETAIL_CONTENT: 양호/취약과 관계 없이 현재 설정값 전체
DETAIL_CONTENT="$(printf "%b" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

# REASON_LINE: 첫 문장에 들어갈 "어떠한 이유"(양호=양호 설정만, 취약=취약 설정만)
if [ "$VULN" -eq 1 ]; then
  STATUS="FAIL"
  REASON_PARTS=""

  # 취약 근거(취약한 설정만)
  if [ -f "$INETD_CONF" ]; then
    INETD_ACTIVE_LINES=$(grep -nEv "^[[:space:]]*#" "$INETD_CONF" 2>/dev/null | grep -nE "^[[:space:]]*finger([[:space:]]|$)" || true)
    if [ -n "$INETD_ACTIVE_LINES" ]; then
      REASON_PARTS+="$INETD_CONF: finger 활성 라인\n$INETD_ACTIVE_LINES\n"
    fi
  fi

  if [ -f "$XINETD_FINGER" ]; then
    DISABLE_LINE_RAW=$(
      tr -d '\r' < "$XINETD_FINGER" \
        | grep -nEv '^[[:space:]]*#' \
        | grep -niE '^[[:space:]]*disable[[:space:]]*=' \
        | tail -n 1 || true
    )
    if [ -z "$DISABLE_LINE_RAW" ]; then
      REASON_PARTS+="$XINETD_FINGER: disable 라인 없음\n"
    else
      DISABLE_VAL=$(printf "%s" "$DISABLE_LINE_RAW" | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}')
      if [ "$DISABLE_VAL" != "yes" ]; then
        REASON_PARTS+="$XINETD_FINGER: $DISABLE_LINE_RAW\n"
      fi
    fi
  fi

  if command -v systemctl >/dev/null 2>&1; then
    for u in finger.socket finger.service; do
      if systemctl list-unit-files 2>/dev/null | awk '{print tolower($1)}' | grep -qx "$(echo "$u" | tr 'A-Z' 'a-z')"; then
        ENA=$(systemctl is-enabled "$u" 2>/dev/null || echo "unknown")
        ACT=$(systemctl is-active "$u" 2>/dev/null || echo "unknown")
        if [ "$ENA" = "enabled" ] || [ "$ACT" = "active" ]; then
          REASON_PARTS+="systemd: $u (is-enabled=$ENA, is-active=$ACT)\n"
        fi
      fi
    done
  fi

  REASON_LINE="$(printf "%b" "$REASON_PARTS" | sed 's/[[:space:]]*$//')"
  [ -z "$REASON_LINE" ] && REASON_LINE="취약 설정이 확인됨"

else
  STATUS="PASS"
  GOOD_PARTS=""

  # 양호 근거(양호 설정만)
  if [ -f "$INETD_CONF" ]; then
    INETD_ACTIVE_LINES=$(grep -nEv "^[[:space:]]*#" "$INETD_CONF" 2>/dev/null | grep -nE "^[[:space:]]*finger([[:space:]]|$)" || true)
    if [ -z "$INETD_ACTIVE_LINES" ]; then
      GOOD_PARTS+="$INETD_CONF: finger 활성 라인 없음(없음 또는 주석)\n"
    fi
  else
    GOOD_PARTS+="$INETD_CONF: 파일 없음\n"
  fi

  if [ -f "$XINETD_FINGER" ]; then
    DISABLE_LINE_RAW=$(
      tr -d '\r' < "$XINETD_FINGER" \
        | grep -nEv '^[[:space:]]*#' \
        | grep -niE '^[[:space:]]*disable[[:space:]]*=' \
        | tail -n 1 || true
    )
    DISABLE_VAL=$(printf "%s" "$DISABLE_LINE_RAW" | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}')
    if [ -n "$DISABLE_LINE_RAW" ] && [ "$DISABLE_VAL" = "yes" ]; then
      GOOD_PARTS+="$XINETD_FINGER: $DISABLE_LINE_RAW\n"
    else
      GOOD_PARTS+="$XINETD_FINGER: disable=yes 확인 안됨\n"
    fi
  else
    GOOD_PARTS+="$XINETD_FINGER: 파일 없음\n"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    HAS_FINGER_UNIT=$(systemctl list-unit-files 2>/dev/null | awk 'tolower($1) ~ /^finger\.(socket|service)$/{print $1}' | head -n 1 || true)
    if [ -z "$HAS_FINGER_UNIT" ]; then
      GOOD_PARTS+="systemd: finger 유닛 없음\n"
    else
      for u in finger.socket finger.service; do
        if systemctl list-unit-files 2>/dev/null | awk '{print tolower($1)}' | grep -qx "$(echo "$u" | tr 'A-Z' 'a-z')"; then
          ENA=$(systemctl is-enabled "$u" 2>/dev/null || echo "unknown")
          ACT=$(systemctl is-active "$u" 2>/dev/null || echo "unknown")
          GOOD_PARTS+="systemd: $u (is-enabled=$ENA, is-active=$ACT)\n"
        fi
      done
    fi
  else
    GOOD_PARTS+="systemctl: 사용 불가\n"
  fi

  REASON_LINE="$(printf "%b" "$GOOD_PARTS" | sed 's/[[:space:]]*$//')"
  [ -z "$REASON_LINE" ] && REASON_LINE="양호 설정이 확인됨"

fi

# detail 첫 문장: 어떠한 이유 때문에 양호/취약합니다. (한 문장, 줄바꿈 없음)
# REASON_LINE은 내부에 줄바꿈이 있을 수 있으므로 첫 문장에서는 공백으로 정리
REASON_ONE_LINE="$(printf "%s" "$REASON_LINE" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/[[:space:]]*$//')"
if [ "$STATUS" = "PASS" ]; then
  DETAIL_HEAD="${REASON_ONE_LINE} 때문에 이 항목에 대해 양호합니다."
else
  DETAIL_HEAD="${REASON_ONE_LINE} 때문에 이 항목에 대해 취약합니다."
fi

GUIDE_LINE="$(cat <<EOF
자동 조치:
$INETD_CONF 에서 finger 활성 라인을 주석 처리하고 $XINETD_FINGER 에 disable = yes 를 표준화하며 finger.socket/finger.service 가 있으면 stop/disable/mask 합니다.
주의사항: 
서비스 관리 정책에 따라 설정 변경 및 재시작이 다른 서비스에 미약한 영향을 줄 수 있으므로 적용 전 백업과 변경 이력 관리가 필요합니다.
EOF
)"

# raw_evidence 구성 (문장 단위 줄바꿈 유지되도록 \n 포함)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_HEAD\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력 (JSON 직전 공백 라인 1줄 필수)
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF
