#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-23
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 불필요하거나 악의적인 파일에 SUID, SGID, Sticky bit 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-23"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/ (root 소유 SUID/SGID/Sticky bit 설정 파일)"
CHECK_COMMAND='find / -user root -type f \( -perm -04000 -o -perm -02000 -o -perm -01000 \) -xdev 2>/dev/null'

DETAIL_CONTENT=""
REASON_LINE=""

json_escape() {
  echo "$1" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | sed ':a;N;$!ba;s/\n/\\n/g'
}

first_n_paths_csv() {
  # 여러 줄 경로를 "a, b, c" 형태로
  local n="$1"
  head -n "$n" | paste -sd ', ' -
}

RESULT_SUID_SGID="$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)"
RESULT_STICKY="$(find / -user root -type f -perm -01000 -xdev 2>/dev/null)"

# 현재 설정값은 양호/취약과 무관하게 항상 보여줌
DETAIL_CONTENT=$(cat <<EOF
[SUID/SGID(4000/2000) 설정 root 소유 파일]
${RESULT_SUID_SGID:-none}

[Sticky bit(1000) 설정 root 소유 파일]
${RESULT_STICKY:-none}
EOF
)

if [ -n "$RESULT_SUID_SGID" ] || [ -n "$RESULT_STICKY" ]; then
  STATUS="FAIL"

  REASON_PARTS=()
  if [ -n "$RESULT_SUID_SGID" ]; then
    EX_SUID_SGID="$(echo "$RESULT_SUID_SGID" | first_n_paths_csv 3)"
    REASON_PARTS+=("root 소유 파일에 SUID/SGID(4000/2000) 설정이 존재하며 예시는 ${EX_SUID_SGID}")
  fi
  if [ -n "$RESULT_STICKY" ]; then
    EX_STICKY="$(echo "$RESULT_STICKY" | first_n_paths_csv 3)"
    REASON_PARTS+=("root 소유 파일에 Sticky bit(1000) 설정이 존재하며 예시는 ${EX_STICKY}")
  fi

  if [ "${#REASON_PARTS[@]}" -eq 2 ]; then
    REASON_LINE="${REASON_PARTS[0]}, ${REASON_PARTS[1]}로 이 항목에 대해 취약합니다."
  else
    REASON_LINE="${REASON_PARTS[0]}로 이 항목에 대해 취약합니다."
  fi
else
  STATUS="PASS"
  REASON_LINE="root 소유 파일에 SUID/SGID(4000/2000) 및 Sticky bit(1000) 설정이 존재하지 않아 이 항목에 대해 양호합니다."
fi

# 자동 조치 위험 + 조치 방법
GUIDE_LINE=$(cat <<EOF
SUID/SGID/Sticky bit 권한을 일괄 제거하면 OS 및 응용프로그램 기능 장애가 발생할 수 있어 수동 조치가 필요합니다.
관리자가 직접 확인 후 불필요한 파일은 chmod -s 또는 chmod -t로 특수 권한을 제거하고 반드시 필요한 경우 chgrp <그룹> 후 chmod 4750 등으로 특정 그룹만 사용하도록 제한해 주시기 바랍니다.
EOF
)

# raw_evidence 구성(모든 값은 문장/항목 단위로 줄바꿈 가능)
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
