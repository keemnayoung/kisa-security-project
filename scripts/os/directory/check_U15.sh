#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-12
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-15
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

# 기본 변수
ID="U-15"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/"
CHECK_COMMAND='find / -xdev \( -nouser -o -nogroup \) -ls 2>/dev/null'

GUIDE_LINE=$'자동 조치 시 파일/디렉터리 삭제 또는 소유권 변경이 서비스 구성/스크립트 동작에 영향을 주어 예기치 않은 오류나 서비스 중단이 발생할 수 있어 수동 조치가 필요합니다.
관리자가 직접 확인 후 불필요한 항목은 rm 또는 rm -r로 제거하고, 사용 중인 항목은 적절한 사용자/그룹으로 chown 및 chgrp를 적용해 주시기 바랍니다.'

# 고아 파일/디렉터리 목록 수집
ORPHAN_FILES_RAW=$(find / \
  -xdev \
  \( -nouser -o -nogroup \) \
  -ls 2>/dev/null)

# 취약/양호 판단 및 RAW_EVIDENCE 구성 요소 생성
if [ -n "$ORPHAN_FILES_RAW" ]; then
  STATUS="FAIL"

  # 취약 사유: 취약한 설정(발견된 항목) 일부만 포함
  VULN_SNIP=$(echo "$ORPHAN_FILES_RAW" | head -n 1 | sed ':a;N;$!ba;s/\n/ | /g')
  REASON_LINE="find 결과에서 -nouser/-nogroup 항목이 확인됩니다(${VULN_SNIP}) 등으로 이 항목에 대해 취약합니다."

  # 현재 설정: 발견된 항목 전체
  DETAIL_CONTENT="$ORPHAN_FILES_RAW"

  
else
  STATUS="PASS"

  # 양호 사유: 현재 값(none)만으로 자연스럽게 구성
  REASON_LINE="find 결과에서 -nouser/-nogroup 항목이 확인되지 않습니다(none)로 이 항목에 대해 양호합니다."

  # 현재 설정값: 현재 결과값만
  DETAIL_CONTENT="none"
fi

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
