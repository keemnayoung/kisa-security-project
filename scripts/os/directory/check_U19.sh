#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-19
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
# @Description : /etc/hosts 파일의 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-19"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/hosts"
CHECK_COMMAND='stat -c "%U %a" /etc/hosts'

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE=""

# 파일 존재 여부 분기
if [ -f "$TARGET_FILE" ]; then
  FILE_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
  FILE_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

  # stat 수집 실패 분기
  if [ -z "$FILE_OWNER" ] || [ -z "$FILE_PERM" ]; then
    STATUS="FAIL"

    # 취약 사유(설정값만): 수집 실패 자체를 상태값으로 표현
    REASON_LINE="owner=${FILE_OWNER:-unknown} perm=${FILE_PERM:-unknown} 으로 확인되어 이 항목에 대해 취약합니다."

    # 현재 설정값(항상 출력)
    DETAIL_CONTENT="owner=${FILE_OWNER:-unknown}
perm=${FILE_PERM:-unknown}
exists=yes
note=stat_failed_or_empty"

    # 취약 시 가이드(자동 조치 가정)
    GUIDE_LINE="자동 조치: 
    chown root:root /etc/hosts 수행 후 chmod 644 /etc/hosts를 적용합니다.
    주의사항: 
    /etc/hosts 내용이 서비스 접근/이름해석에 사용되는 환경에서는 잘못된 항목이 존재할 경우 연결 영향이 있을 수 있으니 내용은 변경하지 않고 권한/소유자만 조치해야 합니다."
  else
    # 권한을 8진수로 안전하게 해석
    PERM_OCT=$((8#$FILE_PERM))

    # 현재 설정값(항상 출력)
    DETAIL_CONTENT="owner=$FILE_OWNER
perm=$FILE_PERM
exists=yes"

    # 기준 판정 분기
    if [ "$FILE_OWNER" = "root" ] && [ "$PERM_OCT" -le $((8#644)) ] && [ $((PERM_OCT & 8#022)) -eq 0 ]; then
      STATUS="PASS"

      # 양호 사유(설정값만): 한 문장, 줄바꿈 없음
      REASON_LINE="owner=$FILE_OWNER perm=$FILE_PERM 으로 설정되어 이 항목에 대해 양호합니다."
      
    else
      STATUS="FAIL"

      # 취약 사유(설정값만): 취약한 설정만 담기
      VULN_PARTS=""
      if [ "$FILE_OWNER" != "root" ]; then
        VULN_PARTS="owner=$FILE_OWNER"
      fi
      if [ "$PERM_OCT" -gt $((8#644)) ] || [ $((PERM_OCT & 8#022)) -ne 0 ]; then
        if [ -n "$VULN_PARTS" ]; then
          VULN_PARTS="$VULN_PARTS perm=$FILE_PERM"
        else
          VULN_PARTS="perm=$FILE_PERM"
        fi
      fi
      [ -z "$VULN_PARTS" ] && VULN_PARTS="owner=$FILE_OWNER perm=$FILE_PERM"

      REASON_LINE="$VULN_PARTS 으로 설정되어 이 항목에 대해 취약합니다."

      # 취약 시 가이드(자동 조치 가정)
      GUIDE_LINE="자동 조치: 
      chown root:root /etc/hosts 수행 후 chmod 644 /etc/hosts를 적용합니다.
      주의사항: 
      /etc/hosts 를 참조하는 서비스가 있는 경우 권한 변경 자체는 영향이 거의 없지만, 운영 중 비root 계정이 파일을 직접 수정하는 절차가 있었다면 해당 작업이 차단될 수 있으니 변경 주체/절차를 확인한 뒤 적용해야 합니다."
    fi
  fi
else
  # 파일 미존재 분기
  STATUS="FAIL"

  # 취약 사유(설정값만): 파일 상태를 설정값처럼 표현
  REASON_LINE="target_file=$TARGET_FILE state=not_found 으로 확인되어 이 항목에 대해 취약합니다."

  # 현재 설정값(항상 출력)
  DETAIL_CONTENT="owner=unknown
perm=unknown
exists=no"

  # 취약 시 가이드(자동 조치 가정)
  GUIDE_LINE="자동 조치: 
  /etc/hosts 복구 후 chown root:root /etc/hosts 및 chmod 644 /etc/hosts를 적용합니다.
  주의사항: 
  파일 생성/복구 과정에서 잘못된 호스트 매핑이 들어가면 이름해석 및 서비스 연결에 영향을 줄 수 있으니, 내용은 백업/검증된 값으로만 복구해야 합니다."
fi

# raw_evidence 구성 (각 값은 줄바꿈으로 문장 구분 가능하도록 구성)
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
