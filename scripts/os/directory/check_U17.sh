#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-17
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : 시스템 시작 스크립트 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-17"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/rc.d/*/*, /etc/systemd/system/* (및 하위 디렉터리)"
CHECK_COMMAND='(readlink -f /etc/rc.d/*/* 2>/dev/null; readlink -f /etc/systemd/system/* 2>/dev/null; readlink -f /etc/systemd/system/*/* 2>/dev/null) | sort -u | xargs -I{} sh -c '"'"'if [ -d "{}" ]; then ls -al "{}"/* 2>/dev/null; else stat -c "%n owner=%U perm=%A" "{}" 2>/dev/null; fi'"'"''

TARGET_FILES=()
DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE=""

json_escape() {
  echo "$1" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# 점검 대상 파일 목록 수집 (init/systemd 경로에서 대상 후보를 수집)
INIT_FILES=""
if [ -d /etc/rc.d ]; then
  INIT_FILES=$(readlink -f /etc/rc.d/*/* 2>/dev/null)
fi

SYSTEMD_FILES=""
if [ -d /etc/systemd/system ]; then
  SYSTEMD_FILES=$(
    (readlink -f /etc/systemd/system/* 2>/dev/null; readlink -f /etc/systemd/system/*/* 2>/dev/null) | sed '/^[[:space:]]*$/d'
  )
fi

ALL_FILES=$(echo -e "$INIT_FILES\n$SYSTEMD_FILES" | sed '/^[[:space:]]*$/d' | sort -u)

# 대상이 없으면 양호 처리
if [ -z "$ALL_FILES" ]; then
  STATUS="PASS"
  DETAIL_CONTENT="no_target_files"
  REASON_LINE="점검 대상 파일이 존재하지 않아 이 항목에 대해 양호합니다."
  GUIDE_LINE="점검 대상이 없어 수동 조치가 필요하지 않습니다."
else
  FOUND_VULN="N"
  VULN_ONLY_FIRST=""
  DETAIL_LINES=""

  # 파일/디렉터리 후보를 순회하며 실제 점검 대상 파일과 설정값(현재 상태)을 수집
  for FILE in $ALL_FILES; do
    [ -e "$FILE" ] || continue

    # 디렉터리인 경우 내부 파일 1레벨 확장
    if [ -d "$FILE" ]; then
      for SUB in "$FILE"/*; do
        [ -e "$SUB" ] || continue
        [ -f "$SUB" ] || continue

        OWNER=$(stat -c %U "$SUB" 2>/dev/null)
        PERM=$(stat -c %A "$SUB" 2>/dev/null)
        OTHERS_WRITE=$(echo "$PERM" | cut -c9)

        TARGET_FILES+=("$SUB")
        DETAIL_LINES+="$SUB owner=$OWNER perm=$PERM"$'\n'

        if [ "$OWNER" != "root" ] || [ "$OTHERS_WRITE" = "w" ]; then
          FOUND_VULN="Y"
          STATUS="FAIL"
          if [ -z "$VULN_ONLY_FIRST" ]; then
            if [ "$OWNER" != "root" ] && [ "$OTHERS_WRITE" = "w" ]; then
              VULN_ONLY_FIRST="$SUB owner=$OWNER perm=$PERM"
            elif [ "$OWNER" != "root" ]; then
              VULN_ONLY_FIRST="$SUB owner=$OWNER"
            else
              VULN_ONLY_FIRST="$SUB perm=$PERM"
            fi
          fi
        fi
      done
      continue
    fi

    # 일반 파일만 점검
    [ -f "$FILE" ] || continue

    OWNER=$(stat -c %U "$FILE" 2>/dev/null)
    PERM=$(stat -c %A "$FILE" 2>/dev/null)
    OTHERS_WRITE=$(echo "$PERM" | cut -c9)

    TARGET_FILES+=("$FILE")
    DETAIL_LINES+="$FILE owner=$OWNER perm=$PERM"$'\n'

    if [ "$OWNER" != "root" ] || [ "$OTHERS_WRITE" = "w" ]; then
      FOUND_VULN="Y"
      STATUS="FAIL"
      if [ -z "$VULN_ONLY_FIRST" ]; then
        if [ "$OWNER" != "root" ] && [ "$OTHERS_WRITE" = "w" ]; then
          VULN_ONLY_FIRST="$FILE owner=$OWNER perm=$PERM"
        elif [ "$OWNER" != "root" ]; then
          VULN_ONLY_FIRST="$FILE owner=$OWNER"
        else
          VULN_ONLY_FIRST="$FILE perm=$PERM"
        fi
      fi
    fi
  done

  TARGET_FILE=$(printf "%s " "${TARGET_FILES[@]}" | sed 's/[[:space:]]*$//')
  DETAIL_CONTENT="$DETAIL_LINES"
  GUIDE_LINE="이 항목에 대해서 시스템 시작 스크립트가 임의로 변경될 위험이 존재하여 수동 조치가 필요합니다.
  관리자가 직접 대상 파일을 확인한 후 소유자를 root로 변경하고(chown root 또는 chown root:root), others 쓰기 권한을 제거(chmod o-w)해 주시기 바랍니다. 
  자동 조치로 일괄 변경할 경우 일부 서비스/에이전트가 기대하는 소유자/권한과 충돌하여 서비스 기동 실패나 운영 작업 영향이 발생할 수 있으니, 변경 전 백업과 변경 후 재기동/동작 확인을 권장합니다."
  # 판단 결과에 따른 reason/guide 구성
  if [ "$FOUND_VULN" = "Y" ]; then
    REASON_LINE="$VULN_ONLY_FIRST 로 이 항목에 대해 취약합니다."

  else
    REASON_LINE="모든 대상 파일이 owner=root이고 others 쓰기 권한이 없어 이 항목에 대해 양호합니다."
  fi
fi

# raw_evidence는 DB 저장/재조회 시 줄바꿈이 복원되도록 \\n 형태로 저장되게 이스케이프 처리
CHECK_COMMAND_ESCAPED=$(json_escape "$CHECK_COMMAND")
REASON_LINE_ESCAPED=$(json_escape "$REASON_LINE")
DETAIL_CONTENT_ESCAPED=$(json_escape "$DETAIL_CONTENT")
GUIDE_LINE_ESCAPED=$(json_escape "$GUIDE_LINE")
TARGET_FILE_ESCAPED=$(json_escape "$TARGET_FILE")

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND_ESCAPED",
  "detail": "$REASON_LINE_ESCAPED\\n$DETAIL_CONTENT_ESCAPED",
  "guide": "$GUIDE_LINE_ESCAPED",
  "target_file": "$TARGET_FILE_ESCAPED"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(json_escape "$RAW_EVIDENCE")

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
