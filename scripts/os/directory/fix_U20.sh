#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-20
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 설정
ID="U-20"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

FILES=(
  "/etc/inetd.conf"
  "/etc/xinetd.conf"
  "/etc/systemd/system.conf"
)

DIR="/etc/systemd"
XINETD_DIR="/etc/xinetd.d"

CHECK_COMMAND="for f in /etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf; do [ -f \"\$f\" ] && stat -c '%U %G %a %n' \"\$f\"; done; [ -d /etc/systemd ] && find /etc/systemd -type f -exec stat -c '%U %G %a %n' {} \\; 2>/dev/null; [ -d /etc/xinetd.d ] && find /etc/xinetd.d -type f -exec stat -c '%U %G %a %n' {} \\; 2>/dev/null"

TARGET_FILE=$(printf "%s\n" "${FILES[@]}")
if [ -d "$DIR" ]; then
  TARGET_FILE="${TARGET_FILE}
$DIR/*"
fi
if [ -d "$XINETD_DIR" ]; then
  TARGET_FILE="${TARGET_FILE}
$XINETD_DIR/*"
fi

FAIL_FLAG=0
MODIFIED=0
DETAIL_CONTENT=""

# 주요 설정 파일들에 대한 소유자 및 권한 조치
for FILE in "${FILES[@]}"; do
  if [ ! -f "$FILE" ]; then
    continue
  fi

  OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
  GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
  PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

  if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
    chown root:root "$FILE" 2>/dev/null
    MODIFIED=1
  fi

  if [ -n "$PERM" ] && [ "$PERM" -gt 600 ]; then
    chmod 600 "$FILE" 2>/dev/null
    MODIFIED=1
  fi
done

# systemd 디렉터리 내 하위 파일들 조치
if [ -d "$DIR" ]; then
  while IFS= read -r FILE; do
    [ -f "$FILE" ] || continue

    OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
      chown root:root "$FILE" 2>/dev/null
      MODIFIED=1
    fi

    if [ -n "$PERM" ] && [ "$PERM" -gt 600 ]; then
      chmod 600 "$FILE" 2>/dev/null
      MODIFIED=1
    fi
  done < <(find "$DIR" -type f 2>/dev/null)
fi

# xinetd.d 디렉터리 내 하위 파일들 조치
if [ -d "$XINETD_DIR" ]; then
  while IFS= read -r FILE; do
    [ -f "$FILE" ] || continue

    OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
      chown root:root "$FILE" 2>/dev/null
      MODIFIED=1
    fi

    if [ -n "$PERM" ] && [ "$PERM" -gt 600 ]; then
      chmod 600 "$FILE" 2>/dev/null
      MODIFIED=1
    fi
  done < <(find "$XINETD_DIR" -type f 2>/dev/null)
fi

# 조치 결과에 대한 최종 상태 값 수집 및 검증
for FILE in "${FILES[@]}"; do
  if [ -f "$FILE" ]; then
    AFTER_OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    DETAIL_CONTENT="${DETAIL_CONTENT}file=$FILE, owner=$AFTER_OWNER, group=$AFTER_GROUP, perm=$AFTER_PERM
"

    if [ "$AFTER_OWNER" != "root" ] || [ "$AFTER_GROUP" != "root" ] || { [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 600 ]; }; then
      FAIL_FLAG=1
    fi
  fi
done

if [ -d "$DIR" ]; then
  while IFS= read -r FILE; do
    [ -f "$FILE" ] || continue
    AFTER_OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    DETAIL_CONTENT="${DETAIL_CONTENT}file=$FILE, owner=$AFTER_OWNER, group=$AFTER_GROUP, perm=$AFTER_PERM
"

    if [ "$AFTER_OWNER" != "root" ] || [ "$AFTER_GROUP" != "root" ] || { [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 600 ]; }; then
      FAIL_FLAG=1
    fi
  done < <(find "$DIR" -type f 2>/dev/null)
fi

if [ -d "$XINETD_DIR" ]; then
  while IFS= read -r FILE; do
    [ -f "$FILE" ] || continue
    AFTER_OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    DETAIL_CONTENT="${DETAIL_CONTENT}file=$FILE, owner=$AFTER_OWNER, group=$AFTER_GROUP, perm=$AFTER_PERM
"

    if [ "$AFTER_OWNER" != "root" ] || [ "$AFTER_GROUP" != "root" ] || { [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 600 ]; }; then
      FAIL_FLAG=1
    fi
  done < <(find "$XINETD_DIR" -type f 2>/dev/null)
fi

# 수집된 데이터를 바탕으로 최종 성공 여부 판정
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="파일들의 소유자와 그룹을 root로 변경하고 권한을 600 이하로 조치를 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  REASON_LINE="소유자 권한이 root가 아니거나 파일 모드가 600을 초과하는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
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

# JSON escape 처리 (따옴표, 줄바꿈)
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