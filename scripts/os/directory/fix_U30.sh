#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-18
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : 시스템 UMASK 값 022 이상으로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수 초기화 분기점
ID="U-30"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PROFILE_OK=0
LOGIN_DEFS_OK=0
PROFILED_OK=1   # profile.d 는 파일이 없으면 OK로 취급
BASHRC_OK=1     # bashrc 는 파일이 없으면 OK로 취급

FINAL_PROFILE=""
FINAL_LOGIN_DEFS=""

PROFILE_FILE="/etc/profile"
LOGIN_DEFS_FILE="/etc/login.defs"
BASHRC_FILE="/etc/bashrc"
PROFILED_GLOB="/etc/profile.d/*.sh"

TARGET_FILE="/etc/profile
/etc/profile.d/*.sh
/etc/bashrc
/etc/login.defs"

CHECK_COMMAND="( [ -f /etc/profile ] && grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile | tail -n 3 || echo 'profile_not_found' ) ; \
( ls -1 /etc/profile.d/*.sh >/dev/null 2>&1 && grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile.d/*.sh | tail -n 5 || echo 'profile_d_not_found_or_no_umask' ) ; \
( [ -f /etc/bashrc ] && grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/bashrc | tail -n 3 || echo 'bashrc_not_found_or_no_umask' ) ; \
( [ -f /etc/login.defs ] && grep -inE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs | tail -n 3 || echo 'login_defs_not_found' )"

# UMASK 값 유효성 판정 함수 분기점
is_umask_ok() {
  local raw="$1"
  local v dec required
  v=$(echo "$raw" | grep -oE '^[0-9]+' || true)
  [ -z "$v" ] && return 1

  dec=$((8#$v))
  required=$((8#022))

  if [ $(( dec & required )) -eq "$required" ]; then
    return 0
  fi
  return 1
}

# /etc/profile 조치 분기점
if [ -f "$PROFILE_FILE" ]; then
  CUR_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$PROFILE_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$CUR_PROFILE" ] && is_umask_ok "$CUR_PROFILE"; then
    PROFILE_OK=1
  else
    sed -i '/^[[:space:]]*umask[[:space:]]\+[0-9]\+/Id' "$PROFILE_FILE"
    printf "\numask 022\nexport umask\n" >> "$PROFILE_FILE"
  fi

  FINAL_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$PROFILE_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$FINAL_PROFILE" ] && is_umask_ok "$FINAL_PROFILE"; then
    PROFILE_OK=1
  fi
fi

# /etc/profile.d/*.sh 조치 분기점
PROFILED_OK=1
if ls -1 $PROFILED_GLOB >/dev/null 2>&1; then
  for f in $PROFILED_GLOB; do
    [ -f "$f" ] || continue
    CUR_PD=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$f" 2>/dev/null | tail -n 1 | awk '{print $2}')
    if [ -n "$CUR_PD" ]; then
      if is_umask_ok "$CUR_PD"; then
        : 
      else
        sed -i -E 's/^[[:space:]]*umask[[:space:]]+[0-9]+/umask 022/I' "$f"
      fi

      FINAL_PD=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$f" 2>/dev/null | tail -n 1 | awk '{print $2}')
      if [ -n "$FINAL_PD" ] && ! is_umask_ok "$FINAL_PD"; then
        PROFILED_OK=0
      fi
    fi
  done
fi

# /etc/bashrc 조치 분기점
BASHRC_OK=1
if [ -f "$BASHRC_FILE" ]; then
  CUR_BASHRC=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$BASHRC_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$CUR_BASHRC" ]; then
    if is_umask_ok "$CUR_BASHRC"; then
      BASHRC_OK=1
    else
      sed -i -E 's/^[[:space:]]*umask[[:space:]]+[0-9]+/umask 022/I' "$BASHRC_FILE"
      FINAL_BASHRC=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$BASHRC_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
      if [ -n "$FINAL_BASHRC" ] && is_umask_ok "$FINAL_BASHRC"; then
        BASHRC_OK=1
      else
        BASHRC_OK=0
      fi
    fi
  fi
fi

# /etc/login.defs 조치 분기점
if [ -f "$LOGIN_DEFS_FILE" ]; then
  CUR_LOGIN=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' "$LOGIN_DEFS_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$CUR_LOGIN" ] && is_umask_ok "$CUR_LOGIN"; then
    LOGIN_DEFS_OK=1
  else
    sed -i '/^[[:space:]]*UMASK[[:space:]]\+[0-9]\+/Id' "$LOGIN_DEFS_FILE"
    echo "UMASK 022" >> "$LOGIN_DEFS_FILE"
  fi

  FINAL_LOGIN_DEFS=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' "$LOGIN_DEFS_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$FINAL_LOGIN_DEFS" ] && is_umask_ok "$FINAL_LOGIN_DEFS"; then
    LOGIN_DEFS_OK=1
  fi
fi

# 현재 설정 값 정보 수집 분기점
DETAIL_CONTENT=""

if [ -f "$PROFILE_FILE" ]; then
  PROFILE_LINE=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$PROFILE_FILE" 2>/dev/null | tail -n 1)
  [ -n "$PROFILE_LINE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${PROFILE_LINE}\n"
fi

if ls -1 $PROFILED_GLOB >/dev/null 2>&1; then
  PD_LINES=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' $PROFILED_GLOB 2>/dev/null | tail -n 5)
  [ -n "$PD_LINES" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${PD_LINES}\n"
fi

if [ -f "$BASHRC_FILE" ]; then
  BASHRC_LINE=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$BASHRC_FILE" 2>/dev/null | tail -n 1)
  [ -n "$BASHRC_LINE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${BASHRC_LINE}\n"
fi

if [ -f "$LOGIN_DEFS_FILE" ]; then
  LOGIN_LINE=$(grep -inE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' "$LOGIN_DEFS_FILE" 2>/dev/null | tail -n 1)
  [ -n "$LOGIN_LINE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${LOGIN_LINE}\n"
fi

# 최종 결과 판정 및 REASON_LINE 확정 분기점
if [ "$PROFILE_OK" -eq 1 ] && [ "$LOGIN_DEFS_OK" -eq 1 ] && [ "$PROFILED_OK" -eq 1 ] && [ "$BASHRC_OK" -eq 1 ]; then
  IS_SUCCESS=1
  REASON_LINE="주요 설정 파일의 UMASK 값을 022 이상으로 설정하여 조치를 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  if [ ! -f "$PROFILE_FILE" ] || [ ! -f "$LOGIN_DEFS_FILE" ]; then
    REASON_LINE="필수 설정 파일이 존재하지 않는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  else
    REASON_LINE="일부 설정 파일에 취약한 UMASK 값이 남아 있는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  fi
fi

# RAW_EVIDENCE 작성을 위한 JSON 구조 생성 분기점
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 데이터 이스케이프 처리 분기점
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 JSON 결과 출력 분기점
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF