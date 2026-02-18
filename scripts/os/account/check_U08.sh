#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-08
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 관리자 그룹에 최소한의 계정 포함
# @Description : 관리자 그룹(root, GID 0)에 불필요한 계정이 포함되어 있는지 점검
# @Criteria_Good : root 그룹(GID 0)에 root 이외 계정이 포함되지 않은 경우
# @Criteria_Bad : root 그룹(GID 0)에 root 이외 계정이 포함된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-08"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/group,/etc/passwd"
CHECK_COMMAND='[ -f /etc/group ] && (grep -E "^root:x:0:" /etc/group || echo "root_group_line_not_found") || echo "group_file_not_found"; [ -f /etc/passwd ] && awk -F: '"'"'($4==0 && $1!="root"){print $1":"$3":"$7}'"'"' /etc/passwd || echo "passwd_file_not_found"'

DETAIL_CONTENT=""
ROOT_GROUP_USERS=""
EXTRA_USERS=""
PRIMARY_GID0_USERS=""            # (취약 후보) 예외 제외 후 남는 GID=0 사용자(이름만)
PRIMARY_GID0_EXCLUDED_USERS=""   # (예외) 시스템 계정으로 제외된 사용자(근거 포함)

# UID_MIN은 일반 사용자 시작 UID 기준이며, 시스템 계정 분류에 사용합니다.
UID_MIN=$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/{print $2; exit}' /etc/login.defs 2>/dev/null)
if ! [[ "$UID_MIN" =~ ^[0-9]+$ ]]; then
  UID_MIN=1000
fi

# 일부 기본 시스템 계정은 환경에 따라 shell 값이 다를 수 있어, UID<UID_MIN 조건 하에 이름으로 예외 허용합니다.
PRIMARY_GID0_NAME_ALLOWLIST="sync shutdown halt"

# /etc/group이 없으면 root 그룹 구성원을 확인할 수 없습니다.
if [ -f "/etc/group" ]; then
  # /etc/group의 root 그룹(=GID 0) 멤버 필드(4번째)를 확인합니다.
  ROOT_GROUP_USERS=$(grep -E '^root:x:0:' "/etc/group" 2>/dev/null | cut -d: -f4 | tail -n 1)

  # 보조 그룹 멤버로 포함된 계정 중 root 이외 계정만 추출합니다.
  EXTRA_USERS=$(echo "$ROOT_GROUP_USERS" \
      | tr ',' '\n' \
      | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
      | grep -v '^root$' \
      | grep -v '^$' )

  # /etc/passwd의 주 그룹(GID=0) 계정을 확인하고, 시스템 계정 예외를 제외합니다.
  if [ -f "/etc/passwd" ]; then
    while IFS=: read -r u uid sh; do
      if ! [[ "$uid" =~ ^[0-9]+$ ]]; then
        PRIMARY_GID0_USERS="${PRIMARY_GID0_USERS}${PRIMARY_GID0_USERS:+$'\n'}$u"
        continue
      fi

      IS_NAME_ALLOWED=0
      for a in $PRIMARY_GID0_NAME_ALLOWLIST; do
        if [ "$u" = "$a" ]; then
          IS_NAME_ALLOWED=1
          break
        fi
      done

      if [ "$uid" -lt "$UID_MIN" ] && ( echo "$sh" | grep -Eq '(nologin|false)$' || [ "$IS_NAME_ALLOWED" -eq 1 ] ); then
        PRIMARY_GID0_EXCLUDED_USERS="${PRIMARY_GID0_EXCLUDED_USERS}${PRIMARY_GID0_EXCLUDED_USERS:+$'\n'}${u}(uid=${uid},shell=${sh})"
      else
        PRIMARY_GID0_USERS="${PRIMARY_GID0_USERS}${PRIMARY_GID0_USERS:+$'\n'}$u"
      fi
    done < <(awk -F: '($4==0 && $1!="root"){print $1 ":" $3 ":" $7}' /etc/passwd 2>/dev/null)
  else
    PRIMARY_GID0_USERS="passwd_file_not_found"
  fi

  # DETAIL_CONTENT는 양호/취약과 관계 없이 "현재 설정 값"만 출력합니다.
  if [ -n "$ROOT_GROUP_USERS" ]; then
    DETAIL_CONTENT="root_group_members=$ROOT_GROUP_USERS"
  else
    DETAIL_CONTENT="root_group_members=empty"
  fi

  if [ -n "$PRIMARY_GID0_USERS" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"primary_gid0_users_detected="$'\n'"$PRIMARY_GID0_USERS"
  else
    DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"primary_gid0_users_detected=empty"
  fi

  if [ -n "$PRIMARY_GID0_EXCLUDED_USERS" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"primary_gid0_users_excluded="$'\n'"$PRIMARY_GID0_EXCLUDED_USERS"
  else
    DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"primary_gid0_users_excluded=empty"
  fi

  # 판단 분기: 취약 조건은 (1) /etc/group에 root 외 멤버 존재 또는 (2) 예외 제외 후 GID=0 계정 존재
  if [ -z "$EXTRA_USERS" ] && [ -z "$PRIMARY_GID0_USERS" ]; then
    STATUS="PASS"
    # 양호 사유(설정 값만 사용) + 한 문장
    REASON_LINE="root_group_members=${ROOT_GROUP_USERS:-empty}, primary_gid0_users_detected=empty로 이 항목에 대해 양호합니다."
  else
    STATUS="FAIL"
    # 취약 사유는 취약 부분 설정만 포함 + 한 문장
    VULN_PARTS=""
    if [ -n "$EXTRA_USERS" ]; then
      VULN_PARTS="root_group_extra_members=$(echo "$EXTRA_USERS" | tr '\n' ',' | sed 's/,$//')"
    fi
    if [ -n "$PRIMARY_GID0_USERS" ]; then
      [ -n "$VULN_PARTS" ] && VULN_PARTS="${VULN_PARTS}, "
      VULN_PARTS="${VULN_PARTS}primary_gid0_users_detected=$(echo "$PRIMARY_GID0_USERS" | tr '\n' ',' | sed 's/,$//')"
    fi
    REASON_LINE="${VULN_PARTS}로 이 항목에 대해 취약합니다."
  fi
else
  STATUS="FAIL"
  # /etc/group이 없으면 설정 확인 자체가 불가하므로 취약으로 판단(취약 부분 설정만)
  REASON_LINE="target_file=/etc/group missing로 이 항목에 대해 취약합니다."
  DETAIL_CONTENT="group_file_not_found"
fi

# RAW_EVIDENCE: 문장/항목은 줄바꿈으로 구분되며, DB 저장/로드 후에도 줄바꿈이 유지되도록 escape 처리합니다.
GUIDE_LINE="자동 조치 시 시스템 계정(예: 기본 시스템 계정/서비스 계정)의 그룹 변경으로 서비스 장애 또는 권한 문제(파일 접근 실패 등)가 발생할 수 있어 수동 조치가 필요합니다.\n관리자가 root 그룹(GID 0) 멤버 및 GID=0 주 그룹 계정의 UID/SHELL/용도를 직접 확인 후, 불필요 계정은 root 그룹에서 제거(gpasswd -d <user> root)하고 주 그룹이 0인 계정은 정책에 맞는 그룹으로 변경(usermod -g <target_group> <user>)해 주시기 바랍니다."

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
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
