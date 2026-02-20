#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-09
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 계정이 존재하지 않는 GID 금지
# @Description : /etc/group 파일에 설정된 그룹 중 소속된 계정이 없는 불필요한 그룹 점검
# @Criteria_Good : 소속 계정이 없는 불필요한 그룹이 존재하지 않는 경우
# @Criteria_Bad : 소속 계정이 없는 불필요한 그룹이 존재하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-09"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

GROUP_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"
GSHADOW_FILE="/etc/gshadow"
TARGET_FILE="$GROUP_FILE $PASSWD_FILE $GSHADOW_FILE"

# 점검 명령
CHECK_COMMAND='[ -f /etc/group ] && [ -f /etc/passwd ] && [ -f /etc/gshadow ] && (echo "[unused_groups_gid_1000_plus]"; awk -F: '\''NR==FNR{u[$4]=1;next}{gid=$3;gm=$4;gname=$1;if(gid~/^[0-9]+$/&&gid>=1000){if(!u[gid]&&gm=="")print gname":"gid}}'\'' /etc/passwd /etc/group; echo "[mismatch_group_vs_gshadow]"; (cut -d: -f1 /etc/group | sed "/^$/d" | while read -r g; do grep -q "^${g}:" /etc/gshadow || echo "group_only:$g"; done); (cut -d: -f1 /etc/gshadow | sed "/^$/d" | while read -r g; do grep -q "^${g}:" /etc/group || echo "gshadow_only:$g"; done); echo "[ghost_members_in_group]"; awk -F: '\''NR==FNR{p[$1]=1;next}{if($4!=""){split($4,a,",");for(i in a){gsub(/^[ \t]+|[ \t]+$/,"",a[i]);if(a[i]!="" && !(a[i] in p))print $1":"a[i]}}'\'' /etc/passwd /etc/group ) || echo "group_or_passwd_or_gshadow_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE=""

UNUSED_GROUPS=()
MISMATCH_GROUPS=()
GHOST_MEMBERS=()

GID_MIN=1000

# JSON escape (따옴표, 역슬래시, 줄바꿈)
json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# 파일 존재 여부 분기
if [ -f "$GROUP_FILE" ] && [ -f "$PASSWD_FILE" ] && [ -f "$GSHADOW_FILE" ]; then
  # /etc/group과 /etc/gshadow 간 그룹명 불일치 여부를 수집
  while IFS=: read -r GNAME _; do
    [ -z "$GNAME" ] && continue
    if ! grep -qE "^${GNAME}:" "$GSHADOW_FILE" 2>/dev/null; then
      MISMATCH_GROUPS+=("group_only:$GNAME")
    fi
  done < "$GROUP_FILE"

  while IFS=: read -r GNAME _; do
    [ -z "$GNAME" ] && continue
    if ! grep -qE "^${GNAME}:" "$GROUP_FILE" 2>/dev/null; then
      MISMATCH_GROUPS+=("gshadow_only:$GNAME")
    fi
  done < "$GSHADOW_FILE"

  # /etc/group 멤버 목록에 존재하지 않는 계정이 포함되어 있는지(유령 멤버) 확인
  # 동시에 GID 1000 이상에서 유휴 그룹(멤버 없음 + primary 사용자 없음)을 수집
  while IFS=: read -r GNAME GPASS GID GMEM; do
    [ -z "$GNAME" ] && continue

    if [ -n "$GMEM" ]; then
      IFS=',' read -r -a MEMBERS <<< "$GMEM"
      for m in "${MEMBERS[@]}"; do
        m_trim="$(echo "$m" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$m_trim" ] && continue
        if ! awk -F: -v u="$m_trim" '$1==u{found=1} END{exit(found?0:1)}' "$PASSWD_FILE" 2>/dev/null; then
          GHOST_MEMBERS+=("$GNAME:$m_trim")
        fi
      done
    fi

    [ -z "$GID" ] && continue
    case "$GID" in
      ''|*[!0-9]*) continue ;;
    esac

    if [ "$GID" -ge "$GID_MIN" ]; then
      USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE" 2>/dev/null | head -n 1)
      if [ -z "$USER_EXISTS" ] && [ -z "$GMEM" ]; then
        UNUSED_GROUPS+=("$GNAME($GID)")
      fi
    fi
  done < "$GROUP_FILE"

  # 점검 결과 분기
  if [ ${#MISMATCH_GROUPS[@]} -gt 0 ] || [ ${#GHOST_MEMBERS[@]} -gt 0 ] || [ ${#UNUSED_GROUPS[@]} -gt 0 ]; then
    STATUS="FAIL"

    # 취약
    VULN_REASON_PARTS=()
    [ ${#MISMATCH_GROUPS[@]} -gt 0 ] && VULN_REASON_PARTS+=("mismatch_group_vs_gshadow=$(printf "%s," "${MISMATCH_GROUPS[@]}" | sed 's/,$//')")
    [ ${#GHOST_MEMBERS[@]} -gt 0 ] && VULN_REASON_PARTS+=("ghost_members_in_group=$(printf "%s," "${GHOST_MEMBERS[@]}" | sed 's/,$//')")
    [ ${#UNUSED_GROUPS[@]} -gt 0 ] && VULN_REASON_PARTS+=("unused_groups_gid_1000_plus=$(printf "%s," "${UNUSED_GROUPS[@]}" | sed 's/,$//')")

    REASON_LINE="$(IFS='; '; echo "${VULN_REASON_PARTS[*]}")로 이 항목에 대해 취약합니다."

    #DETAIL_CONTENT 구성
    DETAIL_CONTENT=""
    if [ ${#MISMATCH_GROUPS[@]} -gt 0 ]; then
      DETAIL_CONTENT="${DETAIL_CONTENT}mismatch_group_vs_gshadow:\n$(printf "%s\n" "${MISMATCH_GROUPS[@]}")\n"
    else
      DETAIL_CONTENT="${DETAIL_CONTENT}mismatch_group_vs_gshadow:\nnone\n"
    fi

    if [ ${#GHOST_MEMBERS[@]} -gt 0 ]; then
      DETAIL_CONTENT="${DETAIL_CONTENT}ghost_members_in_group:\n$(printf "%s\n" "${GHOST_MEMBERS[@]}")\n"
    else
      DETAIL_CONTENT="${DETAIL_CONTENT}ghost_members_in_group:\nnone\n"
    fi

    if [ ${#UNUSED_GROUPS[@]} -gt 0 ]; then
      DETAIL_CONTENT="${DETAIL_CONTENT}unused_groups_gid_1000_plus:\n$(printf "%s\n" "${UNUSED_GROUPS[@]}")"
    else
      DETAIL_CONTENT="${DETAIL_CONTENT}unused_groups_gid_1000_plus:\nnone"
    fi

    # 자동조치 위험 + 조치 방법
    GUIDE_LINE="계정/그룹 정합성을 자동으로 변경하면 파일/디렉터리 소유권, ACL, 서비스 계정 정책, LDAP/SSSD 연동 구성에 영향을 줄 수 있어 위험이 존재하여 수동 조치가 필요합니다. 관리자가 직접 확인 후 불일치 그룹(/etc/group↔/etc/gshadow) 정리, 존재하지 않는 계정의 그룹 멤버 제거, 사용되지 않는 그룹 삭제 여부를 검토하여 조치해 주시기 바랍니다."

  else
    STATUS="PASS"

    # 양호
    REASON_LINE="mismatch_group_vs_gshadow=none; ghost_members_in_group=none; unused_groups_gid_1000_plus=none로 이 항목에 대해 양호합니다."

    DETAIL_CONTENT="mismatch_group_vs_gshadow:\nnone\nghost_members_in_group:\nnone\nunused_groups_gid_1000_plus:\nnone"

    GUIDE_LINE="계정/그룹 정합성을 자동으로 변경하면 파일/디렉터리 소유권, ACL, 서비스 계정 정책, LDAP/SSSD 연동 구성에 영향을 줄 수 있어 위험이 존재하여 수동 조치가 필요합니다. 관리자가 직접 확인 후 불일치 그룹(/etc/group↔/etc/gshadow) 정리, 존재하지 않는 계정의 그룹 멤버 제거, 사용되지 않는 그룹 삭제 여부를 검토하여 조치해 주시기 바랍니다."
  fi

else
  STATUS="FAIL"

  # 파일 누락 시 취약
  MISSING=()
  [ ! -f "$GROUP_FILE" ] && MISSING+=("group_file_missing:/etc/group")
  [ ! -f "$PASSWD_FILE" ] && MISSING+=("passwd_file_missing:/etc/passwd")
  [ ! -f "$GSHADOW_FILE" ] && MISSING+=("gshadow_file_missing:/etc/gshadow")

  REASON_LINE="$(IFS='; '; echo "${MISSING[*]}")로 이 항목에 대해 취약합니다."

  DETAIL_CONTENT=""
  [ ! -f "$GROUP_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}group_file:/etc/group=missing\n" || DETAIL_CONTENT="${DETAIL_CONTENT}group_file:/etc/group=exists\n"
  [ ! -f "$PASSWD_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}passwd_file:/etc/passwd=missing\n" || DETAIL_CONTENT="${DETAIL_CONTENT}passwd_file:/etc/passwd=exists\n"
  [ ! -f "$GSHADOW_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}gshadow_file:/etc/gshadow=missing" || DETAIL_CONTENT="${DETAIL_CONTENT}gshadow_file:/etc/gshadow=exists"

  GUIDE_LINE="계정/그룹 정합성을 자동으로 변경하면 파일/디렉터리 소유권, ACL, 서비스 계정 정책, LDAP/SSSD 연동 구성에 영향을 줄 수 있어 위험이 존재하여 수동 조치가 필요합니다. 
  관리자가 직접 확인 후 누락된 파일을 복구하고, /etc/group·/etc/gshadow·/etc/passwd 정합성을 점검한 뒤 불필요한 그룹/유령 멤버/유휴 그룹을 정리해 주시기 바랍니다."
fi

# raw_evidence 구성 (문장 단위 줄바꿈 유지)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(json_escape "$RAW_EVIDENCE")

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
