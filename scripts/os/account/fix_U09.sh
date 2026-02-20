#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-09
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 계정이 존재하지 않는 GID 금지
# @Description : 소속된 계정이 없는 불필요한 그룹을 제거하여 그룹 관리 체계 정비
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# # 기본 변수
# ID="U-09"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# GROUP_FILE="/etc/group"
# PASSWD_FILE="/etc/passwd"
# GSHADOW_FILE="/etc/gshadow"

# TARGET_FILE="$GROUP_FILE
# $PASSWD_FILE
# $GSHADOW_FILE"

# # 조치 대상 식별 커맨드(기존 + gshadow 정합성/유령멤버는 detail로 기록)
# CHECK_COMMAND="(awk -F: 'NR==FNR{g[\$3]=\$0;next}{u[\$4]=1} END{for(gid in g){split(g[gid],a,\":\"); if(gid>=1000){gm=a[4]; if(!u[gid] && gm==\"\"){print a[1]\":\"gid\":\"gm}}}}' /etc/group /etc/passwd 2>/dev/null)"

# GID_MIN=1000
# MODIFIED=0
# FAIL_FLAG=0

# REMOVED_GROUPS=()
# FIXED_MISMATCH=()
# REMOVED_GSHADOW_ONLY=()
# REMOVED_GHOST_MEMBERS=()

# # 조치 수행
# if [ -f "$GROUP_FILE" ] && [ -f "$PASSWD_FILE" ] && [ -f "$GSHADOW_FILE" ]; then

#   # ---------------------------
#   # 1) /etc/group ↔ /etc/gshadow 정합성 불일치 조치
#   #    - group에만 있는 그룹: gshadow에 기본 엔트리 추가
#   #    - gshadow에만 있는 엔트리: gshadow에서 라인 삭제
#   # ---------------------------

#   # group_only -> gshadow 엔트리 추가
#   while IFS=: read -r GNAME _; do
#     [ -z "$GNAME" ] && continue
#     if ! grep -qE "^${GNAME}:" "$GSHADOW_FILE" 2>/dev/null; then
#       # gshadow 기본 포맷: group:passwd:admins:members
#       # passwd는 잠금 상태로 두기 위해 '!' 사용
#       echo "${GNAME}:!::" >> "$GSHADOW_FILE" 2>/dev/null
#       if [ $? -eq 0 ]; then
#         FIXED_MISMATCH+=("added_gshadow_entry:$GNAME")
#         MODIFIED=1
#       else
#         FAIL_FLAG=1
#       fi
#     fi
#   done < "$GROUP_FILE"

#   # gshadow_only -> gshadow 라인 삭제
#   while IFS=: read -r GNAME _; do
#     [ -z "$GNAME" ] && continue
#     if ! grep -qE "^${GNAME}:" "$GROUP_FILE" 2>/dev/null; then
#       # 해당 그룹명 엔트리 제거
#       if sed -i "/^${GNAME}:/d" "$GSHADOW_FILE" 2>/dev/null; then
#         REMOVED_GSHADOW_ONLY+=("removed_orphan_gshadow_entry:$GNAME")
#         MODIFIED=1
#       else
#         FAIL_FLAG=1
#       fi
#     fi
#   done < "$GSHADOW_FILE"

#   # ---------------------------
#   # 2) /etc/group GMEM에 존재하지 않는 계정(유령 멤버) 제거
#   #    - gpasswd -d <user> <group> 로 멤버십 제거
#   # ---------------------------
#   while IFS=: read -r GNAME GPASS GID GMEM; do
#     [ -z "$GNAME" ] && continue
#     [ -z "$GMEM" ] && continue

#     IFS=',' read -r -a MEMBERS <<< "$GMEM"
#     for m in "${MEMBERS[@]}"; do
#       m_trim="$(echo "$m" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
#       [ -z "$m_trim" ] && continue

#       # /etc/passwd에 사용자 존재 여부 확인
#       if ! awk -F: -v u="$m_trim" '$1==u{found=1} END{exit(found?0:1)}' "$PASSWD_FILE" 2>/dev/null; then
#         # 존재하지 않는 유저면 그룹 멤버십 제거 시도
#         if gpasswd -d "$m_trim" "$GNAME" >/dev/null 2>&1; then
#           REMOVED_GHOST_MEMBERS+=("$GNAME:$m_trim")
#           MODIFIED=1
#         else
#           FAIL_FLAG=1
#         fi
#       fi
#     done
#   done < "$GROUP_FILE"

#   # ---------------------------
#   # 3) 유휴 그룹(GID 1000+ & primary 사용자 없음 & GMEM 비어있음) 삭제
#   #    - 읽는 중 삭제로 인한 이슈 방지 위해 삭제 후보를 먼저 수집 후 처리
#   # ---------------------------
#   DELETE_CANDIDATES=()
#   while IFS=: read -r GNAME GPASS GID GMEM; do
#     [ -z "$GID" ] && continue
#     case "$GID" in
#       ''|*[!0-9]*) continue ;;
#     esac

#     if [ "$GID" -ge "$GID_MIN" ]; then
#       USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE" 2>/dev/null | head -n 1)
#       if [ -z "$USER_EXISTS" ] && [ -z "$GMEM" ]; then
#         DELETE_CANDIDATES+=("$GNAME")
#       fi
#     fi
#   done < "$GROUP_FILE"

#   for g in "${DELETE_CANDIDATES[@]}"; do
#     if groupdel "$g" >/dev/null 2>&1; then
#       REMOVED_GROUPS+=("$g")
#       MODIFIED=1
#     else
#       FAIL_FLAG=1
#     fi
#   done

#   # ---------------------------
#   # 조치 후 상태 수집(조치 후 상태만 detail에 표시)
#   # ---------------------------

#   # (A) group<->gshadow 불일치 재확인
#   STILL_MISMATCH=()
#   while IFS=: read -r GNAME _; do
#     [ -z "$GNAME" ] && continue
#     if ! grep -qE "^${GNAME}:" "$GSHADOW_FILE" 2>/dev/null; then
#       STILL_MISMATCH+=("group_only:$GNAME")
#     fi
#   done < "$GROUP_FILE"

#   while IFS=: read -r GNAME _; do
#     [ -z "$GNAME" ] && continue
#     if ! grep -qE "^${GNAME}:" "$GROUP_FILE" 2>/dev/null; then
#       STILL_MISMATCH+=("gshadow_only:$GNAME")
#     fi
#   done < "$GSHADOW_FILE"

#   # (B) 유령 멤버 재확인
#   STILL_GHOST=()
#   while IFS=: read -r GNAME GPASS GID GMEM; do
#     [ -z "$GNAME" ] && continue
#     [ -z "$GMEM" ] && continue
#     IFS=',' read -r -a MEMBERS <<< "$GMEM"
#     for m in "${MEMBERS[@]}"; do
#       m_trim="$(echo "$m" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
#       [ -z "$m_trim" ] && continue
#       if ! awk -F: -v u="$m_trim" '$1==u{found=1} END{exit(found?0:1)}' "$PASSWD_FILE" 2>/dev/null; then
#         STILL_GHOST+=("$GNAME:$m_trim")
#       fi
#     done
#   done < "$GROUP_FILE"

#   # (C) 기존 로직의 유휴 그룹 재확인
#   STILL_GROUPS=$(awk -F: -v min="$GID_MIN" '
#     NR==FNR { u[$4]=1; next }
#     {
#       gid=$3; gm=$4; gname=$1
#       if (gid ~ /^[0-9]+$/ && gid >= min) {
#         if (!u[gid] && gm == "") print gname ":" gid
#       }
#     }
#   ' "$PASSWD_FILE" "$GROUP_FILE" 2>/dev/null | sed '/^[[:space:]]*$/d')

#   # detail 구성(조치 후 상태 중심)
#   DETAIL_CONTENT=""
#   DETAIL_CONTENT="${DETAIL_CONTENT}remaining_mismatch_group_vs_gshadow=$(printf "%s" "${#STILL_MISMATCH[@]}")\n"
#   if [ ${#STILL_MISMATCH[@]} -gt 0 ]; then
#     DETAIL_CONTENT="${DETAIL_CONTENT}still_mismatch:\n$(printf "%s\n" "${STILL_MISMATCH[@]}")\n"
#   fi

#   DETAIL_CONTENT="${DETAIL_CONTENT}remaining_ghost_members=$(printf "%s" "${#STILL_GHOST[@]}")\n"
#   if [ ${#STILL_GHOST[@]} -gt 0 ]; then
#     DETAIL_CONTENT="${DETAIL_CONTENT}still_ghost_members:\n$(printf "%s\n" "${STILL_GHOST[@]}")\n"
#   fi

#   if [ -n "$STILL_GROUPS" ]; then
#     DETAIL_CONTENT="${DETAIL_CONTENT}still_unused_groups_gid_1000_plus:\n$STILL_GROUPS\n"
#   else
#     DETAIL_CONTENT="${DETAIL_CONTENT}still_unused_groups_gid_1000_plus:\nnone\n"
#   fi

#   # 조치 내역
#   DETAIL_CONTENT="${DETAIL_CONTENT}removed_groups=$(printf "%s" "${#REMOVED_GROUPS[@]}")\n"
#   DETAIL_CONTENT="${DETAIL_CONTENT}fixed_mismatch_added=$(printf "%s" "${#FIXED_MISMATCH[@]}")\n"
#   DETAIL_CONTENT="${DETAIL_CONTENT}removed_orphan_gshadow=$(printf "%s" "${#REMOVED_GSHADOW_ONLY[@]}")\n"
#   DETAIL_CONTENT="${DETAIL_CONTENT}removed_ghost_members=$(printf "%s" "${#REMOVED_GHOST_MEMBERS[@]}")"

#   # 최종 판정
#   if [ ${#STILL_MISMATCH[@]} -eq 0 ] && [ ${#STILL_GHOST[@]} -eq 0 ] && [ -z "$STILL_GROUPS" ] && [ "$FAIL_FLAG" -eq 0 ]; then
#     IS_SUCCESS=1
#     if [ "$MODIFIED" -eq 1 ]; then
#       REASON_LINE="(/etc/group, /etc/gshadow, /etc/passwd) 정합성 불일치 및 존재하지 않는 계정의 그룹 멤버 등록, 유휴 그룹을 정리하여 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     else
#       REASON_LINE="정합성 불일치/유령 멤버/유휴 그룹이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     fi
#   else
#     IS_SUCCESS=0
#     REASON_LINE="조치를 수행했으나 (/etc/group, /etc/gshadow) 정합성 불일치 또는 존재하지 않는 계정의 그룹 멤버 등록, 또는 유휴 그룹이 남아 있거나 조치 과정에서 오류가 발생하여 조치가 완료되지 않았습니다."
#   fi

# else
#   IS_SUCCESS=0
#   if [ ! -f "$GROUP_FILE" ]; then
#     REASON_LINE="조치 대상 파일(/etc/group)이 존재하지 않아 조치가 완료되지 않았습니다."
#   elif [ ! -f "$PASSWD_FILE" ]; then
#     REASON_LINE="조치 대상 파일(/etc/passwd)이 존재하지 않아 조치가 완료되지 않았습니다."
#   else
#     REASON_LINE="조치 대상 파일(/etc/gshadow)이 존재하지 않아 조치가 완료되지 않았습니다."
#   fi
#   DETAIL_CONTENT=""
# fi

# # raw_evidence 구성
# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# # JSON escape 처리 (따옴표, 줄바꿈)
# RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
#   | sed 's/"/\\"/g' \
#   | sed ':a;N;$!ba;s/\n/\\n/g')

# # DB 저장용 JSON 출력
# echo ""
# cat << EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF