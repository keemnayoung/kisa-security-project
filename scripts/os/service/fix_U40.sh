#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-40
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NFS 접근 통제
# @Description : NFS(Network File System)의 접근 통제 설정 적용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-40 NFS 접근 통제

# # 기본 변수
# ID="U-40"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# TARGET_FILE="/etc/exports"
# CHECK_COMMAND='
# ( command -v systemctl >/dev/null 2>&1 && (
#   systemctl is-active nfs-server 2>/dev/null || true;
#   systemctl is-enabled nfs-server 2>/dev/null || true;
#   systemctl is-active rpcbind 2>/dev/null || true;
#   systemctl is-enabled rpcbind 2>/dev/null || true;
# ) ) || echo "systemctl_not_found";
# stat -c "%U %G %a %n" /etc/exports 2>/dev/null;
# grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports 2>/dev/null | head -n 50
# '
# CHECK_COMMAND="$(echo "$CHECK_COMMAND" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"

# REASON_LINE=""
# DETAIL_CONTENT=""
# ACTION_ERR_LOG=""
# FAIL_FLAG=0
# MODIFIED=0

# add_err()   { ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\\n}$1"; }
# add_detail(){ DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\\n}$1"; }

# # root 권장 안내
# [ "$(id -u)" -ne 0 ] && add_err "(주의) root 권한이 아니면 조치가 실패할 수 있습니다."

# # 서비스 상태 읽기
# svc_state() {
#   if command -v systemctl >/dev/null 2>&1; then
#     NFS_A="$(systemctl is-active nfs-server 2>/dev/null | tr -d '[:space:]')"
#     NFS_E="$(systemctl is-enabled nfs-server 2>/dev/null | tr -d '[:space:]')"
#     RPC_A="$(systemctl is-active rpcbind 2>/dev/null | tr -d '[:space:]')"
#     RPC_E="$(systemctl is-enabled rpcbind 2>/dev/null | tr -d '[:space:]')"
#   else
#     NFS_A="unknown"; NFS_E="unknown"; RPC_A="unknown"; RPC_E="unknown"
#   fi
# }

# stop_disable() {
#   command -v systemctl >/dev/null 2>&1 || { add_err "systemctl 없음: 서비스 조치 불가"; return; }
#   systemctl stop nfs-server 2>/dev/null || add_err "stop nfs-server 실패"
#   systemctl disable nfs-server 2>/dev/null || add_err "disable nfs-server 실패"
#   systemctl stop rpcbind 2>/dev/null || add_err "stop rpcbind 실패"
#   systemctl disable rpcbind 2>/dev/null || add_err "disable rpcbind 실패"
#   MODIFIED=1
# }

# active_lines() {
#   grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$TARGET_FILE" 2>/dev/null || true
# }

# has_star()      { active_lines | grep -qE '(^|[[:space:]])\*([[:space:]]|\(|$)'; }
# has_nrs()       { active_lines | grep -qiE 'no_root_squash'; }
# has_only_path() { active_lines | awk '{l=$0; sub(/^[0-9]+:/,"",l); gsub(/^[ \t]+|[ \t]+$/,"",l); n=split(l,a,/[ \t]+/); if(n==1){exit 0}} END{exit 1}'; }

# svc_state

# # 1) exports 없으면: NFS 미사용으로 보고 서비스 stop/disable(필수)
# if [ ! -f "$TARGET_FILE" ]; then
#   stop_disable
#   svc_state
#   add_detail "services(after) nfs-server(active=$NFS_A enabled=$NFS_E) rpcbind(active=$RPC_A enabled=$RPC_E)"
#   add_detail "exports(after)=not_found"

#   if command -v systemctl >/dev/null 2>&1 && { [ "$NFS_A" = "active" ] || [ "$NFS_E" = "enabled" ] || [ "$RPC_A" = "active" ] || [ "$RPC_E" = "enabled" ]; }; then
#     IS_SUCCESS=0
#     REASON_LINE="/etc/exports가 없는데 NFS 서비스가 활성(또는 enable) 상태가 남아 있어 조치가 완료되지 않았습니다. NFS 미사용 시 서비스 중지/비활성화가 필요합니다."
#   else
#     IS_SUCCESS=1
#     REASON_LINE="/etc/exports가 없어 NFS 미사용 상태이며, NFS 서비스가 중지/비활성화되어 조치가 완료되었습니다."
#   fi

# else
#   # stat 실패 방어(필수)
#   OWNER="$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)"
#   GROUP="$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)"
#   PERM="$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)"

#   if [ -z "$OWNER" ] || [ -z "$GROUP" ] || [ -z "$PERM" ]; then
#     IS_SUCCESS=0
#     REASON_LINE="/etc/exports 소유자/그룹/권한 정보를 수집하지 못해 조치가 완료되지 않았습니다."
#     add_detail "exports(after) owner=${OWNER:-unknown} group=${GROUP:-unknown} perm=${PERM:-unknown}"
#   else
#     # exports 유효 라인이 비어있으면 미사용: 서비스 stop/disable(필수)
#     LINES="$(active_lines)"
#     if [ -z "$LINES" ]; then
#       stop_disable
#       # 파일은 표준화
#       [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ] && { chown root:root "$TARGET_FILE" 2>/dev/null || add_err "chown 실패"; MODIFIED=1; }
#       [ "$PERM" != "644" ] && { chmod 644 "$TARGET_FILE" 2>/dev/null || add_err "chmod 실패"; MODIFIED=1; }

#       svc_state
#       AOWNER="$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)"
#       AGROUP="$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)"
#       APERM="$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)"

#       add_detail "services(after) nfs-server(active=$NFS_A enabled=$NFS_E) rpcbind(active=$RPC_A enabled=$RPC_E)"
#       add_detail "exports(after) owner=$AOWNER group=$AGROUP perm=$APERM"
#       add_detail "exports_active_lines(after)=no_active_exports_lines"

#       if command -v systemctl >/dev/null 2>&1 && { [ "$NFS_A" = "active" ] || [ "$NFS_E" = "enabled" ] || [ "$RPC_A" = "active" ] || [ "$RPC_E" = "enabled" ]; }; then
#         IS_SUCCESS=0
#         REASON_LINE="NFS 미사용 상태로 보이나 서비스가 활성(또는 enable) 상태가 남아 있어 조치가 완료되지 않았습니다."
#       elif [ "$AOWNER" = "root" ] && [ "$AGROUP" = "root" ] && [ "$APERM" = "644" ]; then
#         IS_SUCCESS=1
#         REASON_LINE="유효한 공유 설정이 없어 NFS 미사용 상태이며, 서비스 중지/비활성화 및 /etc/exports 권한 표준화가 완료되어 조치가 완료되었습니다."
#       else
#         IS_SUCCESS=0
#         REASON_LINE="/etc/exports 권한 표준화가 기준을 충족하지 못해 조치가 완료되지 않았습니다."
#       fi

#     else
#       # 사용 중: 파일 권한 표준화(필수)
#       if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
#         chown root:root "$TARGET_FILE" 2>/dev/null || add_err "chown 실패"
#         MODIFIED=1
#       fi
#       if [ "$PERM" != "644" ]; then
#         chmod 644 "$TARGET_FILE" 2>/dev/null || add_err "chmod 실패"
#         MODIFIED=1
#       fi

#       # 위험 옵션은 자동수정 금지 → FAIL(필수)
#       has_star      && { FAIL_FLAG=1; add_err "everyone(*) 공유 설정 존재"; }
#       has_nrs       && { FAIL_FLAG=1; add_err "no_root_squash 옵션 존재"; }
#       has_only_path && { FAIL_FLAG=1; add_err "허용 호스트/옵션 미지정 라인 존재"; }

#       # 반영(exportfs -ra)
#       if command -v exportfs >/dev/null 2>&1; then
#         exportfs -ra 2>/dev/null || add_err "exportfs -ra 실패"
#       else
#         add_err "exportfs 없음: 설정 반영 불가"
#       fi

#       # 조치 이후 값만 evidence로 수집
#       AOWNER="$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)"
#       AGROUP="$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)"
#       APERM="$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)"
#       SAMPLE="$(active_lines | head -n 10)"; [ -z "$SAMPLE" ] && SAMPLE="no_active_exports_lines"

#       add_detail "exports(after) owner=$AOWNER group=$AGROUP perm=$APERM"
#       add_detail "wildcard_share_check(after)=$(has_star && echo wildcard_share_exists || echo no_wildcard_share)"
#       add_detail "no_root_squash_check(after)=$(has_nrs && echo no_root_squash_exists || echo no_no_root_squash)"
#       add_detail "host_spec_check(after)=$(has_only_path && echo only_path_line_exists || echo no_only_path_line)"
#       add_detail "exports_active_lines(after)=$SAMPLE"

#       if [ "$AOWNER" = "root" ] && [ "$AGROUP" = "root" ] && [ "$APERM" = "644" ] && [ "$FAIL_FLAG" -eq 0 ]; then
#         IS_SUCCESS=1
#         REASON_LINE="조치 이후 /etc/exports의 소유자/그룹(root) 및 권한(644)이 기준을 충족하고 위험 설정이 없어 조치가 완료되었습니다."
#       else
#         IS_SUCCESS=0
#         REASON_LINE="조치를 수행했으나 /etc/exports의 접근 통제 설정이 기준을 충족하지 못해 조치가 완료되지 않았습니다. everyone(*) 제거, 허용 호스트/대역 지정, no_root_squash 제거 후 exportfs -ra 적용이 필요합니다."
#       fi
#     fi
#   fi
# fi

# # 에러 로그를 detail 뒤에 합치기(조치 이후 값만 포함)
# [ -n "$ACTION_ERR_LOG" ] && add_detail "$ACTION_ERR_LOG"

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