#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-51
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : allow-update 전체 허용(any/*/0.0.0.0/0) 설정을 none으로 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# # 기본 변수
# ID="U-51"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# TARGET_FILE="N/A"
# USE_DNS_DYNAMIC_UPDATE="${USE_DNS_DYNAMIC_UPDATE:-no}"  # no(기본)=동적업데이트 차단, yes=수동조치 안내

# CHECK_COMMAND='
# systemctl is-active named named-chroot 2>/dev/null; pgrep -x named 2>/dev/null;
# command -v named-checkconf >/dev/null 2>&1 && echo "named-checkconf_available" || echo "named-checkconf_not_found";
# for f in /etc/named.conf /etc/bind/named.conf.options /etc/bind/named.conf; do [ -f "$f" ] && echo "seed_conf=$f"; done
# '

# REASON_LINE=""
# DETAIL_CONTENT=""
# ACTION_ERR_LOG=""

# mode="no"
# case "$USE_DNS_DYNAMIC_UPDATE" in yes|YES|Yes|true|TRUE|on|ON|1) mode="yes";; *) mode="no";; esac

# append_detail(){ [ -z "${1:-}" ] && return 0; DETAIL_CONTENT="${DETAIL_CONTENT:+$DETAIL_CONTENT\n}$1"; }
# append_err(){ [ -z "${1:-}" ] && return 0; ACTION_ERR_LOG="${ACTION_ERR_LOG:+$ACTION_ERR_LOG\n}$1"; }

# is_named_running() {
#   command -v systemctl >/dev/null 2>&1 && { systemctl is-active --quiet named || systemctl is-active --quiet named-chroot; } && return 0
#   pgrep -x named >/dev/null 2>&1
# }

# restart_named() {
#   command -v systemctl >/dev/null 2>&1 || return 0
#   systemctl list-unit-files 2>/dev/null | grep -qiE '^named\.service[[:space:]]' && systemctl restart named >/dev/null 2>&1 && return 0
#   systemctl list-unit-files 2>/dev/null | grep -qiE '^named-chroot\.service[[:space:]]' && systemctl restart named-chroot >/dev/null 2>&1 && return 0
#   return 0
# }

# # include "..." 재귀 수집
# collect_conf() {
#   local -a q=() out=() seeds=("$@"); declare -A seen=()
#   local f dir inc p
#   for f in "${seeds[@]}"; do [ -f "$f" ] && q+=("$f"); done
#   while [ "${#q[@]}" -gt 0 ]; do
#     f="${q[0]}"; q=("${q[@]:1}")
#     [ -f "$f" ] || continue
#     [ -n "${seen["$f"]+x}" ] && continue
#     seen["$f"]=1; out+=("$f")
#     dir="$(dirname "$f")"
#     while IFS= read -r inc; do
#       [ -z "$inc" ] && continue
#       [[ "$inc" = /* ]] && p="$inc" || p="$dir/$inc"
#       [ -f "$p" ] && q+=("$p")
#     done < <(grep -hE '^[[:space:]]*include[[:space:]]+"' "$f" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')
#   done
#   printf '%s\n' "${out[@]}"
# }

# backup_once(){ [ -f "$1" ] || return 0; [ -f "${1}.bak_kisa_u51" ] || cp -a "$1" "${1}.bak_kisa_u51" 2>/dev/null; }

# # allow-update { ... }; (멀티라인 포함) -> allow-update { none; };
# rewrite_allow_update_none() {
#   local file="$1" tmp rc
#   tmp="$(mktemp)"
#   awk '
#     BEGIN{IGNORECASE=1; in=0; saw=0}
#     {
#       l=$0
#       if(in==0){
#         if(l ~ /^[[:space:]]*allow-update[[:space:]]*\{/){
#           saw=1; in=1
#           print "    allow-update { none; };"
#           if(l ~ /\}[[:space:]]*;/) in=0
#           next
#         }
#         print $0; next
#       }
#       if(l ~ /\}[[:space:]]*;/) in=0
#       next
#     }
#     END{ if(saw==0) exit 3 }
#   ' "$file" > "$tmp"
#   rc=$?
#   if [ "$rc" -eq 0 ]; then mv "$tmp" "$file"; return 0; fi
#   rm -f "$tmp"; return 1
# }

# # 설정 전체에서 allow-update / update-policy 블록 존재 여부(멀티라인 고려)
# count_blocks() {
#   # 출력: "AU=<n> UP=<n>"
#   awk '
#     BEGIN{IGNORECASE=1; au=0; up=0}
#     /^[[:space:]]*#/ {next}
#     /^[[:space:]]*\/\// {next}
#     /allow-update[[:space:]]*\{/ {au++}
#     /update-policy[[:space:]]*\{/ {up++}
#     END{printf "AU=%d UP=%d\n", au, up}
#   ' "$@"
# }

# ########################################
# # 조치 프로세스
# ########################################
# if [ "$(id -u)" -ne 0 ]; then
#   REASON_LINE="root 권한이 아니어서 DNS 동적 업데이트 제한 설정을 적용할 수 없어 조치를 중단합니다."
#   append_detail "mode(current)=$mode"
#   append_err "(주의) root 권한이 아니면 설정 파일 수정 및 서비스 재시작이 실패할 수 있습니다."
# else
#   if ! is_named_running; then
#     IS_SUCCESS=1
#     REASON_LINE="DNS(named) 서비스가 비활성화되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#     append_detail "named_status(current)=inactive_or_not_running"
#     append_detail "mode(current)=$mode"
#   else
#     append_detail "named_status(current)=running"
#     append_detail "mode(current)=$mode"

#     if [ "$mode" = "yes" ]; then
#       REASON_LINE="동적 업데이트 필요 환경으로 설정되어 자동 조치를 수행하지 않아 조치가 완료되지 않았습니다."
#       append_detail "manual_guide=allow-update 또는 update-policy를 허용 IP/TSIG key로 제한 지정해야 합니다."
#     else
#       SEEDS=(/etc/named.conf /etc/bind/named.conf.options /etc/bind/named.conf)
#       mapfile -t CONF_FILES < <(collect_conf "${SEEDS[@]}")

#       if [ "${#CONF_FILES[@]}" -eq 0 ]; then
#         REASON_LINE="DNS 설정 파일(/etc/named.conf 등)을 찾지 못해 자동 조치를 완료할 수 없습니다."
#         append_detail "conf_files(current)=not_found"
#         append_detail "manual_guide=DNS 설정 파일 경로를 확인한 뒤 allow-update를 allow-update { none; }; 로 제한해야 합니다."
#       else
#         # 메인 conf 선정
#         main_conf=""
#         for f in "${SEEDS[@]}"; do [ -f "$f" ] && main_conf="$f" && break; done
#         [ -z "$main_conf" ] && main_conf="${CONF_FILES[0]}"
#         TARGET_FILE="$main_conf"
#         append_detail "main_conf(current)=$main_conf"

#         changed=0
#         manual_required=0
#         rewritten_files=""

#         # allow-update 존재하는 파일만 치환
#         for f in "${CONF_FILES[@]}"; do
#           [ -f "$f" ] || continue
#           if grep -qiE '^[[:space:]]*allow-update[[:space:]]*\{' "$f" 2>/dev/null; then
#             backup_once "$f" || append_err "$f 백업 실패"
#             if rewrite_allow_update_none "$f"; then
#               changed=1
#               rewritten_files="${rewritten_files:+$rewritten_files, }$f"
#             else
#               manual_required=1
#               append_detail "allow_update_rewrite(after)=failed file=$f"
#             fi
#           fi
#         done
#         [ -n "$rewritten_files" ] && append_detail "allow_update_rewrite(after)=$rewritten_files"

#         # update-policy는 자동으로 건드리면 위험/오탐 가능성이 커서: 존재 시 수동 필요로 처리(필수 보강)
#         up_found=0
#         if grep -RqiE '^[[:space:]]*update-policy[[:space:]]*\{' "${CONF_FILES[@]}" 2>/dev/null; then
#           up_found=1
#           manual_required=1
#           append_detail "update_policy_found(after)=yes"
#           append_detail "manual_guide=update-policy가 존재합니다. 동적 업데이트가 불필요하면 제거/비활성화(또는 none에 준하는 제한)하고, 필요 시 TSIG key 기반으로만 grant 하도록 제한해야 합니다."
#         else
#           append_detail "update_policy_found(after)=no"
#         fi

#         # 구문 검증/재시작(수동 필요면 생략)
#         if [ "$manual_required" -eq 0 ]; then
#           if command -v named-checkconf >/dev/null 2>&1; then
#             if named-checkconf "$main_conf" >/dev/null 2>&1; then
#               append_detail "named_checkconf(after)=ok"
#             else
#               manual_required=1
#               append_detail "named_checkconf(after)=failed"
#               append_detail "manual_guide=named-checkconf 오류 원인을 확인 후 설정을 수정하고 named 재시작이 필요합니다."
#             fi
#           else
#             append_detail "named_checkconf(after)=not_available"
#           fi
#         fi

#         if [ "$manual_required" -eq 0 ]; then
#           if restart_named; then append_detail "named_restart(after)=ok"
#           else
#             manual_required=1
#             append_detail "named_restart(after)=failed"
#             append_detail "manual_guide=설정 적용 후 named 서비스를 수동으로 재시작하고 로그로 실패 원인을 확인해야 합니다."
#           fi
#         fi

#         # 조치 후(현재) 설정 근거: 전체 conf에서 allow-update/update-policy 존재 개수 요약 + main_conf 일부 라인
#         summary="$(count_blocks "${CONF_FILES[@]}" 2>/dev/null | tail -n 1)"
#         [ -z "$summary" ] && summary="AU=unknown UP=unknown"
#         append_detail "blocks_summary(after)=$summary"

#         au_lines="$(grep -nEi '^[[:space:]]*allow-update[[:space:]]*\{' "$main_conf" 2>/dev/null | head -n 5)"
#         [ -z "$au_lines" ] && au_lines="allow-update_not_found_in_main_conf"
#         append_detail "allow_update_lines(after)=$au_lines"

#         up_lines="$(grep -nEi '^[[:space:]]*update-policy[[:space:]]*\{' "$main_conf" 2>/dev/null | head -n 5)"
#         [ -z "$up_lines" ] && up_lines="update-policy_not_found_in_main_conf"
#         append_detail "update_policy_lines(after)=$up_lines"

#         if [ "$manual_required" -eq 1 ]; then
#           IS_SUCCESS=0
#           REASON_LINE="조치를 수행했으나 DNS 동적 업데이트 제한 설정을 자동으로 완료하지 못해 조치가 완료되지 않았습니다."
#         else
#           IS_SUCCESS=1
#           if [ "$changed" -eq 1 ]; then
#             REASON_LINE="DNS 동적 업데이트가 차단되도록 allow-update { none; }; 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#           else
#             REASON_LINE="DNS 동적 업데이트 제한 설정이 적절히 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#           fi
#         fi
#       fi
#     fi
#   fi
# fi

# [ -n "$ACTION_ERR_LOG" ] && DETAIL_CONTENT="${DETAIL_CONTENT}\n$ACTION_ERR_LOG"
# [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# # raw_evidence 구성 (after/current만 포함)
# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE
# $DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# # JSON escape 처리 (역슬래시/따옴표/줄바꿈)
# RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
#   | sed 's/\\/\\\\/g; s/"/\\"/g' \
#   | sed ':a;N;$!ba;s/\n/\\n/g')

# echo ""
# cat << EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF