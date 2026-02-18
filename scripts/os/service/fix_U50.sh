#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-50
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS Zone Transfer 설정
# @Description : allow-transfer를 허용 대상으로 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수

# ID="U-50"
# CATEGORY="서비스 관리"
# TITLE="DNS Zone Transfer 설정"
# IMPORTANCE="상"
# TARGET_FILE="N/A"

# # allow-transfer { <ACL>; };
# # 기본값은 "none"으로 Zone Transfer를 차단합니다.
# # 예) ALLOW_TRANSFER_ACL="10.0.0.2; 10.0.0.3"
# ALLOW_TRANSFER_ACL="${ALLOW_TRANSFER_ACL:-none}"

# # (구버전) named.boot xfnets 값(미지정 시 allow-transfer ACL을 단순 변환해 사용, none이면 127.0.0.1)
# XFNETS_ACL="${XFNETS_ACL:-}"

# STATUS="PASS"
# EVIDENCE="취약점 조치가 완료되었습니다."
# GUIDE="named.conf(options 또는 zone)에 allow-transfer 제한 설정을 적용하고 named 서비스를 재시작했습니다."
# ACTION_RESULT="SUCCESS"
# ACTION_LOG=""

# append_log() {
#   local msg="$1"
#   [ -z "$msg" ] && return 0
#   if [ -n "$ACTION_LOG" ]; then
#     ACTION_LOG="$ACTION_LOG; $msg"
#   else
#     ACTION_LOG="$msg"
#   fi
# }

# json_escape() {
#   echo "$1" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
# }

# json_escape_multiline() {
#   echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g'
# }

# # -----------------------------
# # 서비스 실행/재시작 유틸
# # -----------------------------
# is_named_running() {
#   if command -v systemctl >/dev/null 2>&1; then
#     systemctl is-active --quiet named.service 2>/dev/null && return 0
#     systemctl is-active --quiet named-chroot.service 2>/dev/null && return 0
#   fi
#   pgrep -x named >/dev/null 2>&1 && return 0
#   return 1
# }

# restart_named_if_exists() {
#   if ! command -v systemctl >/dev/null 2>&1; then
#     return 0
#   fi

#   if systemctl list-unit-files 2>/dev/null | grep -qiE '^named\.service[[:space:]]'; then
#     systemctl restart named.service >/dev/null 2>&1 && return 0
#     return 1
#   fi

#   if systemctl list-unit-files 2>/dev/null | grep -qiE '^named-chroot\.service[[:space:]]'; then
#     systemctl restart named-chroot.service >/dev/null 2>&1 && return 0
#     return 1
#   fi

#   # 유닛이 없으면 재시작 생략(수동 환경)
#   return 0
# }

# # -----------------------------
# # 설정 파일 수집/백업/정규화
# # -----------------------------
# collect_named_conf_files() {
#   local -a seeds=("$@")
#   local -a queue=()
#   local -A seen=()
#   local -a out=()
#   local f inc inc_path dir

#   for f in "${seeds[@]}"; do
#     [ -f "$f" ] || continue
#     queue+=("$f")
#   done

#   while [ "${#queue[@]}" -gt 0 ]; do
#     f="${queue[0]}"
#     queue=("${queue[@]:1}")

#     [ -f "$f" ] || continue
#     if [ -n "${seen[$f]:-}" ]; then
#       continue
#     fi
#     seen["$f"]=1
#     out+=("$f")

#     dir="$(dirname "$f")"
#     while IFS= read -r inc; do
#       [ -z "$inc" ] && continue
#       if [[ "$inc" = /* ]]; then
#         inc_path="$inc"
#       else
#         inc_path="${dir}/${inc}"
#       fi
#       [ -f "$inc_path" ] && queue+=("$inc_path")
#     done < <(grep -hE '^[[:space:]]*include[[:space:]]+"' "$f" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')
#   done

#   printf '%s\n' "${out[@]}"
# }

# backup_once() {
#   local f="$1"
#   [ -f "$f" ] || return 0
#   if [ ! -f "${f}.bak_kisa_u50" ]; then
#     cp -a "$f" "${f}.bak_kisa_u50" 2>/dev/null || true
#     append_log "$f 백업 파일(${f}.bak_kisa_u50)을 생성했습니다."
#   fi
# }

# normalize_acl_inside() {
#   local acl="$1"
#   acl="$(echo "$acl" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
#   if [[ "$acl" != *";" ]]; then
#     acl="${acl};"
#   fi
#   echo "$acl"
# }

# normalize_xfnets_acl() {
#   local v="$1"
#   v="$(echo "$v" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
#   if [ -z "$v" ] || [ "$v" = "none" ]; then
#     echo "127.0.0.1"
#     return 0
#   fi
#   echo "$v" | sed -E 's/[;,]/ /g; s/[[:space:]]+/ /g; s/^[[:space:]]+//; s/[[:space:]]+$//'
# }

# # options 블록에 allow-transfer 적용(있으면 치환, 없으면 options 끝 직전에 삽입)
# apply_allow_transfer_in_options() {
#   local file="$1"
#   local inside="$2"
#   local stmt="    allow-transfer { ${inside} };"
#   local tmp rc
#   tmp="$(mktemp)"

#   awk -v STMT="$stmt" '
#     function count(s, ch,    t) { t=s; return gsub(ch,"",t); }
#     BEGIN { in_opt=0; depth=0; inserted=0; }
#     {
#       line=$0
#       if (in_opt==0 && line ~ /^[[:space:]]*options[[:space:]]*\{/) {
#         in_opt=1
#         depth = count(line, "{") - count(line, "}")
#         print line
#         next
#       }
#       if (in_opt==1) {
#         if (line ~ /^[[:space:]]*allow-transfer[[:space:]]*\{/) {
#           print STMT
#           inserted=1
#           depth += count(line, "{") - count(line, "}")
#           next
#         }
#         next_depth = depth + count(line, "{") - count(line, "}")
#         if (next_depth==0 && inserted==0 && line ~ /^[[:space:]]*\};[[:space:]]*(#.*|\/\/.*)?$/) {
#           print STMT
#           inserted=1
#           print line
#           in_opt=0
#           depth=0
#           next
#         }
#         print line
#         depth = next_depth
#         if (depth<=0) { in_opt=0; depth=0; }
#         next
#       }
#       print line
#     }
#     END { if (inserted==0) exit 3; }
#   ' "$file" >"$tmp"
#   rc=$?

#   if [ "$rc" -eq 0 ]; then
#     mv "$tmp" "$file"
#     append_log "$file의 options 블록에 allow-transfer 제한 설정을 적용했습니다."
#     return 0
#   fi
#   rm -f "$tmp"
#   return 1
# }

# # include 파일에 wide-open allow-transfer가 이미 존재하는 경우만 치환(추가 삽입 X)
# # (any/*/0.0.0.0/0/::/0 등)
# tighten_wide_open_allow_transfer_inplace() {
#   local file="$1"
#   local inside="$2"

#   if grep -qiE '^[[:space:]]*allow-transfer[[:space:]]*\{[^}]*\b(any|\*|0\.0\.0\.0([[:space:]]*;|/0)|\:\:/0)\b' "$file" 2>/dev/null; then
#     sed -i -E "s|^[[:space:]]*allow-transfer[[:space:]]*\{[^}]*\};|    allow-transfer { ${inside} };|gI" "$file" 2>/dev/null || true
#     append_log "$file의 allow-transfer 광범위 허용 설정을 제한 설정으로 변경했습니다."
#   fi
# }

# # -----------------------------
# # (구버전) named.boot xfnets 조치
# # -----------------------------
# apply_xfnets_in_named_boot() {
#   local file="$1"
#   local nets="$2"

#   if grep -qiE '^[[:space:]]*xfnets[[:space:]]+' "$file" 2>/dev/null; then
#     sed -i -E "s|^[[:space:]]*xfnets[[:space:]]+.*$|xfnets ${nets}|gI" "$file" 2>/dev/null || return 1
#     return 0
#   fi

#   echo "" >> "$file" 2>/dev/null || return 1
#   echo "xfnets ${nets}" >> "$file" 2>/dev/null || return 1
#   return 0
# }

# # -----------------------------
# # 조치 수행
# # -----------------------------
# if [ "${EUID:-$(id -u)}" -ne 0 ]; then
#   STATUS="FAIL"
#   ACTION_RESULT="FAIL"
#   EVIDENCE="root 권한으로 실행해야 조치가 가능합니다."
#   ACTION_LOG="권한 부족으로 조치를 수행하지 못했습니다."
# else
#   if ! is_named_running; then
#     STATUS="PASS"
#     ACTION_RESULT="SUCCESS"
#     EVIDENCE="DNS(named) 서비스가 비활성화되어 조치 대상이 없습니다."
#     ACTION_LOG="DNS(named) 서비스가 비활성화되어 조치 대상이 없습니다."
#     GUIDE="DNS 미사용 환경은 named 서비스 비활성 상태를 유지해야 합니다."
#   else
#     CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
#     BOOT_CANDIDATES=("/etc/named.boot" "/etc/bind/named.boot")

#     mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")

#     if [ "${#CONF_FILES[@]}" -eq 0 ]; then
#       STATUS="FAIL"
#       ACTION_RESULT="FAIL"
#       EVIDENCE="DNS 설정 파일(/etc/named.conf 등)을 찾지 못했습니다."
#       ACTION_LOG="자동 조치 가능한 DNS 설정 파일이 없습니다."
#     else
#       main_conf=""
#       for f in "${CONF_SEEDS[@]}"; do
#         [ -f "$f" ] && main_conf="$f" && break
#       done
#       [ -z "$main_conf" ] && main_conf="${CONF_FILES[0]}"
#       TARGET_FILE="$main_conf"

#       inside="$(normalize_acl_inside "$ALLOW_TRANSFER_ACL")"

#       # 1) 주 설정 파일 options 블록에 allow-transfer 반영(필수)
#       backup_once "$main_conf"
#       if grep -qE '^[[:space:]]*options[[:space:]]*\{' "$main_conf" 2>/dev/null; then
#         if ! apply_allow_transfer_in_options "$main_conf" "$inside"; then
#           STATUS="MANUAL"
#           ACTION_RESULT="MANUAL_REQUIRED"
#           EVIDENCE="일부 조치를 자동 적용하지 못했습니다."
#           append_log "options 블록에 allow-transfer를 자동 적용하지 못했습니다."
#           GUIDE="named.conf의 options 블록(또는 zone)에 allow-transfer { none; }; 또는 Secondary DNS만 허용하도록 수동 설정한 뒤 named 서비스를 재시작해야 합니다."
#         fi
#       else
#         STATUS="MANUAL"
#         ACTION_RESULT="MANUAL_REQUIRED"
#         EVIDENCE="일부 조치를 자동 적용하지 못했습니다."
#         append_log "$main_conf에서 options 블록을 찾지 못했습니다."
#         GUIDE="named.conf에 options(또는 zone/view) 블록을 확인한 뒤 allow-transfer 제한 설정을 수동 적용해야 합니다."
#       fi

#       # 2) include 파일에서 wide-open allow-transfer만 치환(추가 삽입 X) — 백업은 수정 전에
#       if [ "$ACTION_RESULT" = "SUCCESS" ]; then
#         for f in "${CONF_FILES[@]}"; do
#           [ -f "$f" ] || continue
#           if grep -qiE '^[[:space:]]*allow-transfer[[:space:]]*\{[^}]*\b(any|\*|0\.0\.0\.0([[:space:]]*;|/0)|\:\:/0)\b' "$f" 2>/dev/null; then
#             backup_once "$f"
#             tighten_wide_open_allow_transfer_inplace "$f" "$inside"
#           fi
#         done
#       fi

#       # 3) (구버전) named.boot xfnets 조치(파일이 존재하면 제한 값 적용)
#       if [ "$ACTION_RESULT" = "SUCCESS" ]; then
#         if [ -z "$XFNETS_ACL" ]; then
#           XFNETS_ACL="$(normalize_xfnets_acl "$ALLOW_TRANSFER_ACL")"
#         else
#           XFNETS_ACL="$(normalize_xfnets_acl "$XFNETS_ACL")"
#         fi

#         for bf in "${BOOT_CANDIDATES[@]}"; do
#           [ -f "$bf" ] || continue
#           backup_once "$bf"
#           if apply_xfnets_in_named_boot "$bf" "$XFNETS_ACL"; then
#             append_log "$bf에 xfnets 제한 설정을 적용했습니다."
#           else
#             STATUS="MANUAL"
#             ACTION_RESULT="MANUAL_REQUIRED"
#             EVIDENCE="일부 조치를 자동 적용하지 못했습니다."
#             append_log "named.boot(xfnets) 설정 적용에 실패했습니다."
#             GUIDE="named.boot 파일의 xfnets 값을 Secondary DNS/허용망으로 제한한 뒤 재시작이 필요합니다."
#           fi
#         done
#       fi

#       # 4) 구문 검증(named-checkconf) (가능 시) + 재시작
#       if [ "$ACTION_RESULT" = "SUCCESS" ]; then
#         if command -v named-checkconf >/dev/null 2>&1; then
#           if ! named-checkconf "$main_conf" >/dev/null 2>&1; then
#             STATUS="MANUAL"
#             ACTION_RESULT="MANUAL_REQUIRED"
#             EVIDENCE="설정 적용 후 구문 검증에 실패했습니다."
#             append_log "named-checkconf 구문 검증에 실패했습니다."
#             GUIDE="named-checkconf 오류 원인을 확인 후 설정을 수정하고 named 재시작이 필요합니다."
#           else
#             append_log "named-checkconf 구문 검증이 정상입니다."
#           fi
#         else
#           append_log "named-checkconf가 없어 구문 검증을 생략했습니다."
#         fi
#       fi

#       if [ "$ACTION_RESULT" = "SUCCESS" ]; then
#         if restart_named_if_exists; then
#           append_log "named 서비스를 재시작했습니다."
#         else
#           STATUS="MANUAL"
#           ACTION_RESULT="MANUAL_REQUIRED"
#           EVIDENCE="일부 조치를 자동 적용하지 못했습니다."
#           append_log "named 서비스 재시작에 실패했습니다."
#           GUIDE="allow-transfer 설정 적용 후 named 서비스를 수동으로 재시작하고, 로그로 실패 원인을 확인해야 합니다."
#         fi
#       fi
#     fi
#   fi
# fi

# # -----------------------------
# # 조치 후(현재) 상태 수집: raw_evidence에는 after/current만
# # -----------------------------
# SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# AFTER_ALLOW_LINES="not_collected"
# if [ -n "${TARGET_FILE:-}" ] && [ "$TARGET_FILE" != "N/A" ] && [ -f "$TARGET_FILE" ]; then
#   AFTER_ALLOW_LINES="$(grep -nEv '^[[:space:]]*#' "$TARGET_FILE" 2>/dev/null | grep -nE 'allow-transfer[[:space:]]*\{' | head -n 20)"
#   [ -z "$AFTER_ALLOW_LINES" ] && AFTER_ALLOW_LINES="allow-transfer_line_not_found"
# fi

# AFTER_XFNETS_LINES=""
# for bf in /etc/named.boot /etc/bind/named.boot; do
#   if [ -f "$bf" ]; then
#     xline="$(grep -iE '^[[:space:]]*xfnets[[:space:]]+' "$bf" 2>/dev/null | head -n 1)"
#     [ -z "$xline" ] && xline="xfnets_line_not_found"
#     if [ -n "$AFTER_XFNETS_LINES" ]; then
#       AFTER_XFNETS_LINES="${AFTER_XFNETS_LINES}\n${bf}: ${xline}"
#     else
#       AFTER_XFNETS_LINES="${bf}: ${xline}"
#     fi
#   fi
# done
# [ -z "$AFTER_XFNETS_LINES" ] && AFTER_XFNETS_LINES="named_boot_not_found"

# IMPACT_LEVEL="MEDIUM"
# ACTION_IMPACT="Zone Transfer를 차단하거나 허용 대상을 제한하면 Secondary DNS 구성에 따라 서비스 영향이 발생할 수 있으므로 사전에 허용 대상을 확인해야 합니다."

# # 출력용 문자열 escape(단일 라인 필드)
# EVIDENCE="$(json_escape "$EVIDENCE")"
# GUIDE="$(json_escape "$GUIDE")"
# ACTION_LOG="$(json_escape "$ACTION_LOG")"
# ACTION_IMPACT_ESC="$(json_escape "$ACTION_IMPACT")"

# CHECK_COMMAND="(command -v systemctl >/dev/null 2>&1 && (systemctl is-active named.service 2>/dev/null; systemctl is-active named-chroot.service 2>/dev/null) || true); (pgrep -x named >/dev/null 2>&1 && echo 'named_process_running' || echo 'named_process_not_running'); (command -v named-checkconf >/dev/null 2>&1 && echo 'named-checkconf_available' || echo 'named-checkconf_not_found'); ( [ -f \"$TARGET_FILE\" ] && grep -nE 'allow-transfer[[:space:]]*\\{' \"$TARGET_FILE\" 2>/dev/null | head -n 20 || echo 'allow-transfer_not_found_in_target' ); ( [ -f /etc/named.boot ] && grep -nE '^[[:space:]]*xfnets[[:space:]]+' /etc/named.boot 2>/dev/null | head -n 5 || true ); ( [ -f /etc/bind/named.boot ] && grep -nE '^[[:space:]]*xfnets[[:space:]]+' /etc/bind/named.boot 2>/dev/null | head -n 5 || true )"

# REASON_LINE="$ACTION_LOG"
# DETAIL_CONTENT="상태: ${STATUS}\n근거: ${EVIDENCE}\n가이드: ${GUIDE}\n영향도: ${IMPACT_LEVEL}\n영향: ${ACTION_IMPACT_ESC}\n대상 파일: ${TARGET_FILE}\nallow-transfer(after): ${AFTER_ALLOW_LINES}\nxfnets(after):\n${AFTER_XFNETS_LINES}"

# RAW_EVIDENCE_JSON=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE
# $DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# RAW_EVIDENCE_ESCAPED="$(json_escape_multiline "$RAW_EVIDENCE_JSON")"

# echo ""
# cat << EOF
# {
#   "item_code": "$ID",
#   "status": "$STATUS",
#   "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
#   "scan_date": "$SCAN_DATE"
# }
# EOF