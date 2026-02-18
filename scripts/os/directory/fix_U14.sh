#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 권순형
# @Last Updated: 2026-02-13
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-14
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : PATH 환경변수 내 '.'을 마지막 위치로 이동
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# # 기본 변수
# ID="U-14"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND=""
# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE=""

# MODIFIED_FILES=()
# MODIFIED_COUNT=0

# # -----------------------------------------------------------------------------
# # 유틸: root PATH에서 '.' 위치 판정 (가이드 기준)
# #  - 취약: '.'이 맨 앞 또는 중간
# #  - 양호: '.'이 없음 또는 맨 끝만 존재
# # -----------------------------------------------------------------------------
# is_vulnerable_root_path() {
#   local p="$1"
#   local dot_found="N"
#   local dot_start="N"
#   local dot_mid="N"
#   local dot_end="N"

#   IFS=':' read -ra parts <<< "$p"
#   local n=${#parts[@]}
#   local i=0

#   for ((i=0; i<n; i++)); do
#     if [ "${parts[$i]}" = "." ]; then
#       dot_found="Y"
#       if [ "$i" -eq 0 ]; then
#         dot_start="Y"
#       elif [ "$i" -eq $((n-1)) ]; then
#         dot_end="Y"
#       else
#         dot_mid="Y"
#       fi
#     fi
#   done

#   # 취약 여부만 반환 (0=취약, 1=양호)
#   if [ "$dot_found" = "N" ]; then
#     return 1
#   fi
#   if [ "$dot_end" = "Y" ] && [ "$dot_start" = "N" ] && [ "$dot_mid" = "N" ]; then
#     return 1
#   fi
#   return 0
# }

# # -----------------------------------------------------------------------------
# # 1) root 로그인 쉘 확인 및 대상 파일 정의
# # -----------------------------------------------------------------------------
# ROOT_SHELL=$(getent passwd root | cut -d: -f7)
# SHELL_NAME=$(basename "$ROOT_SHELL")

# TARGET_FILES=()
# case "$SHELL_NAME" in
#   sh)   TARGET_FILES=(/etc/profile /root/.profile) ;;
#   csh)  TARGET_FILES=(/etc/csh.cshrc /etc/csh.login /root/.cshrc /root/.login) ;;
#   ksh)  TARGET_FILES=(/etc/profile /root/.profile /root/.kshrc) ;;
#   bash) TARGET_FILES=(/etc/profile /etc/bash.bashrc /root/.bash_profile /root/.bashrc) ;;
#   *)
#     CHECK_COMMAND="getent passwd root | cut -d: -f7"
#     TARGET_FILE="N/A"
#     IS_SUCCESS=0

#     REASON_LINE="root 로그인 쉘이 지원되지 않는 유형(${SHELL_NAME})이라 자동 조치를 수행할 수 없어 조치가 완료되지 않았습니다."
#     DETAIL_CONTENT=""

#     RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )
#     RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

#     echo ""
#     cat << EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF
#     exit 0
#     ;;
# esac

# # target_file 증적용
# TARGET_FILE="$(printf "%s, " "${TARGET_FILES[@]}")"
# TARGET_FILE="${TARGET_FILE%, }"

# # (증적용) 점검 커맨드 문자열
# CHECK_COMMAND="su - root -c \"echo \\$PATH\"
# for f in ${TARGET_FILES[*]}; do
#   [ -f \"\\\$f\" ] && grep -nE '^[[:space:]]*(export[[:space:]]+)?PATH=|^[[:space:]]*setenv[[:space:]]+PATH|^[[:space:]]*set[[:space:]]+path' \"\\\$f\" | grep -vE '^[[:space:]]*#'
# done"

# # -----------------------------------------------------------------------------
# # 2) 조치 전 root PATH (증거)
# # -----------------------------------------------------------------------------
# BEFORE_PATH=$(su - root -c "echo \$PATH" 2>/dev/null)
# BEFORE_VULN_MSG=""

# if is_vulnerable_root_path "$BEFORE_PATH"; then
#   BEFORE_VULN_MSG="(조치 전 상태: 취약)"
# else
#   BEFORE_VULN_MSG="(조치 전 상태: 양호)"
# fi

# # -----------------------------------------------------------------------------
# # 3) 대상 파일 순회하며 '.'을 PATH 마지막으로 이동
# #    - 맨 앞/중간에 '.'이 있는 경우만 조치
# #    - 이미 맨 끝만 '.'인 경우는 건드리지 않음
# # -----------------------------------------------------------------------------

# for TARGET_FILE_ITEM in "${TARGET_FILES[@]}"; do
#   [ ! -f "$TARGET_FILE_ITEM" ] && continue

#   # 파일 내 PATH 관련 라인(주석 제외) 존재 확인
#   PATH_LINES=$(grep -nE '^[[:space:]]*(export[[:space:]]+)?PATH=|^[[:space:]]*setenv[[:space:]]+PATH|^[[:space:]]*set[[:space:]]+path' "$TARGET_FILE_ITEM" 2>/dev/null \
#     | grep -vE '^[[:space:]]*#')

#   [ -z "$PATH_LINES" ] && continue

#   # "조치가 필요한지"를 파일 단위로 판정 (맨 앞/중간 '.' 존재)
#   # - PATH=... 형태: ':'로 분해해 '.'이 마지막만인지 체크
#   NEED_FIX=0
#   while IFS= read -r line; do
#     # 라인에서 RHS만 대충 뽑아서 '.' 위치를 판정 (정확 처리는 perl에서)
#     rhs=$(echo "$line" | sed -E 's/^[0-9]+:([[:space:]]*export[[:space:]]+)?PATH=//; s/^[0-9]+:[[:space:]]*setenv[[:space:]]+PATH[[:space:]]+//; s/^[0-9]+:[[:space:]]*set[[:space:]]+path[[:space:]]*=\s*\(?(.*)\)?$/\1/' 2>/dev/null)
#     rhs=$(echo "$rhs" | tr -d '"' | tr -d "'" )

#     # set path=(a b . c) 는 ':'가 아니라 공백이므로 여기선 보수적으로 '.' 포함이면 조치 대상으로 간주
#     if echo "$line" | grep -qE '^[0-9]+:[[:space:]]*set[[:space:]]+path'; then
#       if echo "$line" | grep -qE '(^|[[:space:]])\.[[:space:]]'; then
#         NEED_FIX=1
#         break
#       fi
#     else
#       # PATH=: 형태는 ':' 기준
#       IFS=':' read -ra parts <<< "$rhs"
#       n=${#parts[@]}
#       dot_found="N"; dot_start="N"; dot_mid="N"; dot_end="N"
#       for ((i=0;i<n;i++)); do
#         if [ "${parts[$i]}" = "." ]; then
#           dot_found="Y"
#           if [ "$i" -eq 0 ]; then dot_start="Y"
#           elif [ "$i" -eq $((n-1)) ]; then dot_end="Y"
#           else dot_mid="Y"
#           fi
#         fi
#       done

#       if [ "$dot_found" = "Y" ] && ! ( [ "$dot_end" = "Y" ] && [ "$dot_start" = "N" ] && [ "$dot_mid" = "N" ] ); then
#         NEED_FIX=1
#         break
#       fi
#     fi
#   done <<< "$PATH_LINES"

#   [ "$NEED_FIX" -eq 0 ] && continue

#   # 백업
#   BACKUP_FILE="${TARGET_FILE_ITEM}_bak_$(date +%Y%m%d_%H%M%S)"
#   cp -p "$TARGET_FILE_ITEM" "$BACKUP_FILE" 2>/dev/null

#   # perl로 안전하게 재배치 (PATH= / export PATH= / setenv PATH / set path 지원)
#   perl -i -pe '
#     sub move_dot_to_end_colonpath {
#       my ($rhs) = @_;
#       $rhs =~ s/^\s+|\s+$//g;

#       # 따옴표 처리
#       my $q = "";
#       if ($rhs =~ /^"(.*)"\s*$/) { $rhs=$1; $q="\""; }
#       elsif ($rhs =~ /^\x27(.*)\x27\s*$/) { $rhs=$1; $q="\x27"; }

#       my @parts = split(/:/, $rhs);
#       my @clean = ();
#       my $dot_cnt = 0;

#       for my $p (@parts) {
#         next if $p eq "";          # 빈 토큰 제거
#         if ($p eq ".") { $dot_cnt++; next; }
#         push @clean, $p;
#       }

#       # dot이 없으면 원본 유지
#       return (undef) if $dot_cnt == 0;

#       # dot이 끝만 있는 경우는 수정하지 않음 (가이드: 양호)
#       if (@clean >= 1 && $parts[-1] eq "." && $dot_cnt == 1) {
#         # 원래 rhs 마지막이 '.'이고 그 외 '.'이 없다면 그대로
#         return (undef);
#       }

#       push @clean, ".";            # 항상 맨 끝에 '.' 1회만
#       my $new = join(":", @clean);
#       return ($q . $new . $q);
#     }

#     sub move_dot_to_end_cshpath {
#       my ($rhs) = @_;
#       $rhs =~ s/^\s+|\s+$//g;

#       # setenv PATH .:/usr/bin:/bin 형태 지원 (콜론 path)
#       my $new = move_dot_to_end_colonpath($rhs);
#       return $new;
#     }

#     # 1) bash/sh/ksh: PATH=... 또는 export PATH=...
#     if ($_ !~ /^\s*#/ && $_ =~ /^(\s*)(export\s+)?PATH=(.*)$/) {
#       my ($indent,$exp,$rhs) = ($1,$2,$3);
#       my $newrhs = move_dot_to_end_colonpath($rhs);
#       if (defined $newrhs) {
#         $_ = $indent . ($exp ? "export " : "") . "PATH=" . $newrhs . "\n";
#       }
#     }

#     # 2) csh: setenv PATH ...
#     elsif ($_ !~ /^\s*#/ && $_ =~ /^(\s*)setenv\s+PATH\s+(.*)$/) {
#       my ($indent,$rhs) = ($1,$2);
#       my $newrhs = move_dot_to_end_cshpath($rhs);
#       if (defined $newrhs) {
#         $_ = $indent . "setenv PATH " . $newrhs . "\n";
#       }
#     }

#     # 3) csh: set path=( ... )  (공백 리스트)
#     elsif ($_ !~ /^\s*#/ && $_ =~ /^(\s*)set\s+path\s*=\s*\(?\s*(.*?)\s*\)?\s*$/) {
#       my ($indent,$rhs) = ($1,$2);
#       my @parts = split(/\s+/, $rhs);
#       my @clean = ();
#       my $dot_cnt = 0;

#       for my $p (@parts) {
#         next if $p eq "";
#         if ($p eq ".") { $dot_cnt++; next; }
#         push @clean, $p;
#       }

#       # dot이 없으면 유지
#       if ($dot_cnt == 0) {
#         # no-op
#       } else {
#         # dot이 끝만 있는 경우는 유지(양호) — 단, dot이 1개이고 마지막이 dot일 때
#         if (!(@parts && $parts[-1] eq "." && $dot_cnt == 1)) {
#           push @clean, ".";
#           my $new = join(" ", @clean);
#           $_ = $indent . "set path=( " . $new . " )\n";
#         }
#       }
#     }
#   ' "$TARGET_FILE_ITEM" 2>/dev/null

#   MODIFIED_FILES+=("$TARGET_FILE_ITEM")
#   MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
# done

# # -----------------------------------------------------------------------------
# # 4) 조치 후 root PATH 재확인 (가장 신뢰 가능한 최종 검증)
# # -----------------------------------------------------------------------------
# AFTER_PATH=$(su - root -c "echo \$PATH" 2>/dev/null)

# # -----------------------------------------------------------------------------
# # 5) 최종 판단 (가이드 기준)
# # -----------------------------------------------------------------------------
# if is_vulnerable_root_path "$AFTER_PATH"; then
#   IS_SUCCESS=0
#   REASON_LINE="PATH 내 현재 디렉터리('.')가 맨 앞 또는 중간에 존재하여 조치가 완료되지 않았습니다. (수동 확인 필요)"
# else
#   IS_SUCCESS=1
#   if [ "$MODIFIED_COUNT" -gt 0 ]; then
#     REASON_LINE="PATH 내 현재 디렉터리('.')가 마지막 위치로 재배치되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   else
#     REASON_LINE="PATH 내 현재 디렉터리('.')가 맨 앞 또는 중간에 존재하는 취약한 설정이 없어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
#   fi
# fi

# MODIFIED_LIST=$(printf "%s\n" "${MODIFIED_FILES[@]}")
# DETAIL_CONTENT="root_shell=$SHELL_NAME
# before_path=$BEFORE_PATH $BEFORE_VULN_MSG
# after_path=$AFTER_PATH
# modified_count=$MODIFIED_COUNT
# modified_files:
# ${MODIFIED_LIST:-N/A}"

# RAW_EVIDENCE=$(cat <<EOF
# {
#   "command": "$CHECK_COMMAND",
#   "detail": "$REASON_LINE\n$DETAIL_CONTENT",
#   "target_file": "$TARGET_FILE"
# }
# EOF
# )

# RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# # -----------------------------------------------------------------------------
# # 6) JSON 출력
# # -----------------------------------------------------------------------------
# echo ""
# cat << EOF
# {
#     "item_code": "$ID",
#     "action_date": "$ACTION_DATE",
#     "is_success": $IS_SUCCESS,
#     "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
# }
# EOF