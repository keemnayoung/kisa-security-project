# #!/bin/bash
# # ============================================================================
# # @Project: 시스템 보안 자동화 프로젝트
# # @Version: 2.0.0
# # @Author: 이가영
# # @Last Updated: 2026-02-15
# # ============================================================================
# # [보완 항목 상세]
# # @Check_ID : U-49
# # @Category : 서비스 관리
# # @Platform : Rocky Linux
# # @Importance : 상
# # @Title : DNS 보안 버전 패치
# # @Description : BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검
# # @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# # ============================================================================

# # 기본 변수
# ID="U-49"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# CHECK_COMMAND='
# (command -v systemctl >/dev/null 2>&1 && (
#   systemctl list-unit-files 2>/dev/null | grep -qiE "^(named|named-chroot)\.service[[:space:]]" && \
#     for u in named.service named-chroot.service; do
#       systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && \
#         echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)";
#     done
# )) || echo "systemctl_not_found";
# (command -v rpm >/dev/null 2>&1 && (
#   rpm -q bind 2>/dev/null || echo "bind_pkg_not_installed";
#   rpm -q bind-libs 2>/dev/null || echo "bind_libs_not_installed";
#   rpm -q bind9 2>/dev/null || echo "bind9_pkg_not_installed"
# )) || echo "rpm_not_found";
# (command -v named >/dev/null 2>&1 && (named -v 2>/dev/null || named -V 2>/dev/null | head -n 1)) || echo "named_cmd_not_found"
# '

# REASON_LINE=""
# DETAIL_CONTENT=""
# TARGET_FILE="/usr/sbin/named (bind 패키지), systemd(named.service)"

# ACTION_ERR_LOG=""

# append_detail() {
#   if [ -n "$DETAIL_CONTENT" ]; then
#     DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
#   else
#     DETAIL_CONTENT="$1"
#   fi
# }

# append_err() {
#   if [ -n "$ACTION_ERR_LOG" ]; then
#     ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
#   else
#     ACTION_ERR_LOG="$1"
#   fi
# }

# # (필수) root 권한 권장 안내(실패 원인 명확화용)
# if [ "$(id -u)" -ne 0 ]; then
#   ACTION_ERR_LOG="(주의) root 권한이 아니어도 상태 확인은 가능하지만, 패치/업데이트 작업은 root 권한이 필요합니다."
# fi

# RUNNING=0

# ########################################
# # 1) 현재 상태 수집(현재/조치 후만 기록)
# ########################################
# # 1) systemd 상태
# if command -v systemctl >/dev/null 2>&1; then
#   for u in named.service named-chroot.service; do
#     if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
#       en="$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)"
#       ac="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
#       append_detail "${u}(current) enabled=$en active=$ac"
#       echo "$ac" | grep -qiE "^active$" && RUNNING=1
#     fi
#   done
# else
#   append_detail "systemctl_not_found"
# fi

# # 2) 패키지 버전(rocky/rhel 계열 우선)
# if command -v rpm >/dev/null 2>&1; then
#   b="$(rpm -q bind 2>/dev/null || echo bind_not_installed)"
#   bl="$(rpm -q bind-libs 2>/dev/null || echo bind-libs_not_installed)"
#   b9="$(rpm -q bind9 2>/dev/null || echo bind9_not_installed)"
#   append_detail "packages(current) bind=$b"
#   append_detail "packages(current) bind-libs=$bl"
#   append_detail "packages(current) bind9=$b9"
# else
#   append_detail "rpm_not_found"
# fi

# # 3) named 바이너리 버전
# if command -v named >/dev/null 2>&1; then
#   nv="$(named -v 2>/dev/null | tr -d '\n')"
#   if [ -z "$nv" ]; then
#     nv="$(named -V 2>/dev/null | head -n 1 | tr -d '\n')"
#   fi
#   [ -z "$nv" ] && nv="named_version_unknown"
#   append_detail "named_version(current)=$nv"
# else
#   append_detail "named_cmd(current)=not_found"
# fi

# ########################################
# # 2) 판정(패치 자체는 수동)
# ########################################
# if [ "$RUNNING" -eq 1 ]; then
#   IS_SUCCESS=0
#   REASON_LINE="DNS 서비스(nametd)가 실행 중으로 확인되어 보안 패치(최신 버전 적용) 여부를 수동으로 점검하고 업데이트해야 조치가 완료됩니다."
#   # 수동 조치 가이드 문구를 detail에 포함(현재값만 + 안내)
#   append_detail "manual_guide=Rocky Linux 기준: dnf update bind bind-libs 후 named 재시작 및 보안 권고(CVE/벤더 공지) 기준 최신 버전 여부 확인 필요"
# else
#   IS_SUCCESS=1
#   REASON_LINE="DNS 서비스가 실행 중이 아니거나 미사용 상태로 확인되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
# fi

# if [ -n "$ACTION_ERR_LOG" ]; then
#   DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
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
