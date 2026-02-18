# #!/bin/bash
# # ============================================================================
# # @Project: 시스템 보안 자동화 프로젝트
# # @Version: 2.0.0
# # @Author: 이가영
# # @Last Updated: 2026-02-15
# # ============================================================================
# # [보완 항목 상세]
# # @Check_ID : U-45
# # @Category : 서비스 관리
# # @Platform : Rocky Linux
# # @Importance : 상
# # @Title : 메일 서비스 버전 점검
# # @Description : 취약한 버전의 메일 서비스 이용 여부 점검
# # @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# # ============================================================================

# # [보완] U-45 메일 서비스 버전 점검

# # 기본 변수
# ID="U-45"
# ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# IS_SUCCESS=0

# TARGET_FILE="systemd(mail services), packages"

# CHECK_COMMAND='
# (command -v systemctl >/dev/null 2>&1 && (
#   for u in sendmail.service postfix.service exim.service exim4.service; do
#     systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)";
#   done
# )) || echo "systemctl_not_found";
# (command -v rpm >/dev/null 2>&1 && (
#   rpm -q sendmail 2>/dev/null || echo "sendmail_pkg_not_installed";
#   rpm -q postfix 2>/dev/null || echo "postfix_pkg_not_installed";
#   rpm -q exim 2>/dev/null || echo "exim_pkg_not_installed"
# )) || echo "rpm_not_found";
# (command -v sendmail >/dev/null 2>&1 && sendmail -d0.1 -bv 2>/dev/null | head -n 3) || echo "sendmail_cmd_not_found";
# (command -v postconf >/dev/null 2>&1 && postconf -d mail_version 2>/dev/null | head -n 1) || echo "postconf_not_found";
# (command -v exim >/dev/null 2>&1 && exim -bV 2>/dev/null | head -n 3) || echo "exim_cmd_not_found"
# '

# REASON_LINE=""
# DETAIL_CONTENT=""
# ACTION_ERR_LOG=""

# append_detail() {
#   if [ -n "$DETAIL_CONTENT" ]; then
#     DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
#   else
#     DETAIL_CONTENT="$1"
#   fi
# }

# # 메일 데몬이 “실행 중”이면 수동 패치 필요(MANUAL 성격)
# RUNNING_MAIL=0

# # ---------------------------
# # 현재 상태/버전 수집(현재/조치 후만 기록)
# # ---------------------------
# # 1) systemd 상태
# if command -v systemctl >/dev/null 2>&1; then
#   for u in sendmail.service postfix.service exim.service exim4.service; do
#     if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
#       en="$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)"
#       ac="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
#       append_detail "${u}(current) enabled=$en active=$ac"
#       echo "$ac" | grep -qiE "active" && RUNNING_MAIL=1
#     fi
#   done
# else
#   append_detail "systemctl_not_found"
# fi

# # 2) 패키지 버전(rpm)
# if command -v rpm >/dev/null 2>&1; then
#   sv="$(rpm -q sendmail 2>/dev/null || echo sendmail_not_installed)"
#   pv="$(rpm -q postfix 2>/dev/null || echo postfix_not_installed)"
#   ev="$(rpm -q exim 2>/dev/null || echo exim_not_installed)"
#   append_detail "packages(current) sendmail=$sv"
#   append_detail "packages(current) postfix=$pv"
#   append_detail "packages(current) exim=$ev"
# else
#   append_detail "rpm_not_found"
# fi

# # 3) 바이너리 버전(가능할 때만)
# if command -v sendmail >/dev/null 2>&1; then
#   smv="$(sendmail -d0.1 -bv 2>/dev/null | head -n 3 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
#   [ -z "$smv" ] && smv="sendmail_version_unknown"
#   append_detail "sendmail_version(current)=$smv"
# fi
# if command -v postconf >/dev/null 2>&1; then
#   pfv="$(postconf -d mail_version 2>/dev/null | head -n 1 | tr -d '\n')"
#   [ -z "$pfv" ] && pfv="postfix_version_unknown"
#   append_detail "postfix_version(current)=$pfv"
# fi
# if command -v exim >/dev/null 2>&1; then
#   exv="$(exim -bV 2>/dev/null | head -n 3 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
#   [ -z "$exv" ] && exv="exim_version_unknown"
#   append_detail "exim_version(current)=$exv"
# fi

# # ---------------------------
# # 최종 판정(이 항목은 수동 점검/패치가 핵심)
# # - 실행 중 메일 데몬이 있으면: 수동 패치 필요 -> is_success=0
# # - 실행 중 데몬이 없고(또는 미설치): 위험 낮음 -> is_success=1
# # ---------------------------
# if [ "$RUNNING_MAIL" -eq 1 ]; then
#   IS_SUCCESS=0
#   REASON_LINE="메일 서비스가 실행 중으로 확인되어 버전 및 보안 패치 적용 여부를 수동으로 점검해야 조치가 완료됩니다."
# else
#   IS_SUCCESS=1
#   REASON_LINE="메일 서비스가 실행 중이 아니거나 미설치 상태로 확인되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
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