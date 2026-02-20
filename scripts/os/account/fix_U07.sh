# #!/bin/bash
# # ============================================================================
# # @Project: 시스템 보안 자동화 프로젝트
# # @Version: 1.0.0
# # @Author: 김나영
# # @Last Updated: 2026-02-09
# # ============================================================================
# # [조치 항목 상세]
# # @Check_ID : U-07
# # @Category : 계정관리
# # @Platform : Rocky Linux
# # @Importance : 하
# # @Title : 불필요한 계정 제거
# # @Description : 시스템 운영에 불필요한 기본 계정(lp, uucp, nuucp)을 삭제하여 보안 강화
# # @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# # ============================================================================

# ID="U-07"
# CATEGORY="계정관리"
# TITLE="불필요한 계정 제거"
# IMPORTANCE="하"
# TARGET_FILE="/etc/passwd"
# TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# ACTION_RESULT="FAIL"
# STATUS="FAIL"
# ACTION_LOG="N/A"

# # 삭제 대상 정의
# UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")

# if [ -f "$TARGET_FILE" ]; then
#     # 1. 안전한 복구를 위한 백업 생성
#     cp -p "$TARGET_FILE" "/etc/passwd_bak_$TIMESTAMP"
#     [ -f "/etc/shadow" ] && cp -p "/etc/shadow" "/etc/shadow_bak_$TIMESTAMP"

#     # 계정 삭제 수행
#     REMOVED_LIST=()
#     for acc in "${UNUSED_ACCOUNTS[@]}"; do
#         if id "$acc" >/dev/null 2>&1; then
#             # 홈 디렉토리는 남겨두고 계정만 삭제 (현업 안정성 기준)
#             if userdel "$acc" >/dev/null 2>&1; then
#                 REMOVED_LIST+=("$acc")
#             fi
#         fi
#     done

#     # [핵심 검증] 조치 후 실제 계정이 남아있는지 재검사
#     STILL_EXISTS=0
#     for acc in "${UNUSED_ACCOUNTS[@]}"; do
#         if grep -q "^${acc}:" "$TARGET_FILE"; then
#             STILL_EXISTS=$((STILL_EXISTS + 1))
#         fi
#     done

#     # 결과 판정
#     if [ "$STILL_EXISTS" -eq 0 ]; then
#         ACTION_RESULT="SUCCESS"
#         STATUS="PASS"
#         if [ ${#REMOVED_LIST[@]} -gt 0 ]; then
#             ACTION_LOG="시스템 보안을 위해 식별된 기본 계정(${REMOVED_LIST[*]})을 모두 삭제하고 정상적으로 조치를 완료하였습니다."
#         else
#             ACTION_LOG="삭제 대상인 기본 계정들이 시스템 내에 이미 존재하지 않아 추가적인 조치 없이 완료되었습니다."
#         fi
#     else
#         ACTION_RESULT="PARTIAL_SUCCESS"
#         STATUS="FAIL"
#         ACTION_LOG="계정 삭제 작업을 시도하였으나 일부 계정이 시스템에 남아 있어, 관리자의 수동 확인 및 조치가 필요합니다."
#     fi
# else
#     ACTION_RESULT="ERROR"
#     STATUS="FAIL"
#     ACTION_LOG="계정 정보 파일($TARGET_FILE)이 존재하지 않아 자동 삭제 조치를 수행할 수 없습니다."
# fi

# # 표준 JSON 출력
# echo ""
# cat << EOF
# {
#     "check_id": "$ID",
#     "category": "$CATEGORY",
#     "title": "$TITLE",
#     "importance": "$IMPORTANCE",
#     "status": "$STATUS",
#     "evidence": "$EVIDENCE",
#     "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
#     "action_result": "$ACTION_RESULT",
#     "action_log": "$ACTION_LOG",
#     "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
#     "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
# }
# EOF