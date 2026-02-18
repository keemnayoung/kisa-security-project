# #!/bin/bash
# # ============================================================================
# # @Project: 시스템 보안 자동화 프로젝트
# # @Version: 1.0.0
# # @Author: 김나영
# # @Last Updated: 2026-02-09
# # ============================================================================
# # [조치 항목 상세]
# # @Check_ID : U-10
# # @Category : 계정관리
# # @Platform : Rocky Linux
# # @Importance : 중
# # @Title : 동일한 UID 금지
# # @Description : /etc/passwd 내 중복된 UID를 사용하는 계정 확인 및 조치 가이드 제공
# # @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# # ============================================================================

# ID="U-10"
# CATEGORY="계정관리"
# TITLE="동일한 UID 금지"
# IMPORTANCE="중"
# TARGET_FILE="/etc/passwd"
# TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# ACTION_RESULT="FAIL"
# STATUS="FAIL"
# ACTION_LOG="N/A"

# if [ -f "$TARGET_FILE" ]; then
#     # 1. 백업 생성 (조치 전 필수)
#     cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"

#     # 2. 중복 상황 파악
#     DUPS=$(cut -d: -f3 "$TARGET_FILE" | sort | n | uniq -d)
    
#     if [ -z "$DUPS" ]; then
#         ACTION_RESULT="SUCCESS"
#         STATUS="PASS"
#         ACTION_LOG="시스템 내의 모든 계정이 고유한 식별 번호를 사용하고 있어, 추가 설정 변경 없이 조치를 완료하였습니다."
#     else
#         REPORT=""
#         for uid in $DUPS; do
#             ACCOUNTS=$(awk -F: -v u="$uid" '$3 == u {print $1}' "$TARGET_FILE" | xargs | sed 's/ /, /g')
#             REPORT+="UID ${uid}번(${ACCOUNTS}) "
#         done

#         # 3. 조치 가이드 제공 (영향도 고려하여 수동 조치 권고)
#         ACTION_RESULT="MANUAL_REQUIRED"
#         STATUS="FAIL"
#         ACTION_LOG="동일한 식별 번호를 공유하는 계정($REPORT)이 식별되었습니다. 파일 소유권 영향도를 고려하여 usermod -u 명령을 이용한 관리자의 수동 조치가 필요합니다."
#     fi
# else
#     ACTION_RESULT="ERROR"
#     STATUS="FAIL"
#     ACTION_LOG="사용자 정보 설정 파일($TARGET_FILE)이 존재하지 않아 자동 조치 프로세스를 완료할 수 없습니다."
# fi

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