# #!/bin/bash
# # ============================================================================
# # @Project: 시스템 보안 자동화 프로젝트
# # @Version: 1.0.0
# # @Author: 김나영
# # @Last Updated: 2026-02-09
# # ============================================================================
# # [조치 항목 상세]
# # @Check_ID : U-06
# # @Category : 계정관리
# # @Platform : Rocky Linux
# # @Importance : 상
# # @Title : su 명령 사용 제한
# # @Description : 특정 그룹(wheel)만 su 명령을 사용할 수 있도록 PAM 설정 조치
# # @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# # ============================================================================

# ID="U-06"
# CATEGORY="계정관리"
# TITLE="su 명령 사용 제한"
# IMPORTANCE="상"
# TARGET_FILE="/etc/pam.d/su"
# TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# ACTION_RESULT="FAIL"
# STATUS="FAIL"
# ACTION_LOG="N/A"

# # 백업 생성
# if [ -f "$TARGET_FILE" ]; then
#     cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"
# else
#     ACTION_RESULT="ERROR"
#     ACTION_LOG="대상 파일($TARGET_FILE)이 존재하지 않습니다."
#     # 결과 출력 후 종료
#     exit 1
# fi

# # 실제 조치 프로세스
# {
#     # pam_wheel.so 설정 활성화 (주석 제거 및 use_uid 옵션 강제)
#     if grep -qi "pam_wheel.so" "$TARGET_FILE"; then
#         # 1) 주석 제거 (라인 시작의 # 제거)
#         sed -i '/pam_wheel.so/s/^#//' "$TARGET_FILE"
#         # 2) 필수 옵션인 use_uid가 없다면 추가
#         if ! grep -q "pam_wheel.so.*use_uid" "$TARGET_FILE"; then
#             sed -i 's/pam_wheel.so/pam_wheel.so use_uid/' "$TARGET_FILE"
#         fi
#     else
#         # 설정이 아예 없으면 최상단 부근(auth 설정 구역)에 추가
#         sed -i '1i auth            required        pam_wheel.so use_uid' "$TARGET_FILE"
#     fi

#     # [검증] 조치 후 상태 재확인
#     FINAL_CHECK=$(grep -v '^#' "$TARGET_FILE" | grep "pam_wheel.so" | grep "auth" | grep "required")
#     if [ -n "$FINAL_CHECK" ]; then
#         ACTION_RESULT="SUCCESS"
#         STATUS="PASS"
#         ACTION_LOG="일반 사용자의 무분별한 관리자 권한 승격을 방지하기 위해 wheel 그룹 전용 su 명령 제한 설정을 적용하고 조치를 완료하였습니다."
#     else
#         ACTION_LOG="보안 설정 수정을 시도하였으나 실제 반영 상태가 확인되지 않아 조치가 완료되지 않았습니다. 수동 점검이 필요합니다."
#     fi
# } || {
#     [ -f "${TARGET_FILE}_bak_$TIMESTAMP" ] && mv "${TARGET_FILE}_bak_$TIMESTAMP" "$TARGET_FILE"
#     ACTION_RESULT="FAIL_AND_ROLLBACK"
#     ACTION_LOG="설정 파일 수정 중 오류가 발생하여 시스템 인증 체계의 안정성을 위해 기존 설정으로 복구 조치를 완료하였습니다."
# }

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