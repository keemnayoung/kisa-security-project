#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : SHA-256 이상 기반 인증 암호 알고리즘 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-08"
CATEGORY="계정 관리"
TITLE="안전한 암호화 알고리즘 사용"
IMPORTANCE="상"
TARGET_FILE="mysql.user.plugin"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 사용자 계정의 인증 플러그인 확인
QUERY="
SELECT user, host, plugin
FROM mysql.user
;
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="계정의 암호화 알고리즘 정보를 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 암호화 알고리즘 사용 여부를 확인할 수 없습니다."
else
    # SHA-256 미만 알고리즘 사용 계정 확인
    WEAK_USERS=$(echo "$RESULT" | awk '$3!="caching_sha2_password"{print $1"@"$2"("$3")"}')

    if [[ -z "$WEAK_USERS" ]]; then
        STATUS="PASS"
        EVIDENCE="모든 DB 계정이 SHA-256 기반의 안전한 암호화 알고리즘을 사용하고 있어, 비밀번호 탈취 및 무차별 대입 공격 위험이 낮습니다."
    else
        COUNT=$(echo "$WEAK_USERS" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$WEAK_USERS" | head -n 1)
        STATUS="FAIL"
        EVIDENCE="SHA-256 미만의 암호화 알고리즘을 사용하는 계정(${COUNT}개)이 존재하여, 비밀번호 유출 및 계정 탈취 위험이 있습니다. (예: ${SAMPLE})"
    fi
fi

# 파일 해시
if [ -f "$TARGET_FILE" ]; then
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    [[ -z "$FILE_HASH" ]] && FILE_HASH="HASH_ERROR"
else
    FILE_HASH="NOT_FOUND"
fi

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없습니다. 계정별 암호화 알고리즘 및 비밀번호 설정을 확인하고 필요한 경우 업데이트하더라도 기존 서비스나 사용자 접근에는 지장이 없으며, MySQL 5.7에서는 기본적으로 mysql_native_password가 사용되어 추가 설정이 필요하지 않습니다."

cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "계정의 인증 플러그인을 SHA-256 기반(caching_sha2_password)으로 변경하십시오.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
