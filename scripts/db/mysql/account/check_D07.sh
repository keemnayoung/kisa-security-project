#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 한은결
# @Last Updated: 2026-02-18
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : DBMS 서비스가 root 권한이 아닌 전용 계정으로 실행되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-07"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/my.cnf"

# 실제 실행 중인 mysqld/mariadbd 프로세스의 소유 계정과 바이너리 경로를 추출하는 함수
get_real_mysqld_proc_info() {
    local pid user comm exe
    while read -r pid user comm; do
        [[ -z "$pid" ]] && continue
        exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
        [[ "$exe" == */mysqld || "$exe" == */mariadbd ]] || continue
        printf "%s\t%s\t%s\n" "$pid" "$user" "$exe"
    done < <(ps -eo pid=,user=,comm= 2>/dev/null | awk '$3=="mysqld" || $3=="mariadbd"{print $1, $2, $3}')
}

# 프로세스 정보 수집 실행
PROC_INFO="$(get_real_mysqld_proc_info)"

REASON_LINE=""
DETAIL_CONTENT=""
# 자동 조치 시 발생할 수 있는 데이터 디렉터리 권한 문제 및 서비스 기동 실패 위험성 정의
GUIDE_LINE="이 항목에 대해서 서비스 실행 계정을 자동으로 변경할 경우 데이터 디렉터리 권한 충돌이나 소켓 파일 접근 거부로 인해 데이터베이스 서비스가 기동되지 않는 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 /etc/my.cnf 설정 파일의 [mysqld] 섹션에 user=mysql 설정을 추가하고, 관련 데이터 폴더의 소유권을 변경한 뒤 서비스를 재기동하여 조치해 주시기 바랍니다."

# 프로세스 존재 여부에 따른 점검 가능 여부 판단
if [[ -z "$PROC_INFO" ]]; then
    STATUS="FAIL"
    REASON_LINE="실행 중인 MySQL 서비스 프로세스가 확인되지 않습니다."
    DETAIL_CONTENT="현재 시스템에서 구동 중인 mysqld 또는 mariadbd 프로세스가 없습니다."
else
    # root 계정 소유의 프로세스 필터링
    ROOT_PROC=$(echo "$PROC_INFO" | awk -F'\t' '$2=="root"')

    # 구동 계정 상태에 따른 양호/취약 판정 분기
    if [[ -z "$ROOT_PROC" ]]; then
        STATUS="PASS"
        # 단일 또는 다수 계정으로 실행 중인 현재 사용자 정보 취합
        RUN_USERS=$(echo "$PROC_INFO" | awk -F'\t' '{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//')
        REASON_LINE="MySQL 서비스가 root 권한이 아닌 '${RUN_USERS}' 계정으로 실행되고 있어 이 항목에 대해 양호합니다."
        
        # 전체 프로세스 현황 상세 작성
        DETAIL_CONTENT="[현재 서비스 실행 계정 현황]\n"
        while IFS=$'\t' read -r pid user exe; do
            DETAIL_CONTENT="${DETAIL_CONTENT}- PID: ${pid} / USER: ${user} / BIN: ${exe}\n"
        done <<< "$PROC_INFO"
    else
        STATUS="FAIL"
        # root 권한으로 실행 중인 구체적인 프로세스 정보 추출
        ROOT_PIDS=$(echo "$ROOT_PROC" | awk -F'\t' '{print $1}' | tr '\n' ',' | sed 's/,$//')
        REASON_LINE="MySQL 서비스가 root 권한(PID: ${ROOT_PIDS})으로 실행되고 있어 이 항목에 대해 취약합니다."
        
        # 전체 프로세스 현황 상세 작성 (취약 시에도 전체 상태 표시)
        DETAIL_CONTENT="[현재 서비스 실행 계정 현황]\n"
        while IFS=$'\t' read -r pid user exe; do
            DETAIL_CONTENT="${DETAIL_CONTENT}- PID: ${pid} / USER: ${user} / BIN: ${exe}\n"
        done <<< "$PROC_INFO"
    fi
fi

# 점검 시 사용된 핵심 로직 설명
CHECK_COMMAND="ps -eo pid=,user=,comm= | awk '\$3==\"mysqld\" || \$3==\"mariadbd\"{print \$1, \$2, \$3}' + readlink -f /proc/<pid>/exe"
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 데이터의 개행 및 특수문자가 파이썬/DB에서 깨지지 않도록 이스케이프 처리
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# 최종 결과 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF