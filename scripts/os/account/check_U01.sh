#!/bin/bash
# U-01: root 계정 원격 접속 제한

ITEM_CODE="U-01"
TARGET_FILE="/etc/ssh/sshd_config"

STATUS="취약"
DETAIL=""
PERMIT_ROOT=""

if [ -f "$TARGET_FILE" ]; then
    # sshd 실제 적용값 확인
    PERMIT_ROOT=$(sshd -T 2>/dev/null | grep -i "permitrootlogin" | awk '{print $2}')

    if [[ "$PERMIT_ROOT" == "no" ]]; then
        STATUS="양호"
        DETAIL="PermitRootLogin이 no로 설정되어 있습니다."
    else
        STATUS="취약"
        DETAIL="PermitRootLogin이 ${PERMIT_ROOT:-미설정} 상태입니다."
    fi
else
    STATUS="양호"
    DETAIL="SSH 설정 파일이 존재하지 않아 해당 위협이 없습니다."
fi

cat << EOF
{
    "item_code": "$ITEM_CODE",
    "status": "$STATUS",
    "evidence": {
        "detail": "$DETAIL",
        "permit_root_login": "${PERMIT_ROOT:-null}",
        "target_file": "$TARGET_FILE"
    },
    "scan_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF