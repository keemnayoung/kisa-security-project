#!/bin/bash
# fix_U-01: root 계정 원격 접속 제한 조치

ITEM_CODE="U-01"
TARGET_FILE="/etc/ssh/sshd_config"
CONF_DIR="/etc/ssh/sshd_config.d"

IS_SUCCESS=false
DESC=""

# 조치 전 상태 기록
BEFORE=$(sshd -T 2>/dev/null | grep -i "permitrootlogin" | awk '{print $2}')

if [ -f "$TARGET_FILE" ]; then
    # 1. 백업
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"

    # 2. 설정 변경
    sed -i '/PermitRootLogin/d' "$TARGET_FILE"
    echo "PermitRootLogin no" >> "$TARGET_FILE"

    # 3. .d 폴더 내 우선순위 설정 제거
    if [ -d "$CONF_DIR" ]; then
        rm -f "$CONF_DIR/01-permitrootlogin.conf"
        find "$CONF_DIR" -name "*.conf" -exec sed -i '/PermitRootLogin/d' {} + 2>/dev/null
    fi

    # 4. 서비스 재시작
    systemctl daemon-reload >/dev/null 2>&1
    if systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1; then

        AFTER=$(sshd -T 2>/dev/null | grep -i "permitrootlogin" | awk '{print $2}')

        if [[ "$AFTER" == "no" ]]; then
            IS_SUCCESS=true
            DESC="PermitRootLogin을 no로 변경 완료. root 원격 접속이 차단되었습니다."
        else
            IS_SUCCESS=false
            DESC="설정 변경 후에도 PermitRootLogin이 ${AFTER} 상태입니다. 수동 확인이 필요합니다."
        fi
    else
        # 서비스 재시작 실패 → 백업 복원
        mv "$BACKUP_FILE" "$TARGET_FILE"
        systemctl restart sshd >/dev/null 2>&1
        AFTER="${BEFORE}"
        IS_SUCCESS=false
        DESC="서비스 재시작 실패로 기존 설정으로 원복하였습니다."
    fi
else
    BEFORE="null"
    AFTER="null"
    IS_SUCCESS=false
    DESC="조치 대상 파일($TARGET_FILE)이 존재하지 않습니다."
fi

cat << EOF
{
    "item_code": "$ITEM_CODE",
    "is_success": $IS_SUCCESS,
    "before": {
        "permit_root_login": "${BEFORE:-null}"
    },
    "after": {
        "permit_root_login": "${AFTER:-null}"
    },
    "description": "$DESC",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF