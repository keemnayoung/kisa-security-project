#!/bin/bash
# U-34~U-63 check 실행 + 상태 요약 도구 (scripts/unix/3_service 기준)

set -u

CHECK_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="/root/.kisa_check_env_u34_u63"

if [ -f "$ENV_FILE" ]; then
    # U-45/U-49 FAIL 유도를 위한 기준버전 변수
    # shellcheck disable=SC1090
    source "$ENV_FILE"
fi

fail_count=0
manual_count=0
pass_count=0
unknown_count=0

echo "=== U-34~U-63 check 실행 시작 ==="
for i in $(seq 34 63); do
    f="$CHECK_DIR/check_U${i}.sh"
    if [ ! -x "$f" ]; then
        echo "[U-${i}] SKIP (파일 없음 또는 실행권한 없음)"
        unknown_count=$((unknown_count + 1))
        continue
    fi

    out="$("$f" 2>/dev/null)"
    status="$(echo "$out" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
    [ -z "$status" ] && status="UNKNOWN"

    case "$status" in
        FAIL)
            fail_count=$((fail_count + 1))
            ;;
        MANUAL)
            manual_count=$((manual_count + 1))
            ;;
        PASS)
            pass_count=$((pass_count + 1))
            ;;
        *)
            unknown_count=$((unknown_count + 1))
            ;;
    esac

    printf "[U-%02d] %s\n" "$i" "$status"
done

echo ""
echo "=== 요약 ==="
echo "FAIL   : $fail_count"
echo "MANUAL : $manual_count"
echo "PASS   : $pass_count"
echo "UNKNOWN: $unknown_count"

if [ "$manual_count" -gt 0 ]; then
    echo ""
    echo "[안내] MANUAL이 있으면 기준버전 변수 미설정 가능성이 큽니다."
    echo "       source /root/.kisa_check_env_u34_u63"
fi
