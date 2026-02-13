#!/bin/bash
# ============================================================
# run.sh - KISA 보안 취약점 점검 시스템 통합 실행
#
#   ./run.sh scan       → 점검 + 파싱 + 정리
#   ./run.sh fix        → 조치 + 파싱 + 정리
#   ./run.sh score      → 보안 점수 계산
#   ./run.sh dashboard  → 대시보드 실행
#   ./run.sh all        → 점검 + 파싱 + 대시보드
#   ./run.sh mock       → 가짜 데이터 생성 + DB 적용
# ============================================================

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"

activate_venv() {
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    else
        echo "[ERROR] 가상환경이 없습니다."
        echo "  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
}

run_scan() {
    echo "=============================================="
    echo "  [1/3] OS 취약점 점검 실행"
    echo "=============================================="
    cd "$PROJECT_DIR/ansible"
    ansible-playbook -i inventories/hosts.ini playbooks/scan_os.yml

    echo ""
    echo "=============================================="
    echo "  [2/3] 점검 결과 DB 저장"
    echo "=============================================="
    activate_venv
    cd "$PROJECT_DIR/backend"
    python3 run_pipeline.py scan

    echo ""
    echo "=============================================="
    echo "  [3/3] 임시 파일 정리"
    echo "=============================================="
    #rm -rf /tmp/audit/check/*
    echo "[OK] /tmp/audit/check/ 정리 완료"

    echo ""
    echo "✅ 점검 완료! 대시보드: ./run.sh dashboard"
}

run_fix() {
    echo "=============================================="
    echo "  [1/3] OS 취약점 조치 실행"
    echo "=============================================="
    cd "$PROJECT_DIR/ansible"
    ansible-playbook -i inventories/hosts.ini playbooks/fix_os.yml

    echo ""
    echo "=============================================="
    echo "  [2/3] 조치 결과 DB 저장"
    echo "=============================================="
    activate_venv
    cd "$PROJECT_DIR/backend"
    python3 run_pipeline.py fix

    echo ""
    echo "=============================================="
    echo "  [3/3] 임시 파일 정리"
    echo "=============================================="
    rm -rf /tmp/audit/fix/*
    echo "[OK] /tmp/audit/fix/ 정리 완료"

    echo ""
    echo "✅ 조치 완료! 대시보드: ./run.sh dashboard"
}

run_score() {
    activate_venv
    cd "$PROJECT_DIR/backend"
    python3 run_pipeline.py score $1
}

run_dashboard() {
    echo "=============================================="
    echo "  🔒 SECURITYCORE 대시보드 실행"
    echo "=============================================="
    activate_venv
    cd "$PROJECT_DIR/dashboard"
    streamlit run app.py
}

run_mock() {
    echo "=============================================="
    echo "  🏭 가짜 서버 데이터 생성"
    echo "=============================================="
    activate_venv
    cd "$PROJECT_DIR/simulation"
    python3 mock_generator.py --apply
    echo ""
    echo "✅ 가짜 데이터 적용 완료! 대시보드: ./run.sh dashboard"
}

run_all() {
    run_scan
    echo ""
    run_dashboard
}

show_help() {
    echo "🔒 SECURITYCORE - KISA 보안 취약점 점검 시스템"
    echo ""
    echo "사용법: ./run.sh [명령어]"
    echo ""
    echo "  scan         점검 + DB 저장 + 정리"
    echo "  fix          조치 + DB 저장 + 정리"
    echo "  score [서버] 보안 점수 계산"
    echo "  dashboard    대시보드 실행"
    echo "  all          점검 + DB 저장 + 대시보드"
    echo "  mock         가짜 데이터 생성 + DB 적용"
    echo ""
}

case "${1}" in
    scan)      run_scan ;;
    fix)       run_fix ;;
    score)     run_score "$2" ;;
    dashboard) run_dashboard ;;
    all)       run_all ;;
    mock)      run_mock ;;
    *)         show_help ;;
esac