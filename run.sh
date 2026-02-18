#!/bin/bash
# ============================================================
# run.sh - KISA 보안 취약점 점검 시스템 통합 실행
#
#   ./run.sh scan       → OS 점검 + 파싱 + 정리
#   ./run.sh scan-db    → DB 점검 + 파싱 + 정리
#   ./run.sh scan-all   → OS + DB 점검 + 파싱 + 정리
#   ./run.sh fix        → OS 조치 + 파싱 + 정리
#   ./run.sh fix-db     → DB 조치 + 파싱 + 정리
#   ./run.sh score      → 보안 점수 계산
#   ./run.sh dashboard  → 대시보드 실행
#   ./run.sh api        → 내부망 Job API(FastAPI) 실행
#   ./run.sh all        → 전체 점검 + 파싱 + 대시보드
#   ./run.sh mock       → 가짜 데이터 생성 + DB 적용
# ============================================================

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"

ensure_local_audit_dirs() {
    # Ansible fetch writes to /tmp/audit/{check,fix}. If these dirs are root-owned
    # (happens when cleanup used sudo or a previous run created them), fetch will fail
    # and pipeline will see "no JSON".
    local base="/tmp/audit"
    local dirs=("${base}" "${base}/check" "${base}/fix")

    for d in "${dirs[@]}"; do
        mkdir -p "$d" 2>/dev/null || true
    done

    # If not writable, try to fix with passwordless sudo (common in this project setup).
    for d in "${dirs[@]}"; do
        if [ -w "$d" ]; then
            continue
        fi

        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo -n mkdir -p "$d" 2>/dev/null || true
            sudo -n chown -R "$(id -u)":"$(id -g)" "$base" 2>/dev/null || true
            sudo -n chmod -R u+rwX,go+rX "$base" 2>/dev/null || true
        fi
    done
}

ansible_playbook() {
    local playbook_path="$1"
    shift || true

    local inventory_path="${ANSIBLE_INVENTORY:-inventories/hosts.ini}"
    local vault_pass_file="$PROJECT_DIR/ansible/.vault_pass"
    local args=(-i "${inventory_path}")

    # Ansible Vault 비밀번호 파일이 있으면 자동 사용
    if [[ -f "${vault_pass_file}" ]]; then
        args+=(--vault-password-file "${vault_pass_file}")
    fi

    if [[ -n "${ANSIBLE_LIMIT:-}" ]]; then
        args+=(--limit "${ANSIBLE_LIMIT}")
    fi
    if [[ -n "${ANSIBLE_EXTRA_VARS_FILE:-}" ]]; then
        args+=(-e "@${ANSIBLE_EXTRA_VARS_FILE}")
    fi

    ansible-playbook "${args[@]}" "${playbook_path}" "$@"
}

activate_venv() {
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    else
        echo "[ERROR] 가상환경이 없습니다."
        echo "  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
}

sync_inventory() {
    # Generate ansible/inventories/hosts.ini + group_vars from DB.
    # This must run inside the venv because DB connector deps are installed there.
    activate_venv
    (cd "$PROJECT_DIR/backend" && python3 sync_inventory.py)
}

cleanup_tmp_dir() {
    local target_dir="$1"

    if [ ! -d "$target_dir" ]; then
        echo "[OK] ${target_dir}/ 정리 완료 (디렉토리 없음)"
        return 0
    fi

    if rm -rf "${target_dir}"/* 2>/dev/null; then
        echo "[OK] ${target_dir}/ 정리 완료"
        return 0
    fi

    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        if sudo -n rm -rf "${target_dir}"/* 2>/dev/null; then
            echo "[OK] ${target_dir}/ 정리 완료 (sudo 사용)"
            return 0
        fi
    fi

    echo "[WARN] ${target_dir}/ 일부 파일 정리에 실패했습니다. 권한을 확인하세요."
    return 1
}

maybe_cleanup_tmp_dir() {
    local target_dir="$1"
    if [[ "${SKIP_CLEANUP:-0}" == "1" ]]; then
        echo "[OK] ${target_dir}/ 정리 건너뜀 (SKIP_CLEANUP=1)"
        return 0
    fi
    cleanup_tmp_dir "$target_dir"
}

_split_csv() {
    # Split comma-separated values into newline-separated tokens.
    # Usage: _split_csv "a,b,c"
    local s="${1:-}"
    if [[ -z "$s" ]]; then
        return 0
    fi
    echo "$s" | tr ',' '\n' | awk 'NF{print $0}'
}

_inventory_prefixes_for_limit() {
    # Build filename prefixes (<company>_<server_id>_) for hosts in ANSIBLE_LIMIT.
    # This is used to prune stale JSON results that would otherwise be parsed into DB.
    local inventory_path="${ANSIBLE_INVENTORY:-inventories/hosts.ini}"
    local limit="${ANSIBLE_LIMIT:-}"

    if [[ -z "$limit" ]]; then
        return 1
    fi
    if [[ ! -f "$inventory_path" ]]; then
        return 1
    fi

    local host
    while IFS= read -r host; do
        # If user passed a group name/wildcard, we can't safely map -> do nothing.
        if [[ "$host" =~ [*:?\\[] ]]; then
            return 1
        fi
        # Match an inventory host line: <host> ... company=... server_id=...
        local line
        line="$(awk -v h="$host" '$1==h{print; exit 0}' "$inventory_path")"
        if [[ -z "$line" ]]; then
            # Might be a group name; don't prune in that case.
            return 1
        fi

        local company server_id
        company="$(echo "$line" | sed -n 's/.*company=\\([^ ]*\\).*/\\1/p')"
        server_id="$(echo "$line" | sed -n 's/.*server_id=\\([^ ]*\\).*/\\1/p')"
        if [[ -z "$company" || -z "$server_id" ]]; then
            return 1
        fi

        echo "${company}_${server_id}_"
    done < <(_split_csv "$limit")

    return 0
}

_inventory_server_ids_for_limit() {
    # Build server_id list for hosts in ANSIBLE_LIMIT.
    local inventory_path="${ANSIBLE_INVENTORY:-inventories/hosts.ini}"
    local limit="${ANSIBLE_LIMIT:-}"

    if [[ -z "$limit" ]]; then
        return 1
    fi
    if [[ ! -f "$inventory_path" ]]; then
        return 1
    fi

    local host
    while IFS= read -r host; do
        if [[ "$host" =~ [*:?\\[] ]]; then
            return 1
        fi
        local line
        line="$(awk -v h="$host" '$1==h{print; exit 0}' "$inventory_path")"
        if [[ -z "$line" ]]; then
            return 1
        fi
        local server_id
        server_id="$(echo "$line" | sed -n 's/.*server_id=\\([^ ]*\\).*/\\1/p')"
        if [[ -z "$server_id" ]]; then
            return 1
        fi
        echo "$server_id"
    done < <(_split_csv "$limit")

    return 0
}

export_pipeline_server_filter() {
    # Tell the python parser which server_id(s) are allowed for this run.
    # Even if stale JSON exists, it won't be inserted into DB.
    local ids
    ids="$(_inventory_server_ids_for_limit 2>/dev/null | paste -sd, - 2>/dev/null || true)"
    if [[ -n "${ids:-}" ]]; then
        export PIPELINE_ALLOWED_SERVER_IDS="$ids"
    else
        unset PIPELINE_ALLOWED_SERVER_IDS || true
    fi
}

normalize_ansible_limit_server_ids() {
    # If ANSIBLE_LIMIT contains server_id(s) (e.g., naver-r9-002), translate them to
    # actual inventory hostnames after sync_inventory regenerates hosts.ini.
    local inventory_path="${ANSIBLE_INVENTORY:-$PROJECT_DIR/ansible/inventories/hosts.ini}"
    local limit="${ANSIBLE_LIMIT:-}"
    if [[ -z "$limit" ]]; then
        return 0
    fi
    if [[ ! -f "$inventory_path" ]]; then
        return 0
    fi

    local out=()
    local tok
    while IFS= read -r tok; do
        [[ -z "$tok" ]] && continue
        # Leave groups/wildcards untouched.
        if [[ "$tok" =~ [*:?\\[] ]]; then
            out+=("$tok")
            continue
        fi
        # If token already matches a host, keep it.
        if awk -v h="$tok" '$1==h{found=1} END{exit(found?0:1)}' "$inventory_path" 2>/dev/null; then
            out+=("$tok")
            continue
        fi
        # Heuristic: if token looks like a server_id, map it to a host with server_id=...
        if [[ "$tok" == *-* ]]; then
            local mapped
            mapped="$(awk -v sid="$tok" '
                $0 ~ /^[[:space:]]*($|#|\\[)/ {next}
                {for (i=2;i<=NF;i++) if ($i=="server_id="sid) {print $1; exit 0}}
            ' "$inventory_path" 2>/dev/null)"
            if [[ -n "$mapped" ]]; then
                out+=("$mapped")
                continue
            fi
        fi
        out+=("$tok")
    done < <(_split_csv "$limit")

    if [[ "${#out[@]}" -gt 0 ]]; then
        ANSIBLE_LIMIT="$(IFS=,; echo "${out[*]}")"
        export ANSIBLE_LIMIT
    fi
}

prune_scan_dir_for_limit() {
    # Keep only result JSONs that belong to hosts in this run (by company/server_id prefix).
    # Prevents "I scanned 002 but 001 also appears" due to stale files in the scan output dir.
    local dir="${1:-${SCAN_OUTPUT_DIR:-/tmp/audit/check}}"
    if [[ ! -d "$dir" ]]; then
        return 0
    fi

    local prefixes=()
    local p
    while IFS= read -r p; do
        [[ -n "$p" ]] && prefixes+=("$p")
    done < <(_inventory_prefixes_for_limit) || true

    if [[ "${#prefixes[@]}" -eq 0 ]]; then
        # No safe mapping; don't prune.
        return 0
    fi

    local f base keep
    shopt -s nullglob
    for f in "$dir"/*.json; do
        base="$(basename "$f")"
        keep=0
        for p in "${prefixes[@]}"; do
            if [[ "$base" == "${p}"* ]]; then
                keep=1
                break
            fi
        done
        if [[ "$keep" -eq 0 ]]; then
            rm -f "$f" 2>/dev/null || true
        fi
    done
    shopt -u nullglob
}

make_scan_output_dir() {
    # Create an isolated per-run output directory to avoid mixing stale JSONs.
    local base="/tmp/audit/check_runs"
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    local dir="${base}/${ts}"
    mkdir -p "$dir" 2>/dev/null || true
    echo "$dir"
}

run_scan() {
    echo "=============================================="
    echo "  [1/3] OS 취약점 점검 실행"
    echo "=============================================="
    ensure_local_audit_dirs
    export SCAN_OUTPUT_DIR
    SCAN_OUTPUT_DIR="$(make_scan_output_dir)"
    cd "$PROJECT_DIR/ansible"
    ansible_playbook playbooks/scan_os.yml -e "scan_output_dir=${SCAN_OUTPUT_DIR}"

    echo ""
    echo "=============================================="
    echo "  [2/3] 점검 결과 DB 저장"
    echo "=============================================="
    prune_scan_dir_for_limit "${SCAN_OUTPUT_DIR}"
    export_pipeline_server_filter
    activate_venv
    cd "$PROJECT_DIR/backend"
    python3 run_pipeline.py scan

    echo ""
    echo "=============================================="
    echo "  [3/3] 임시 파일 정리"
    echo "=============================================="
    # Keep last runner log outside /tmp/audit/check so we can debug missing items (e.g., U-64).
    if [ -f "${SCAN_OUTPUT_DIR}/os_check_runner.log" ]; then
        cp -f "${SCAN_OUTPUT_DIR}/os_check_runner.log" /tmp/audit/last_os_check_runner.log 2>/dev/null || true
    fi
    maybe_cleanup_tmp_dir "${SCAN_OUTPUT_DIR}"

    echo ""
    echo "✅ 점검 완료! 대시보드: ./run.sh dashboard"
}

load_fix_target_server() {
    # fix_service.py가 저장한 대상 서버 ID를 읽어 ANSIBLE_LIMIT 설정
    # 신규 포맷: {"server_ids": ["s1","s2"]}  /  기존 포맷: {"server_id": "s1"}
    local target_file="/tmp/audit/fix_target_server.json"
    if [[ -f "$target_file" ]]; then
        local limit
        limit="$(python3 -c "
import json
data = json.load(open('$target_file'))
if 'server_ids' in data and data['server_ids']:
    print(','.join(data['server_ids']))
elif 'server_id' in data:
    print(data['server_id'])
" 2>/dev/null || true)"
        if [[ -n "$limit" ]]; then
            export ANSIBLE_LIMIT="$limit"
            echo "[INFO] 조치 대상 서버: $limit"
        fi
    fi
}

run_fix() {
    echo "=============================================="
    echo "  [1/3] OS 취약점 조치 실행"
    echo "=============================================="
    ensure_local_audit_dirs
    # 이전 실행 결과 파일 정리 (중복 파싱 방지)
    rm -f /tmp/audit/fix/*.json /tmp/audit/fix/*.tar.gz 2>/dev/null || true
    sync_inventory
    load_fix_target_server
    normalize_ansible_limit_server_ids
    cd "$PROJECT_DIR/ansible"
    ansible_playbook playbooks/fix_os.yml

    echo ""
    echo "=============================================="
    echo "  [2/3] 조치 결과 DB 저장"
    echo "=============================================="
    export_pipeline_server_filter
    activate_venv
    cd "$PROJECT_DIR/backend"
    python3 run_pipeline.py fix

    echo ""
    echo "=============================================="
    echo "  [3/3] 임시 파일 정리"
    echo "=============================================="
    maybe_cleanup_tmp_dir /tmp/audit/fix
    # fix_target_server.json / fix_item_codes.json은 fix-db job이 공유하므로 삭제하지 않음
    # start_fix()가 매번 덮어쓰므로 stale 위험 없음

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
    DASHBOARD_HOST="${DASHBOARD_HOST:-127.0.0.1}"
    DASHBOARD_PORT="${DASHBOARD_PORT:-8501}"
    streamlit run Dashboard.py --server.address "$DASHBOARD_HOST" --server.port "$DASHBOARD_PORT"
}

run_api() {
    echo "=============================================="
    echo "  🔒 SECURITYCORE Job API(FastAPI) 실행"
    echo "=============================================="
    activate_venv
    cd "$PROJECT_DIR"
    # Default bind is localhost to avoid bind failures in restricted environments.
    # Override with API_HOST/API_PORT if you need LAN exposure.
    API_HOST="${API_HOST:-127.0.0.1}"
    API_PORT="${API_PORT:-8000}"
    uvicorn api.main:app --host "$API_HOST" --port "$API_PORT"
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

run_scan_db() {
    if [[ "${DEBUG_SCAN_DB:-0}" == "1" ]]; then
        echo "DEBUG: ANSIBLE_EXTRA_VARS_FILE=${ANSIBLE_EXTRA_VARS_FILE:-not_set}"
        if [[ -n "${ANSIBLE_EXTRA_VARS_FILE:-}" ]]; then
            echo "DEBUG: extra vars file content:"
            cat "${ANSIBLE_EXTRA_VARS_FILE}"
        fi
    fi
    
    sync_inventory
    normalize_ansible_limit_server_ids
    echo "=============================================="
    echo "  [1/3] DB 취약점 점검 실행"
    echo "=============================================="
    ensure_local_audit_dirs
    export SCAN_OUTPUT_DIR
    SCAN_OUTPUT_DIR="$(make_scan_output_dir)"
    cd "$PROJECT_DIR/ansible"
    ansible_playbook playbooks/scan_db.yml -e "scan_output_dir=${SCAN_OUTPUT_DIR}"

    echo ""
    echo "=============================================="
    echo "  [2/3] 점검 결과 DB 저장"
    echo "=============================================="
    prune_scan_dir_for_limit "${SCAN_OUTPUT_DIR}"
    export_pipeline_server_filter
    activate_venv
    cd "$PROJECT_DIR/backend"
    python3 run_pipeline.py scan

    echo ""
    echo "=============================================="
    echo "  [3/3] 임시 파일 정리"
    echo "=============================================="
    if [ -f "${SCAN_OUTPUT_DIR}/db_check_runner.log" ]; then
        cp -f "${SCAN_OUTPUT_DIR}/db_check_runner.log" /tmp/audit/last_db_check_runner.log 2>/dev/null || true
    fi
    maybe_cleanup_tmp_dir "${SCAN_OUTPUT_DIR}"

    echo ""
    echo "✅ DB 점검 완료! 대시보드: ./run.sh dashboard"
}

run_scan_all() {
    echo "=============================================="
    echo "  🔒 전체 점검 (OS + DB)"
    echo "=============================================="
    ensure_local_audit_dirs
    export SCAN_OUTPUT_DIR
    SCAN_OUTPUT_DIR="$(make_scan_output_dir)"
    cd "$PROJECT_DIR/ansible"
    ansible_playbook playbooks/scan_os.yml -e "scan_output_dir=${SCAN_OUTPUT_DIR}"
    ansible_playbook playbooks/scan_db.yml -e "scan_output_dir=${SCAN_OUTPUT_DIR}"

    echo ""
    echo "=============================================="
    echo "  점검 결과 DB 저장"
    echo "=============================================="
    prune_scan_dir_for_limit "${SCAN_OUTPUT_DIR}"
    export_pipeline_server_filter
    activate_venv
    cd "$PROJECT_DIR/backend"
    python3 run_pipeline.py scan

    maybe_cleanup_tmp_dir "${SCAN_OUTPUT_DIR}"
    echo ""
    echo "✅ 전체 점검 완료! 대시보드: ./run.sh dashboard"
}

run_fix_db() {
    echo "=============================================="
    echo "  [1/3] DB 취약점 조치 실행"
    echo "=============================================="
    ensure_local_audit_dirs
    # 이전 실행 결과 파일 정리 (중복 파싱 방지)
    rm -f /tmp/audit/fix/*.json /tmp/audit/fix/*.tar.gz 2>/dev/null || true
    sync_inventory
    load_fix_target_server
    normalize_ansible_limit_server_ids
    cd "$PROJECT_DIR/ansible"
    ansible_playbook playbooks/fix_db.yml

    echo ""
    echo "=============================================="
    echo "  [2/3] 조치 결과 DB 저장"
    echo "=============================================="
    export_pipeline_server_filter
    activate_venv
    cd "$PROJECT_DIR/backend"
    python3 run_pipeline.py fix

    echo ""
    echo "=============================================="
    echo "  [3/3] 임시 파일 정리"
    echo "=============================================="
    maybe_cleanup_tmp_dir /tmp/audit/fix
    # fix_target_server.json / fix_item_codes.json은 start_fix()가 매번 덮어쓰므로 삭제 불필요

    echo ""
    echo "✅ DB 조치 완료! 대시보드: ./run.sh dashboard"
}

run_all() {
    run_scan_all
    echo ""
    run_dashboard
}

show_help() {
    echo "🔒 SECURITYCORE - KISA 보안 취약점 점검 시스템"
    echo ""
    echo "사용법: ./run.sh [명령어]"
    echo ""
    echo "  scan         OS 점검 + DB 저장 + 정리"
    echo "  scan-db      DB 점검 + DB 저장 + 정리"
    echo "  scan-all     OS + DB 점검 + DB 저장 + 정리"
    echo "  fix          OS 조치 + DB 저장 + 정리"
    echo "  fix-db       DB 조치 + DB 저장 + 정리"
    echo "  score [서버] 보안 점수 계산"
    echo "  dashboard    대시보드 실행"
    echo "  api          Job API(FastAPI) 실행"
    echo "  all          전체 점검 + DB 저장 + 대시보드"
    echo "  mock         가짜 데이터 생성 + DB 적용"
    echo ""
}

case "${1}" in
    scan)      run_scan ;;
    scan-db)   run_scan_db ;;
    scan-all)  run_scan_all ;;
    fix)       run_fix ;;
    fix-db)    run_fix_db ;;
    score)     run_score "$2" ;;
    dashboard) run_dashboard ;;
    api)      run_api ;;
    all)       run_all ;;
    mock)      run_mock ;;
    *)         show_help ;;
esac
