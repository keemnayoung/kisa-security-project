"""
parse_scan_result.py
점검 결과 JSON 파일을 읽어서 scan_history 테이블에 INSERT
"""

import os
import json
import glob
import sys
import re
from datetime import datetime, timedelta

# backend/ 디렉토리를 path에 추가
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from db.connector import DBConnector
from config import SCAN_OUTPUT_DIR

# DB 스크립트: PASS/FAIL, OS 스크립트: 양호/취약 → 통일
STATUS_MAP = {
    'PASS': '양호',
    'FAIL': '취약',
    '양호': '양호',
    '취약': '취약',
}


def parse_filename(filename):
    """
    파일명에서 company, server_id, item_code 추출

    OS:  NAVER_rocky9_1_check_U01.json → ('NAVER', 'rocky9_1', 'U-01')
    DB:  NAVER_rocky9_1_check_D01.json → ('NAVER', 'rocky9_1', 'D-01')
    """
    name = os.path.basename(filename).replace('.json', '')
    parts = name.split('_')

    raw_code = parts[-1]  # U01 or D01
    item_code = raw_code[0] + '-' + raw_code[1:]  # U-01 or D-01

    check_idx = parts.index('check')
    company = parts[0]
    server_id = '_'.join(parts[1:check_idx])  # rocky9_1

    return company, server_id, item_code


def normalize_status(raw_status):
    """PASS/FAIL → 양호/취약 변환"""
    return STATUS_MAP.get(raw_status, raw_status)


def _parse_dt_best_effort(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    # Common formats produced by our shell scripts and some tools.
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


def normalize_scan_date(raw_scan_date: str, *, now: datetime, max_skew: timedelta = timedelta(minutes=15)) -> str:
    """
    Store scan_date as controller time for every row created by this pipeline run.

    이유:
    - OS/DB 점검 스크립트는 원격 호스트에서 date를 찍어 JSON에 넣는다.
    - 항목별로 시간이 달라지면 '점검 1회'가 여러 분으로 쪼개져 타임라인이 깔끔하게 "착착" 쌓이지 않는다.
    - 원격 시간 오차/타임존 이슈도 흔하다.

    raw_scan_date는 참고용이며, 기본 정책은 항상 controller now.
    (향후 필요하면 환경변수로 raw 유지 옵션을 추가할 수 있음)
    """
    # Use minute precision to make "one run == one bucket" deterministic in the UI.
    dt = now.replace(second=0, microsecond=0)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def extract_raw_evidence(data, fallback_path):
    """
    점검 스크립트별 출력 차이를 흡수한다.
    1) raw_evidence (string/dict)
    2) evidence (dict)
    """
    raw = data.get('raw_evidence')
    if isinstance(raw, dict):
        return json.dumps(raw, ensure_ascii=False)
    if isinstance(raw, str) and raw.strip():
        return raw

    evidence = data.get('evidence')
    if isinstance(evidence, dict):
        return json.dumps(evidence, ensure_ascii=False)

    return fallback_path


def _lenient_extract(text: str, fallback_item_code: str, fallback_path: str) -> dict:
    """
    JSON 파싱이 깨진(Invalid \\escape 등) 파일을 최대한 복구한다.
    - item_code/status/scan_date를 정규식으로 추출
    - raw_evidence는 원문 일부를 저장(문법 깨짐 원인 포함)
    """
    def _m(pat: str) -> str | None:
        m = re.search(pat, text, re.DOTALL)
        return m.group(1).strip() if m else None

    item_code = _m(r'"item_code"\s*:\s*"([^"]+)"') or fallback_item_code
    status = _m(r'"status"\s*:\s*"([^"]+)"') or "FAIL"
    scan_date = _m(r'"scan_date"\s*:\s*"([^"]+)"') or ""

    # raw_evidence는 파싱이 깨져있을 확률이 높으므로 원문을 그대로 저장
    # (DB에 들어갈 때는 LONGTEXT이므로 길이 제한만 가볍게 걸자)
    raw_evidence = _m(r'"raw_evidence"\s*:\s*"(.+?)"\s*,\s*"scan_date"')  # best-effort
    if raw_evidence is None:
        raw_evidence = text

    raw_evidence = raw_evidence[:20000]
    return {
        "item_code": item_code,
        "status": status,
        "scan_date": scan_date,
        "raw_evidence": raw_evidence or fallback_path,
    }


def parse_and_insert():
    db = DBConnector()
    if not db.connect():
        print("[ERROR] DB 연결 실패")
        return False

    print(f"[INFO] SCAN_OUTPUT_DIR={SCAN_OUTPUT_DIR}")

    allowed_ids_env = (os.getenv("PIPELINE_ALLOWED_SERVER_IDS") or "").strip()
    allowed_server_ids = {s.strip() for s in allowed_ids_env.split(",") if s.strip()} if allowed_ids_env else set()
    if allowed_server_ids:
        print(f"[INFO] PIPELINE_ALLOWED_SERVER_IDS 적용: {','.join(sorted(allowed_server_ids))}")

    json_files = glob.glob(os.path.join(SCAN_OUTPUT_DIR, '*.json'))
    print(f"[INFO] json_files={len(json_files)}")

    if not json_files:
        print(f"[INFO] {SCAN_OUTPUT_DIR}에 JSON 파일이 없습니다.")
        db.disconnect()
        return False

    # FK 보호(server_id): servers 테이블에 없는 서버 결과 파일은 무시한다.
    try:
        rows = db._fetch("SELECT server_id FROM servers", ())
        known_server_ids = {r["server_id"] for r in (rows or []) if r.get("server_id")}
    except Exception:
        known_server_ids = set()

    success_count = 0
    fail_count = 0
    skip_count = 0
    controller_now = datetime.now()
    inserted_item_codes: set[str] = set()
    u64_scan_ids: list[int] = []

    for json_file in json_files:
        try:
            company, server_id, item_code = parse_filename(json_file)
            server_id = str(server_id).strip()
            item_code = str(item_code).strip()

            if allowed_server_ids and server_id not in allowed_server_ids:
                print(f"[SKIP] {os.path.basename(json_file)} → 이번 실행 대상 아님(server_id={server_id})")
                skip_count += 1
                continue

            if known_server_ids and server_id not in known_server_ids:
                print(f"[SKIP] {os.path.basename(json_file)} → 미등록 서버(server_id={server_id})")
                skip_count += 1
                continue

            raw_text = ""
            with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                raw_text = f.read()

            try:
                data = json.loads(raw_text)
            except Exception:
                # Invalid \\escape 등으로 JSON 파싱이 실패하면 복구 모드로 진행
                data = _lenient_extract(raw_text, item_code, json_file)

            # D-25 등 is_success 형식 호환: is_success → status 변환
            if 'status' not in data and 'is_success' in data:
                data['status'] = 'PASS' if data['is_success'] else 'FAIL'

            # status 통일 (PASS→양호, FAIL→취약)
            status = normalize_status(data.get('status', 'FAIL'))

            data_item_code = str(data.get('item_code', item_code)).strip()
            # kisa_items에 없는 item_code이면 건너뛴다 (자동 생성하지 않음).
            try:
                exists = db._fetch("SELECT item_code FROM kisa_items WHERE item_code=%s", (data_item_code,))
                if not exists:
                    print(f"[SKIP] {data_item_code}: kisa_items에 등록되지 않은 항목이므로 건너뜁니다.")
                    skip_count += 1
                    continue
            except Exception:
                pass

            result = db.insert_scan_result(
                server_id=server_id,
                item_code=data_item_code,
                status=status,
                raw_evidence=extract_raw_evidence(data, json_file),
                scan_date=normalize_scan_date(
                    data.get('scan_date') or data.get('action_date') or "",
                    now=controller_now,
                ),
            )

            if result:
                inserted_item_codes.add(data_item_code)
                if data_item_code == "U-64":
                    u64_scan_ids.append(int(result))
                print(f"[OK] {os.path.basename(json_file)} → scan_history INSERT 성공 (scan_id: {result})")
                success_count += 1
            else:
                print(f"[FAIL] {os.path.basename(json_file)} → INSERT 실패")
                fail_count += 1

        except Exception as e:
            print(f"[ERROR] {os.path.basename(json_file)} → {e}")
            fail_count += 1

    print(f"\n[점검 파싱 완료] 성공: {success_count}, 실패: {fail_count}")
    if inserted_item_codes:
        # Helpful when a specific item (e.g., U-64) appears missing in the dashboard.
        sample = ", ".join(sorted(inserted_item_codes)[:12])
        print(f"[INFO] inserted_item_codes_sample={sample} (total_unique={len(inserted_item_codes)})")
        print(f"[INFO] inserted_contains_U-64={'U-64' in inserted_item_codes} u64_scan_ids_tail={u64_scan_ids[-3:]}")
    if skip_count:
        print(f"[점검 파싱] 스킵: {skip_count} (servers 미등록 결과 파일)")
    db.disconnect()
    return fail_count == 0


if __name__ == '__main__':
    parse_and_insert()
