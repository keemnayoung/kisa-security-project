"""
parse_fix_result.py
조치 결과 JSON 파일을 읽어서 remediation_logs 테이블에 INSERT
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
from config import FIX_OUTPUT_DIR


def parse_filename(filename):
    """
    파일명에서 company, server_id, item_code 추출
    예:
      - NAVER_rocky9_1_fix_D01.json → ('NAVER', 'rocky9_1', 'D-01')
      - NAVER_naver-r9-002_U02.json → ('NAVER', 'naver-r9-002', 'U-02')  # 구형 OS 조치 결과
    """
    name = os.path.basename(filename).replace('.json', '')
    parts = name.split('_')

    raw_code = parts[-1]  # U02 / D01
    item_code = raw_code[0] + '-' + raw_code[1:]  # U-02 / D-01

    company = parts[0]
    if 'fix' in parts:
        fix_idx = parts.index('fix')
        server_id = '_'.join(parts[1:fix_idx])
    else:
        # Backward-compat: some OS fix runners wrote ..._{U02}.json without an explicit "fix" token.
        server_id = '_'.join(parts[1:-1])

    return company, server_id, item_code


def extract_failure_reason(data):
    """
    조치 실패(is_success=0) 시 raw_evidence.detail의 첫 줄을 실패 사유로 사용한다.
    """
    is_success = data.get("is_success")
    if is_success in (1, True, "1", "true", "True"):
        return None

    # 스크립트가 failure_reason를 직접 내려주면 최우선 사용
    direct_reason = str(data.get("failure_reason", "")).strip()
    if direct_reason:
        return direct_reason[:500]

    raw_evidence = data.get("raw_evidence", "")
    if not raw_evidence:
        return "조치 실패 (사유 미제공)"

    detail = _extract_detail_from_raw_evidence(raw_evidence)
    if detail:
        return detail.splitlines()[0][:500]

    return "조치 실패 (raw_evidence 파싱 실패)"


def _extract_detail_from_raw_evidence(raw_evidence):
    """
    raw_evidence 형식이 스크립트마다 조금 달라도 detail을 최대한 복구한다.
    1) JSON 객체 문자열
    2) JSON 문자열 안에 다시 JSON이 들어간 이중 인코딩
    3) 형식이 깨진 경우 정규식으로 detail 추출
    """
    if not raw_evidence:
        return None

    # 1) 정상 JSON 혹은 이중 JSON
    parsed = _try_parse_json_layers(raw_evidence)
    if isinstance(parsed, dict):
        detail = str(parsed.get("detail", "")).strip()
        if detail:
            return _decode_escapes(detail)

    # 2) 부분적으로 깨진 문자열에서 "detail":"..." 패턴 복구
    match = re.search(r'"detail"\s*:\s*"(?P<detail>.*?)"\s*(,|\})', raw_evidence, re.DOTALL)
    if match:
        return _decode_escapes(match.group("detail").strip())

    return None


def _try_parse_json_layers(text):
    current = text
    for _ in range(3):
        try:
            current = json.loads(current)
        except Exception:
            return current
    return current


def _decode_escapes(text):
    # 스크립트에서 \n, \" 형태로 이스케이프된 문자열 복원
    # NOTE: unicode_escape는 UTF-8 한글을 깨뜨리므로 사용하지 않음
    return text.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")


def _lenient_extract(text: str, fallback_item_code: str, fallback_path: str) -> dict:
    """
    Invalid \\escape 등으로 JSON 파싱이 실패한 경우 복구한다.
    """
    def _m(pat: str) -> str | None:
        m = re.search(pat, text, re.DOTALL)
        return m.group(1).strip() if m else None

    item_code = _m(r'"item_code"\s*:\s*"([^"]+)"') or fallback_item_code
    action_date = _m(r'"action_date"\s*:\s*"([^"]+)"') or ""
    is_success = _m(r'"is_success"\s*:\s*([01]|true|false|"0"|"1")') or "0"
    raw_evidence = _m(r'"raw_evidence"\s*:\s*"(.+?)"\s*,\s*"action_date"')  # best-effort
    if raw_evidence is None:
        raw_evidence = text
    raw_evidence = raw_evidence[:20000]
    return {
        "item_code": item_code,
        "action_date": action_date,
        "is_success": 1 if str(is_success).strip('"').lower() in ("1", "true") else 0,
        "raw_evidence": raw_evidence or fallback_path,
    }


def _parse_dt_best_effort(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


def normalize_action_date(raw_action_date: str, *, now: datetime, max_skew: timedelta = timedelta(minutes=15)) -> str:
    """
    Store action_date as controller time for every row created by this pipeline run.
    Same rationale as scan_date: timeline should stack per run, and remote clocks can be skewed.
    """
    dt = now.replace(second=0, microsecond=0)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_and_insert():
    db = DBConnector()
    if not db.connect():
        print("[ERROR] DB 연결 실패")
        return False

    allowed_ids_env = (os.getenv("PIPELINE_ALLOWED_SERVER_IDS") or "").strip()
    allowed_server_ids = {s.strip() for s in allowed_ids_env.split(",") if s.strip()} if allowed_ids_env else set()

    json_files = glob.glob(os.path.join(FIX_OUTPUT_DIR, '*.json'))

    if not json_files:
        print(f"[INFO] {FIX_OUTPUT_DIR}에 JSON 파일이 없습니다.")
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

    for json_file in json_files:
        try:
            company, server_id, item_code = parse_filename(json_file)

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
                data = _lenient_extract(raw_text, item_code, json_file)

            failure_reason = extract_failure_reason(data)

            # kisa_items에 없는 item_code이면 건너뛴다 (자동 생성하지 않음).
            fix_item_code = data.get('item_code', item_code)
            try:
                exists = db._fetch("SELECT item_code FROM kisa_items WHERE item_code=%s", (fix_item_code,))
                if not exists:
                    print(f"[SKIP] {fix_item_code}: kisa_items에 등록되지 않은 항목이므로 건너뜁니다.")
                    skip_count += 1
                    continue
            except Exception:
                pass

            result = db.insert_remediation_log(
                server_id=server_id,
                item_code=data.get('item_code', item_code),
                action_date=normalize_action_date(
                    data.get('action_date') or data.get('scan_date') or "",
                    now=controller_now,
                ),
                is_success=data.get('is_success', 0),
                failure_reason=failure_reason,
                raw_evidence=data.get('raw_evidence', json_file)
            )

            if result:
                print(f"[OK] {os.path.basename(json_file)} → remediation_logs INSERT 성공 (id: {result})")
                success_count += 1
            else:
                print(f"[FAIL] {os.path.basename(json_file)} → INSERT 실패")
                fail_count += 1

        except Exception as e:
            print(f"[ERROR] {os.path.basename(json_file)} → {e}")
            fail_count += 1

    print(f"\n[조치 파싱 완료] 성공: {success_count}, 실패: {fail_count}")
    if skip_count:
        print(f"[조치 파싱] 스킵: {skip_count} (servers 미등록 결과 파일)")
    db.disconnect()
    return fail_count == 0


if __name__ == '__main__':
    parse_and_insert()
