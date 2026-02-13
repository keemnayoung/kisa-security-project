"""
parse_fix_result.py
조치 결과 JSON 파일을 읽어서 remediation_logs 테이블에 INSERT
"""

import os
import json
import glob
import sys
import re

# backend/ 디렉토리를 path에 추가
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from db.connector import DBConnector
from config import FIX_OUTPUT_DIR


def parse_filename(filename):
    """
    파일명에서 company, server_id, item_code 추출
    예: NAVER_rocky9_1_fix_D01.json → ('NAVER', 'rocky9_1', 'D-01')
    """
    name = os.path.basename(filename).replace('.json', '')
    parts = name.split('_')

    raw_code = parts[-1]  # D01
    item_code = raw_code[0] + '-' + raw_code[1:]  # D-01

    fix_idx = parts.index('fix')
    company = parts[0]
    server_id = '_'.join(parts[1:fix_idx])  # rocky9_1

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
    try:
        return bytes(text, "utf-8").decode("unicode_escape")
    except Exception:
        return text.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")


def parse_and_insert():
    db = DBConnector()
    if not db.connect():
        print("[ERROR] DB 연결 실패")
        return False

    json_files = glob.glob(os.path.join(FIX_OUTPUT_DIR, '*.json'))

    if not json_files:
        print(f"[INFO] {FIX_OUTPUT_DIR}에 JSON 파일이 없습니다.")
        db.disconnect()
        return False

    success_count = 0
    fail_count = 0

    for json_file in json_files:
        try:
            company, server_id, item_code = parse_filename(json_file)

            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            failure_reason = extract_failure_reason(data)

            result = db.insert_remediation_log(
                server_id=server_id,
                item_code=data.get('item_code', item_code),
                action_date=data['action_date'],
                is_success=data['is_success'],
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
    db.disconnect()
    return fail_count == 0


if __name__ == '__main__':
    parse_and_insert()
