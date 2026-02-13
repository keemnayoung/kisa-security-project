"""
parse_scan_result.py
점검 결과 JSON 파일을 읽어서 scan_history 테이블에 INSERT
"""

import os
import json
import glob
import sys

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


def parse_and_insert():
    db = DBConnector()
    if not db.connect():
        print("[ERROR] DB 연결 실패")
        return False

    json_files = glob.glob(os.path.join(SCAN_OUTPUT_DIR, '*.json'))

    if not json_files:
        print(f"[INFO] {SCAN_OUTPUT_DIR}에 JSON 파일이 없습니다.")
        db.disconnect()
        return False

    success_count = 0
    fail_count = 0

    for json_file in json_files:
        try:
            company, server_id, item_code = parse_filename(json_file)

            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # status 통일 (PASS→양호, FAIL→취약)
            status = normalize_status(data['status'])

            result = db.insert_scan_result(
                server_id=server_id,
                item_code=data.get('item_code', item_code),
                status=status,
                raw_evidence=extract_raw_evidence(data, json_file),
                scan_date=data['scan_date']
            )

            if result:
                print(f"[OK] {os.path.basename(json_file)} → scan_history INSERT 성공 (scan_id: {result})")
                success_count += 1
            else:
                print(f"[FAIL] {os.path.basename(json_file)} → INSERT 실패")
                fail_count += 1

        except Exception as e:
            print(f"[ERROR] {os.path.basename(json_file)} → {e}")
            fail_count += 1

    print(f"\n[점검 파싱 완료] 성공: {success_count}, 실패: {fail_count}")
    db.disconnect()
    return fail_count == 0


if __name__ == '__main__':
    parse_and_insert()
