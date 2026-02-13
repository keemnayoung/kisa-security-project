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


def parse_filename(filename):
    """
    파일명에서 company, server_id, item_code 추출
    예: NAVER_rocky9_1_check_U01.json → ('NAVER', 'rocky9_1', 'U-01')
    """
    name = os.path.basename(filename).replace('.json', '')
    parts = name.split('_')

    raw_code = parts[-1]  # U01
    item_code = raw_code[0] + '-' + raw_code[1:]  # U-01

    check_idx = parts.index('check')
    company = parts[0]
    server_id = '_'.join(parts[1:check_idx])  # rocky9_1

    return company, server_id, item_code


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

            result = db.insert_scan_result(
                server_id=server_id,
                item_code=data.get('item_code', item_code),
                status=data['status'],
                raw_evidence=json_file,
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