"""
score_calculator.py
보안 점수 산출 (예외 처리 반영, severity 가중치 적용)
"""

import sys, os

# backend/ 디렉토리를 path에 추가
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from db.connector import DBConnector

# severity별 가중치
SEVERITY_WEIGHT = {
    '상': 3,
    '중': 2,
    '하': 1,
}


def calculate_score(server_id):
    """
    특정 서버의 보안 점수 계산

    점수 = (양호 항목 가중치 합 / 전체 항목 가중치 합) × 100

    - exceptions 테이블에 있는 항목은 '양호'로 처리
    - severity(상/중/하)에 따라 가중치 적용
    """
    db = DBConnector()
    if not db.connect():
        print("[ERROR] DB 연결 실패")
        return None

    try:
        scan_results = db.get_latest_scan(server_id)
        if not scan_results:
            print(f"[INFO] {server_id}의 점검 결과가 없습니다.")
            return None

        exceptions = db.get_exceptions(server_id)

        total_weight = 0
        pass_weight = 0
        details = []

        for item in scan_results:
            weight = SEVERITY_WEIGHT.get(item['severity'], 1)
            total_weight += weight

            if item['item_code'] in exceptions:
                status = '양호 (예외)'
                pass_weight += weight
            elif item['status'] == '양호':
                status = '양호'
                pass_weight += weight
            else:
                status = '취약'

            details.append({
                'item_code': item['item_code'],
                'title': item['title'],
                'severity': item['severity'],
                'weight': weight,
                'status': status,
            })

        score = round((pass_weight / total_weight) * 100, 1) if total_weight > 0 else 0

        result = {
            'server_id': server_id,
            'score': score,
            'total_items': len(scan_results),
            'pass_count': sum(1 for d in details if '양호' in d['status']),
            'fail_count': sum(1 for d in details if d['status'] == '취약'),
            'exception_count': sum(1 for d in details if '예외' in d['status']),
            'details': details,
        }

        print(f"[{server_id}] 보안 점수: {score}점 "
              f"(양호: {result['pass_count']}, 취약: {result['fail_count']}, "
              f"예외: {result['exception_count']})")

        return result

    except Exception as e:
        print(f"[ERROR] 점수 계산 실패: {e}")
        return None

    finally:
        db.disconnect()


if __name__ == '__main__':
    calculate_score('rocky9_1')