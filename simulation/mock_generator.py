"""
mock_generator.py
97대 가짜 서버 + 점검/조치 데이터 생성

사용법:
    python3 mock_generator.py          → SQL 파일 생성
    python3 mock_generator.py --apply  → SQL 파일 생성 + DB에 바로 적용
"""

import random, sys, os
from datetime import datetime

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), 'fake_data', 'mock_data.sql')

# 실제 서버 3대는 제외 (rocky9_1 등)
COMPANIES = {
    'AUTOEVER': {'full': 'HYUNDAI AUTOEVER', 'count': 30},
    'NAVER': {'full': 'NAVER', 'count': 32},
    'KAKAO': {'full': 'KAKAO', 'count': 35},
}

OS_DB_COMBOS = [
    ('Rocky Linux 9.7', 'MySQL 8.0.4', '3306'),
    ('Rocky Linux 10.1', 'PostgreSQL 16.11', '5432'),
    ('Rocky Linux 9.7', None, None),
    ('Rocky Linux 10.1', None, None),
]

ITEMS = ['U-01', 'U-02', 'U-03', 'U-04', 'U-05']

MANAGERS = {
    'AUTOEVER': [('홍길동', '개발1팀'), ('김영희', '인프라팀'), ('박철수', '보안팀')],
    'NAVER': [('이수진', '플랫폼팀'), ('최민호', '검색팀'), ('정다은', 'AI팀')],
    'KAKAO': [('강지훈', '톡개발팀'), ('윤서연', '페이팀'), ('임하늘', '인프라팀')],
}


def generate():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    lines = []
    lines.append("USE kisa_security;")
    lines.append("")

    # 서버 생성
    lines.append("-- 가짜 서버 97대")
    ip_counter = 1
    all_servers = []

    for company_key, info in COMPANIES.items():
        for i in range(1, info['count'] + 1):
            sid = f"{company_key.lower()}-mock-{i:02d}"
            os_type, db_type, db_port = random.choice(OS_DB_COMBOS)
            mgr = random.choice(MANAGERS[company_key])

            db_t = f"'{db_type}'" if db_type else "NULL"
            db_p = f"'{db_port}'" if db_port else "NULL"
            db_u = "'audit_user'" if db_type else "NULL"

            lines.append(f"INSERT IGNORE INTO servers (server_id, company, hostname, ip_address, ssh_port, os_type, db_type, db_port, db_user, db_passwd, is_active, manager, department) VALUES ('{sid}', '{info['full']}', 'audit2026', '10.20.{ip_counter // 256}.{ip_counter % 256}', '22', '{os_type}', {db_t}, {db_p}, {db_u}, 'enc_mock', 1, '{mgr[0]}', '{mgr[1]}');")
            all_servers.append(sid)
            ip_counter += 1

    lines.append("")

    # 1차 점검 (취약률 70%)
    lines.append("-- 1차 점검 (2026-02-10) 조치 전")
    for sid in all_servers:
        for item in ITEMS:
            status = '취약' if random.random() < 0.7 else '양호'
            lines.append(f"INSERT INTO scan_history (server_id, item_code, status, raw_evidence, scan_date) VALUES ('{sid}', '{item}', '{status}', '/tmp/audit/check/mock.json', '2026-02-10 14:00:00');")

    lines.append("")

    # 조치 기록
    lines.append("-- 조치 기록 (2026-02-11)")
    for sid in all_servers:
        for item in ITEMS:
            if random.random() < 0.5:
                success = 1 if random.random() < 0.85 else 0
                lines.append(f"INSERT INTO remediation_logs (server_id, item_code, action_date, is_success, raw_evidence) VALUES ('{sid}', '{item}', '2026-02-11 10:30:00', {success}, '/tmp/audit/fix/mock.json');")

    lines.append("")

    # 2차 점검 (취약률 25%)
    lines.append("-- 2차 점검 (2026-02-12) 조치 후")
    for sid in all_servers:
        for item in ITEMS:
            status = '취약' if random.random() < 0.25 else '양호'
            lines.append(f"INSERT INTO scan_history (server_id, item_code, status, raw_evidence, scan_date) VALUES ('{sid}', '{item}', '{status}', '/tmp/audit/check/mock.json', '2026-02-12 16:00:00');")

    lines.append("")

    # 예외 몇 개
    lines.append("-- 예외 항목")
    samples = random.sample(all_servers, 5)
    for sid in samples:
        item = random.choice(ITEMS)
        lines.append(f"INSERT INTO exceptions (server_id, item_code, reason, valid_date) VALUES ('{sid}', '{item}', '테스트 예외 처리', '2026-12-31 00:00:00');")

    sql = '\n'.join(lines)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(sql)

    print(f"[OK] {OUTPUT_FILE} 생성 완료 (서버 {len(all_servers)}대)")
    return OUTPUT_FILE


if __name__ == '__main__':
    path = generate()

    if '--apply' in sys.argv:
        print("[INFO] DB에 적용 중...")
        os.system(f"mysql kisa_security < {path}")
        print("[OK] DB 적용 완료")