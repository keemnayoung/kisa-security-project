"""
config.py
DB 접속 정보 및 프로젝트 설정 (.env 파일에서 로드)
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# 프로젝트 루트의 .env 로드 (backend/ 상위)
PROJECT_ROOT = Path(__file__).parent.parent
load_dotenv(PROJECT_ROOT / '.env')

# MySQL 접속 정보
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'kisa_security'),
    'charset': 'utf8mb4',
}

# 점검 결과 JSON 저장 경로
SCAN_OUTPUT_DIR = os.getenv('SCAN_OUTPUT_DIR', '/tmp/audit/check')

# 조치 결과 JSON 저장 경로
FIX_OUTPUT_DIR = os.getenv('FIX_OUTPUT_DIR', '/tmp/audit/fix')