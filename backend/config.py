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

# Ansible 경로 설정
ANSIBLE_ROOT = PROJECT_ROOT / 'ansible'
ANSIBLE_INVENTORY = ANSIBLE_ROOT / 'inventories' / 'hosts.ini'
ANSIBLE_CONFIG = ANSIBLE_ROOT / 'ansible.cfg'

# DB 기본값 (타입별)
DB_DEFAULTS = {
    'mysql': {'port': 3306, 'user': 'root'},
    'postgresql': {'port': 5432, 'user': 'postgres'}
}


# ============================================================
# 헬퍼 함수
# ============================================================

def normalize_db_type(db_type: str) -> str:
    """
    DB 타입 정규화 (버전 정보 제거)

    Examples:
        "MySQL 8.0.4" -> "mysql"
        "PostgreSQL 16.11" -> "postgresql"
        "MYSQL" -> "mysql"

    Args:
        db_type: DB 타입 문자열

    Returns:
        정규화된 DB 타입 (소문자)
    """
    if not db_type:
        return ""

    db_type_lower = db_type.lower()

    if "mysql" in db_type_lower or "mariadb" in db_type_lower:
        return "mysql"
    elif "postgres" in db_type_lower:
        return "postgresql"
    else:
        # 공백 제거하고 첫 단어만
        return db_type_lower.split()[0] if db_type_lower else db_type_lower


def normalize_company_name(company: str) -> str:
    """
    회사명 정규화

    Examples:
        "NAVER" -> "naver"
        "  Kakao  " -> "kakao"

    Args:
        company: 회사명

    Returns:
        소문자로 변환되고 공백이 제거된 회사명
    """
    if not company:
        return ""
    return company.strip().lower()


def get_db_port(db_type: str) -> int:
    """
    DB 타입에 따른 기본 포트 반환

    Args:
        db_type: DB 타입 (정규화 전/후 모두 가능)

    Returns:
        기본 포트 번호
    """
    normalized = normalize_db_type(db_type)
    return DB_DEFAULTS.get(normalized, {}).get('port', 3306)


def get_db_user(db_type: str) -> str:
    """
    DB 타입에 따른 기본 사용자 반환

    Args:
        db_type: DB 타입 (정규화 전/후 모두 가능)

    Returns:
        기본 사용자명
    """
    normalized = normalize_db_type(db_type)
    return DB_DEFAULTS.get(normalized, {}).get('user', 'root')