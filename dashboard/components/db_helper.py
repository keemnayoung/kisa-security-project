"""
components/db_helper.py
대시보드용 DB 연결 헬퍼 (프로젝트 루트 .env 로드)
"""

import mysql.connector
from mysql.connector import Error
import os
from pathlib import Path
from dotenv import load_dotenv

# 1. .env 파일 경로 찾기 (현재 파일 기준 3단계 상위 폴더)
# dashboard/components/db_helper.py -> dashboard -> kisa-security-project -> .env
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_PATH = BASE_DIR / '.env'

# 2. .env 파일 로드 (성공 여부를 터미널에 출력)
if load_dotenv(dotenv_path=ENV_PATH):
    print(f"✅ 설정 파일 로드 성공: {ENV_PATH}")
else:
    print(f"❌ 설정 파일을 못 찾았습니다! 경로 확인 필요: {ENV_PATH}")

def get_connection():
    try:
        # 3. .env에서 정보 가져오기 
        db_host = os.getenv('DB_HOST', '127.0.0.1')
        db_user = os.getenv('DB_USER')
        db_password = os.getenv('DB_PASSWORD')
        db_name = os.getenv('DB_NAME', 'kisa_security')

        # 필수 정보가 없으면 에러 출력
        if not db_user or not db_password:
            print("❌ .env 파일에서 DB_USER 또는 DB_PASSWORD를 읽지 못했습니다.")
            return None

        # DB 연결 시도
        conn = mysql.connector.connect(
            host=db_host,
            port=3306,
            user=db_user,       # manager
            password=db_password, # qwer1234
            database=db_name,
            charset='utf8mb4'
        )
        return conn
    except Error as e:
        return None


def run_query(query, params=None):
    conn = get_connection()
    if not conn:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        return cursor.fetchall()
    except Error as e:
        return []
    finally:
        conn.close()


def run_execute(query, params=None):
    conn = get_connection()
    if not conn:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return True
    except Error as e:
        conn.rollback()
        return False
    finally:
        conn.close()

