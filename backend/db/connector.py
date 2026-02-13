"""
connector.py
MySQL 연결 관리 (커넥션 풀)
"""

import mysql.connector
from mysql.connector import pooling, Error
import sys, os

# backend/ 디렉토리를 path에 추가
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from config import DB_CONFIG


class DBConnector:
    _pool = None

    @classmethod
    def _get_pool(cls):
        """커넥션 풀 싱글턴"""
        if cls._pool is None:
            cls._pool = pooling.MySQLConnectionPool(
                pool_name="kisa_pool",
                pool_size=5,
                **DB_CONFIG
            )
        return cls._pool

    def __init__(self):
        self.connection = None

    def connect(self):
        """풀에서 커넥션 획득"""
        try:
            self.connection = self._get_pool().get_connection()
            return True
        except Error as e:
            print(f"[DB ERROR] 연결 실패: {e}")
            return False

    def disconnect(self):
        """커넥션 반환"""
        if self.connection and self.connection.is_connected():
            self.connection.close()

    # =========================================================
    # scan_history
    # =========================================================
    def insert_scan_result(self, server_id, item_code, status, raw_evidence, scan_date):
        query = """
            INSERT INTO scan_history (server_id, item_code, status, raw_evidence, scan_date)
            VALUES (%s, %s, %s, %s, %s)
        """
        return self._execute(query, (server_id, item_code, status, raw_evidence, scan_date))

    def get_scan_history(self, server_id=None, item_code=None):
        query = "SELECT * FROM scan_history WHERE 1=1"
        params = []
        if server_id:
            query += " AND server_id = %s"
            params.append(server_id)
        if item_code:
            query += " AND item_code = %s"
            params.append(item_code)
        query += " ORDER BY scan_date DESC"
        return self._fetch(query, tuple(params))

    def get_latest_scan(self, server_id):
        query = """
            SELECT sh.*, ki.title, ki.severity, ki.category
            FROM scan_history sh
            JOIN kisa_items ki ON sh.item_code = ki.item_code
            WHERE sh.server_id = %s
              AND sh.scan_date = (
                  SELECT MAX(scan_date) FROM scan_history WHERE server_id = %s
              )
            ORDER BY sh.item_code
        """
        return self._fetch(query, (server_id, server_id))

    # =========================================================
    # remediation_logs
    # =========================================================
    def insert_remediation_log(self, server_id, item_code, action_date, is_success, raw_evidence):
        query = """
            INSERT INTO remediation_logs (server_id, item_code, action_date, is_success, raw_evidence)
            VALUES (%s, %s, %s, %s, %s)
        """
        return self._execute(query, (server_id, item_code, action_date, is_success, raw_evidence))

    # =========================================================
    # servers
    # =========================================================
    def get_active_servers(self, company=None):
        query = "SELECT * FROM servers WHERE is_active = 1"
        params = []
        if company:
            query += " AND company = %s"
            params.append(company)
        return self._fetch(query, tuple(params))

    def get_server(self, server_id):
        query = "SELECT * FROM servers WHERE server_id = %s"
        result = self._fetch(query, (server_id,))
        return result[0] if result else None

    # =========================================================
    # exceptions
    # =========================================================
    def get_exceptions(self, server_id):
        query = """
            SELECT item_code FROM exceptions
            WHERE server_id = %s AND valid_date > NOW()
        """
        results = self._fetch(query, (server_id,))
        return [row['item_code'] for row in results] if results else []

    # =========================================================
    # 대시보드용 집계 쿼리
    # =========================================================
    def get_vulnerability_summary(self, server_id, scan_date=None):
        query = """
            SELECT
                scan_date,
                SUM(CASE WHEN status = '양호' THEN 1 ELSE 0 END) AS pass_count,
                SUM(CASE WHEN status = '취약' THEN 1 ELSE 0 END) AS fail_count
            FROM scan_history
            WHERE server_id = %s
        """
        params = [server_id]
        if scan_date:
            query += " AND scan_date = %s"
            params.append(scan_date)
        query += " GROUP BY scan_date ORDER BY scan_date"
        return self._fetch(query, tuple(params))

    # =========================================================
    # 내부 헬퍼
    # =========================================================
    def _execute(self, query, params=None):
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            return cursor.lastrowid
        except Error as e:
            print(f"[DB ERROR] 쿼리 실행 실패: {e}")
            self.connection.rollback()
            return None

    def _fetch(self, query, params=None):
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params)
            return cursor.fetchall()
        except Error as e:
            print(f"[DB ERROR] 조회 실패: {e}")
            return None