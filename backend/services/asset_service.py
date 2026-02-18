"""
자산 관리 서비스
"""

import subprocess
import socket
from typing import Tuple
from sqlalchemy.orm import Session

from db.models import Server
from schemas.asset import ServerCreate
from services.encryption import encrypt_password


def test_ssh_connection(ip_address: str, hostname: str, port: str = "22") -> Tuple[bool, str]:
    """
    SSH 연결 테스트 (포트 접근성 확인)

    Args:
        ip_address: 서버 IP
        hostname: 서버 호스트명 (표시용)
        port: SSH 포트

    Returns:
        (성공 여부, 메시지)
    """
    try:
        # 디버깅: 받은 값 로깅
        print(f"[DEBUG] test_ssh_connection - ip_address: {ip_address!r}, hostname: {hostname!r}, port: {port!r}")

        # SSH 포트가 열려있는지 확인 (타임아웃 3초)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip_address, int(port)))
        sock.close()

        if result == 0:
            return True, f"SSH 포트 {port}가 열려 있습니다"
        else:
            return False, f"SSH 포트 {port}에 연결할 수 없습니다"

    except socket.timeout:
        return False, f"연결 시간 초과 ({ip_address}:{port})"
    except Exception as e:
        return False, f"SSH 연결 테스트 실패: {str(e)}"


def test_db_port(ip_address: str, db_port: int) -> Tuple[bool, str]:
    """
    DB 포트 테스트

    Args:
        ip_address: 서버 IP
        db_port: DB 포트

    Returns:
        (성공 여부, 메시지)
    """
    try:
        # 디버깅: 받은 값 로깅
        print(f"[DEBUG] test_db_port - ip_address: {ip_address!r}, db_port: {db_port!r}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip_address, db_port))
        sock.close()

        if result == 0:
            return True, f"DB 포트 {db_port} 접근 가능"
        else:
            return False, f"DB 포트 {db_port}에 연결할 수 없습니다"

    except socket.timeout:
        return False, f"연결 시간 초과 ({ip_address}:{db_port})"
    except Exception as e:
        return False, f"DB 포트 테스트 실패: {str(e)}"


def test_db_login(
    ip_address: str,
    db_type: str,
    db_port: int,
    db_user: str,
    db_passwd: str
) -> Tuple[bool, str]:
    """
    DB 로그인 테스트 (실제 연결 시도)

    Args:
        ip_address: 서버 IP
        db_type: DB 종류 (MySQL, PostgreSQL)
        db_port: DB 포트
        db_user: DB 사용자명
        db_passwd: DB 비밀번호

    Returns:
        (성공 여부, 메시지)
    """
    # 디버깅: 받은 값 로깅 (비밀번호는 마스킹)
    print(f"[DEBUG] test_db_login - ip_address: {ip_address!r}, db_type: {db_type!r}, db_port: {db_port!r}, db_user: {db_user!r}")

    db_type_lower = db_type.lower()

    # MySQL 연결 테스트
    if "mysql" in db_type_lower or "mariadb" in db_type_lower:
        try:
            import mysql.connector

            conn = mysql.connector.connect(
                host=ip_address,
                port=db_port,
                user=db_user,
                password=db_passwd,
                connect_timeout=3
            )
            conn.close()
            return True, f"DB 로그인 성공 ({db_type} {db_user}@{ip_address}:{db_port})"

        except mysql.connector.Error as e:
            error_code = e.errno
            if error_code == 1045:  # Access denied
                return False, f"DB 로그인 실패: 비밀번호 오류 또는 사용자 '{db_user}' 권한 없음"
            elif error_code == 2003:  # Can't connect
                return False, f"DB 서버 연결 실패: {ip_address}:{db_port}"
            elif error_code == 2013:  # Lost connection
                return False, f"DB 연결 시간 초과"
            else:
                return False, f"DB 연결 실패: {str(e)}"
        except Exception as e:
            return False, f"DB 로그인 테스트 실패: {str(e)}"

    # PostgreSQL 연결 테스트
    elif "postgres" in db_type_lower:
        try:
            import psycopg2

            conn = psycopg2.connect(
                host=ip_address,
                port=db_port,
                user=db_user,
                password=db_passwd,
                database='postgres',  # 기본 DB로 연결 (인증 확인용)
                connect_timeout=3
            )
            conn.close()
            return True, f"DB 로그인 성공 ({db_type} {db_user}@{ip_address}:{db_port})"

        except psycopg2.OperationalError as e:
            error_msg = str(e).lower()
            if "password authentication failed" in error_msg:
                return False, f"DB 로그인 실패: 비밀번호 오류"
            elif "role" in error_msg and "does not exist" in error_msg:
                return False, f"DB 로그인 실패: 사용자 '{db_user}' 존재하지 않음"
            elif "timeout" in error_msg or "could not connect" in error_msg:
                return False, f"DB 서버 연결 실패: {ip_address}:{db_port}"
            else:
                return False, f"DB 연결 실패: {str(e)}"
        except Exception as e:
            return False, f"DB 로그인 테스트 실패: {str(e)}"

    else:
        return False, f"지원하지 않는 DB 종류: {db_type}"


def create_server(db: Session, server_data: ServerCreate) -> Server:
    """
    서버 등록

    Args:
        db: 데이터베이스 세션
        server_data: 서버 등록 데이터

    Returns:
        생성된 Server 객체

    Raises:
        ValueError: 서버 ID 중복
    """
    # 입력값 trim (공백 제거)
    server_data.server_id = server_data.server_id.strip()
    server_data.ip_address = server_data.ip_address.strip()
    server_data.hostname = server_data.hostname.strip()

    # 서버 ID 중복 확인
    existing_server = db.query(Server).filter(Server.server_id == server_data.server_id).first()
    if existing_server:
        raise ValueError(f"서버 ID '{server_data.server_id}'가 이미 존재합니다")

    # DB 비밀번호 암호화
    encrypted_passwd = ""
    if server_data.db_passwd and server_data.encrypt_pw:
        try:
            encrypted_passwd = encrypt_password(server_data.db_passwd)
        except Exception as e:
            raise ValueError(f"비밀번호 암호화 실패: {str(e)}")
    elif server_data.db_passwd:
        # 암호화 하지 않는 경우 (테스트용)
        encrypted_passwd = server_data.db_passwd

    # 서버 생성
    new_server = Server(
        server_id=server_data.server_id,
        ip_address=server_data.ip_address,
        company=server_data.company,
        hostname=server_data.hostname,
        ssh_port=server_data.ssh_port,
        os_type=server_data.os_type,
        db_type=server_data.db_type or "없음",
        db_port=server_data.db_port,
        db_user=server_data.db_user,
        db_passwd=encrypted_passwd,
        manager=server_data.manager,
        department=server_data.department,
        is_active=True
    )

    db.add(new_server)
    db.commit()
    db.refresh(new_server)

    return new_server
