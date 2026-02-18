"""
Fernet 암호화/복호화 함수
서버 SSH/DB 패스워드를 MySQL에 안전하게 저장
"""

from cryptography.fernet import Fernet
from .config import FERNET_KEY


# Fernet 인스턴스 생성
if not FERNET_KEY:
    raise ValueError("FERNET_KEY 환경 변수가 설정되지 않았습니다")

_fernet = Fernet(FERNET_KEY.encode())


def encrypt_password(plain_password: str) -> str:
    """
    평문 비밀번호를 Fernet으로 암호화

    Args:
        plain_password: 평문 비밀번호

    Returns:
        str: Base64 인코딩된 암호화 문자열
    """
    if not plain_password:
        raise ValueError("password cannot be empty")

    encrypted_bytes = _fernet.encrypt(plain_password.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')


def decrypt_password(encrypted_password: str) -> str:
    """
    암호화된 비밀번호를 복호화

    Args:
        encrypted_password: Fernet으로 암호화된 비밀번호

    Returns:
        str: 평문 비밀번호
    """
    if not encrypted_password:
        raise ValueError("encrypted_password cannot be empty")

    try:
        decrypted_bytes = _fernet.decrypt(encrypted_password.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"복호화 실패: {str(e)}")
