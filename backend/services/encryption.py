"""
Fernet 암호화 서비스
MySQL db_passwd 필드 암호화/복호화
"""

from cryptography.fernet import Fernet
from typing import Optional
from core.config import FERNET_KEY


def get_fernet() -> Optional[Fernet]:
    """
    Fernet 인스턴스 생성

    Returns:
        Fernet 객체 또는 None (키가 없는 경우)
    """
    if not FERNET_KEY:
        return None

    try:
        return Fernet(FERNET_KEY.encode())
    except Exception:
        return None


def encrypt_password(password: str) -> str:
    """
    비밀번호 Fernet 암호화

    Args:
        password: 평문 비밀번호

    Returns:
        암호화된 비밀번호 (base64 문자열)

    Raises:
        ValueError: FERNET_KEY가 설정되지 않은 경우
    """
    if not password:
        return ""

    fernet = get_fernet()
    if not fernet:
        raise ValueError("FERNET_KEY가 설정되지 않았습니다")

    encrypted = fernet.encrypt(password.encode())
    return encrypted.decode()


def decrypt_password(encrypted_password: str) -> str:
    """
    Fernet 암호화된 비밀번호 복호화

    Args:
        encrypted_password: 암호화된 비밀번호

    Returns:
        평문 비밀번호

    Raises:
        ValueError: FERNET_KEY가 설정되지 않은 경우
        Exception: 복호화 실패
    """
    if not encrypted_password:
        return ""

    fernet = get_fernet()
    if not fernet:
        raise ValueError("FERNET_KEY가 설정되지 않았습니다")

    decrypted = fernet.decrypt(encrypted_password.encode())
    return decrypted.decode()
