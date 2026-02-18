"""
보안 관련 함수 (JWT 토큰, PBKDF2 비밀번호 해싱)
기존 Streamlit auth.py의 PBKDF2 로직 이식
"""

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from jose import JWTError, jwt
from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES


# =============================================================================
# PBKDF2 Password Hashing (기존 Streamlit 로직 이식)
# =============================================================================

def hash_password(password: str, iterations: int = 260_000) -> str:
    """
    PBKDF2-HMAC-SHA256 해싱

    Returns: pbkdf2_sha256$<iterations>$<salt_b64>$<dk_b64>
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password required")

    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)

    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(dk).decode("ascii").rstrip("="),
    )


def _b64decode_nopad(s: str) -> bytes:
    """Base64 디코딩 (패딩 없는 경우 처리)"""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def verify_password(password: str, stored: str) -> bool:
    """
    PBKDF2 해시 검증

    Args:
        password: 입력 비밀번호
        stored: 저장된 해시 (pbkdf2_sha256$<iterations>$<salt>$<hash>)

    Returns:
        bool: 비밀번호 일치 여부
    """
    if not password or not stored:
        return False

    stored = str(stored)

    # PBKDF2 해시 형식 확인
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, it_s, salt_b64, dk_b64 = stored.split("$", 3)
            iterations = int(it_s)
            salt = _b64decode_nopad(salt_b64)
            expected = _b64decode_nopad(dk_b64)

            # 입력 비밀번호로 해시 계산
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)

            # 타이밍 공격 방지를 위해 compare_digest 사용
            return hmac.compare_digest(dk, expected)
        except Exception:
            return False

    return False


# =============================================================================
# JWT Token 생성/검증
# =============================================================================

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    JWT 액세스 토큰 생성

    Args:
        data: 토큰에 포함할 데이터 (sub, username, role, company 등)
        expires_delta: 만료 시간 (기본값: ACCESS_TOKEN_EXPIRE_MINUTES)

    Returns:
        str: JWT 토큰
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow()  # Issued At
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    JWT 토큰 디코딩

    Args:
        token: JWT 토큰

    Returns:
        Dict or None: 토큰 페이로드 (유효하지 않으면 None)
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
