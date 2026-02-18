"""
FastAPI 의존성 주입 함수
- DB 세션 제공
- 인증 사용자 추출
- 권한 확인
"""

from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from db.session import get_db
from db.models import User
from core.security import decode_access_token


# HTTP Bearer 토큰 인증
security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    JWT 토큰에서 현재 사용자 추출

    Args:
        credentials: Bearer 토큰
        db: 데이터베이스 세션

    Returns:
        User: 현재 사용자

    Raises:
        HTTPException: 토큰이 유효하지 않거나 사용자를 찾을 수 없는 경우
    """
    token = credentials.credentials
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="로그인 세션이 만료되었습니다. 다시 로그인해주세요.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str: Optional[str] = payload.get("sub")
    if user_id_str is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="로그인 세션이 만료되었습니다. 다시 로그인해주세요.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="로그인 세션이 만료되었습니다. 다시 로그인해주세요.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="사용자를 찾을 수 없습니다. 다시 로그인해주세요.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_admin_user(user: User = Depends(get_current_user)) -> User:
    """
    ADMIN 권한 확인

    Args:
        user: 현재 사용자

    Returns:
        User: ADMIN 사용자

    Raises:
        HTTPException: ADMIN 권한이 없는 경우
    """
    if user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 권한이 필요합니다"
        )
    return user


def get_viewer_or_admin_user(user: User = Depends(get_current_user)) -> User:
    """
    VIEWER 또는 ADMIN 권한 확인 (모든 로그인 사용자)

    Args:
        user: 현재 사용자

    Returns:
        User: 로그인된 사용자
    """
    if user.role not in ("VIEWER", "ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="뷰어 또는 관리자 권한이 필요합니다"
        )
    return user
