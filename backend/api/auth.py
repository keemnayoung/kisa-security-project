"""
인증 API
- POST /api/auth/login: 로그인 (JWT 발급)
- GET /api/auth/me: 현재 사용자 정보
- POST /api/auth/change-password: 비밀번호 변경
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db.session import get_db
from db.models import User
from schemas.auth import (
    LoginRequest,
    LoginResponse,
    UserResponse,
    ChangePasswordRequest
)
from core.security import (
    verify_password,
    hash_password,
    create_access_token
)
from core.deps import get_current_user
from core.config import PASSWORD_MIN_LEN, PASSWORD_MAX_LEN


router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    로그인 API

    Args:
        request: 로그인 요청 (username, password)
        db: 데이터베이스 세션

    Returns:
        LoginResponse: JWT 토큰 + 사용자 정보

    Raises:
        HTTPException: 인증 실패
    """
    # 사용자 조회
    user = db.query(User).filter(User.user_name == request.username).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="아이디 또는 비밀번호가 올바르지 않습니다"
        )

    # 비밀번호 검증
    if not verify_password(request.password, user.user_passwd):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="아이디 또는 비밀번호가 올바르지 않습니다"
        )

    # last_login 업데이트
    user.last_login = datetime.now()
    db.commit()

    # JWT 토큰 생성
    access_token = create_access_token(
        data={
            "sub": str(user.user_id),  # JWT 스펙: sub는 문자열이어야 함
            "username": user.user_name,
            "role": user.role,
            "company": user.company
        }
    )

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.from_orm(user)
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    현재 사용자 정보 조회

    Args:
        current_user: 현재 로그인된 사용자

    Returns:
        UserResponse: 사용자 정보
    """
    return UserResponse.from_orm(current_user)


@router.post("/change-password")
def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    비밀번호 변경 API

    Args:
        request: 비밀번호 변경 요청 (old_password, new_password)
        current_user: 현재 로그인된 사용자
        db: 데이터베이스 세션

    Returns:
        dict: 성공 메시지

    Raises:
        HTTPException: 비밀번호 검증 실패
    """
    # 기존 비밀번호 검증
    if not verify_password(request.old_password, current_user.user_passwd):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="현재 비밀번호가 올바르지 않습니다"
        )

    # 새 비밀번호 검증
    if len(request.new_password) < PASSWORD_MIN_LEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"비밀번호는 최소 {PASSWORD_MIN_LEN}자 이상이어야 합니다"
        )

    if len(request.new_password) > PASSWORD_MAX_LEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"비밀번호는 {PASSWORD_MAX_LEN}자 이하여야 합니다"
        )

    # 이전 비밀번호와 동일한지 확인
    if verify_password(request.new_password, current_user.user_passwd):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="새 비밀번호는 현재 비밀번호와 달라야 합니다"
        )

    # prev_user_passwd가 있으면 그것과도 비교
    if current_user.prev_user_passwd:
        if verify_password(request.new_password, current_user.prev_user_passwd):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="새 비밀번호는 이전 비밀번호와 달라야 합니다"
            )

    # 비밀번호 변경
    current_user.prev_user_passwd = current_user.user_passwd
    current_user.user_passwd = hash_password(request.new_password)
    current_user.password_changed_at = datetime.now()
    current_user.must_change_password = False

    db.commit()

    return {"message": "비밀번호가 변경되었습니다"}
