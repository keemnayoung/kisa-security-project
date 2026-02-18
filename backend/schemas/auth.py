"""
인증 관련 Pydantic 스키마
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


# =============================================================================
# Request 스키마
# =============================================================================

class LoginRequest(BaseModel):
    """로그인 요청"""
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    """비밀번호 변경 요청"""
    old_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)


# =============================================================================
# Response 스키마
# =============================================================================

class Token(BaseModel):
    """JWT 토큰 응답"""
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """사용자 정보 응답"""
    user_id: int
    user_name: str
    role: str
    company: str
    must_change_password: bool
    password_changed_at: Optional[datetime]
    last_login: datetime
    created_at: datetime

    class Config:
        from_attributes = True  # SQLAlchemy 모델 변환 허용


class LoginResponse(BaseModel):
    """로그인 성공 응답"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
