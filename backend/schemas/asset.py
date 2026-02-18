"""
자산 관리 Pydantic 스키마
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class ServerCreate(BaseModel):
    """서버 등록 요청"""
    server_id: str = Field(..., min_length=1, max_length=100)
    ip_address: str = Field(..., min_length=7, max_length=45)
    company: str = Field(..., min_length=1, max_length=100)
    hostname: str = Field(..., min_length=1, max_length=100)
    ssh_port: str = Field(default="22", max_length=10)
    os_type: str = Field(..., min_length=1, max_length=100)
    db_type: Optional[str] = Field(None, max_length=100)
    db_port: Optional[str] = Field(None, max_length=10)
    db_user: Optional[str] = Field(None, max_length=100)
    db_passwd: Optional[str] = None  # 평문으로 받아서 암호화 저장
    manager: str = Field(..., min_length=1, max_length=100)
    department: str = Field(..., min_length=1, max_length=100)
    encrypt_pw: bool = Field(default=True)  # 비밀번호 암호화 여부


class BulkServerCreate(BaseModel):
    """CSV 일괄 등록 요청"""
    servers: List[ServerCreate]


class SSHTestRequest(BaseModel):
    """SSH 연결 테스트 요청"""
    ip_address: str
    hostname: str
    ssh_port: str = "22"


class DBPortTestRequest(BaseModel):
    """DB 포트 테스트 요청"""
    ip_address: str
    db_port: int


class DBLoginTestRequest(BaseModel):
    """DB 로그인 테스트 요청"""
    ip_address: str
    db_type: str
    db_port: int
    db_user: str
    db_passwd: str


class ServerResponse(BaseModel):
    """서버 응답"""
    id: int
    server_id: str
    ip_address: str
    company: str
    hostname: str
    ssh_port: str
    os_type: str
    db_type: Optional[str]
    db_port: Optional[str]
    db_user: Optional[str]
    manager: str
    department: str
    is_active: bool

    class Config:
        from_attributes = True
