"""
FastAPI 설정
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# 프로젝트 루트의 .env 로드
PROJECT_ROOT = Path(__file__).parent.parent.parent
load_dotenv(PROJECT_ROOT / '.env')

# JWT 설정
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))  # 2시간

# IP 필터링 설정
ALLOWED_CIDRS = os.getenv(
    "DASHBOARD_ALLOWED_CIDRS",
    "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1/32"
).split(",")

# 비밀번호 정책
PASSWORD_MIN_LEN = int(os.getenv("DASHBOARD_PASSWORD_MIN_LEN", "12"))
PASSWORD_MAX_LEN = int(os.getenv("DASHBOARD_PASSWORD_MAX_LEN", "128"))

# CORS 설정
CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:3000"  # React 개발 서버
).split(",")

# Fernet 암호화 키 (서버 패스워드 암호화용)
FERNET_KEY = os.getenv("FERNET_KEY")
