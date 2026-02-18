"""
FastAPI 메인 애플리케이션
- 인증 API
- IP 필터링 미들웨어
- CORS 설정
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api import auth, assets, scan, dashboard, analysis, fix, exceptions, reports
from core.config import ALLOWED_CIDRS, CORS_ORIGINS
from core.middleware import IPFilterMiddleware


# FastAPI 앱 생성
app = FastAPI(
    title="KISA Security Dashboard API",
    description="KISA 보안 점검 프로젝트 REST API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


# =============================================================================
# 미들웨어 설정
# =============================================================================

# CORS 미들웨어 (가장 먼저 - 모든 응답에 헤더 추가)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,  # React 개발 서버 허용
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# IP 필터링 미들웨어
if ALLOWED_CIDRS:
    cidrs_str = ",".join(ALLOWED_CIDRS)
    app.add_middleware(IPFilterMiddleware, allowed_cidrs=cidrs_str)


# =============================================================================
# 라우터 등록
# =============================================================================

# 인증 API
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])

# 자산 관리 API
app.include_router(assets.router, prefix="/api/assets", tags=["Assets"])

# 전수 점검 API
app.include_router(scan.router, prefix="/api/scan", tags=["Scan"])

# 대시보드 API
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])

# 자산 분석 API
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])

# 자동조치 API
app.include_router(fix.router, prefix="/api/fix", tags=["Fix"])

# 예외 처리 API
app.include_router(exceptions.router, prefix="/api/exceptions", tags=["Exceptions"])

# 보고서 생성 API
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


# =============================================================================
# 헬스 체크
# =============================================================================

@app.get("/health")
def health_check():
    """API 헬스 체크"""
    return {
        "status": "healthy",
        "service": "KISA Security Dashboard API"
    }


@app.get("/")
def root():
    """루트 엔드포인트"""
    return {
        "message": "KISA Security Dashboard API",
        "version": "1.0.0",
        "docs": "/docs"
    }
