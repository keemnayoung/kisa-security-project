"""
자동조치 API
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Optional
from sqlalchemy.orm import Session

from core.deps import get_db, get_admin_user, get_current_user
from db.models import User
from services.fix_service import (
    start_fix, start_batch_fix,
    get_fix_progress, get_fix_result,
    get_affected_servers,
)


router = APIRouter()


# ── 스키마 ──────────────────────────────────────────

class FixExecuteRequest(BaseModel):
    """조치 실행 요청"""
    server_id: str = Field(..., description="서버 ID")
    item_codes: List[str] = Field(..., min_length=1, description="조치할 항목 코드 목록")


class BatchFixExecuteRequest(BaseModel):
    """일괄 조치 실행 요청 (다중 서버)"""
    server_ids: List[str] = Field(..., min_length=1, description="서버 ID 목록")
    item_codes: List[str] = Field(..., min_length=1, description="조치할 항목 코드 목록")


class AffectedServersRequest(BaseModel):
    """영향 받는 서버 조회 요청"""
    item_codes: List[str] = Field(..., min_length=1, description="점검 항목 코드 목록")


class FixProgressResponse(BaseModel):
    """조치 진행 상황 응답"""
    job_id: str
    status: str
    progress: int = Field(ge=0, le=100)
    message: str
    total_items: int


class FixResultItem(BaseModel):
    """조치 결과 항목"""
    item_code: str
    title: str
    is_success: bool
    failure_reason: Optional[str] = None
    raw_evidence: str
    action_date: str


class FixImprovement(BaseModel):
    """개선도"""
    before_vuln: int
    after_vuln: int
    improved: int


class FixResultServerInfo(BaseModel):
    """서버별 조치 결과"""
    server_id: str
    hostname: str
    total_items: int
    success_count: int
    fail_count: int
    items: List[FixResultItem]


class FixResultResponse(BaseModel):
    """조치 결과 응답 (단일/다중 서버 호환)"""
    job_id: str
    total_items: int
    success_count: int
    fail_count: int
    servers: List[FixResultServerInfo] = []
    items: List[FixResultItem]
    improvement: FixImprovement


class AffectedServerInfo(BaseModel):
    """영향 받는 서버 정보"""
    server_id: str
    hostname: str
    ip_address: str
    os_type: str
    vulnerable_items: List[str]
    vulnerable_count: int


class AffectedServersResponse(BaseModel):
    """영향 받는 서버 목록 응답"""
    item_codes: List[str]
    servers: List[AffectedServerInfo]
    total_servers: int
    total_fixable: int


# ── 엔드포인트 ──────────────────────────────────────

@router.post("/execute", status_code=status.HTTP_202_ACCEPTED)
async def execute_fix(
    request: FixExecuteRequest,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    자동조치 실행 (단일 서버)
    """
    try:
        job_id, total_items = start_fix(request.server_id, request.item_codes, db)

        return {
            "job_id": job_id,
            "total_items": total_items,
            "status": "queued",
            "message": "자동조치를 시작했습니다"
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/execute-batch", status_code=status.HTTP_202_ACCEPTED)
async def execute_batch_fix(
    request: BatchFixExecuteRequest,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    일괄 자동조치 실행 (다중 서버)
    """
    try:
        job_id, total_items = start_batch_fix(
            request.server_ids, request.item_codes, db
        )

        return {
            "job_id": job_id,
            "total_items": total_items,
            "status": "queued",
            "message": f"{len(request.server_ids)}대 서버에 일괄 자동조치를 시작했습니다"
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/affected-servers", response_model=AffectedServersResponse)
async def get_affected_servers_endpoint(
    request: AffectedServersRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """주어진 항목 코드에 대해 영향받는 서버 목록 조회"""
    result = get_affected_servers(request.item_codes, current_user.company, db)
    return AffectedServersResponse(**result)


@router.get("/progress/{job_id}", response_model=FixProgressResponse)
async def get_fix_progress_endpoint(
    job_id: str,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """조치 진행률 조회"""
    progress_data = get_fix_progress(job_id)

    return FixProgressResponse(
        job_id=job_id,
        status=progress_data["status"],
        progress=progress_data["progress"],
        message=progress_data["message"],
        total_items=progress_data.get("total_items", 0)
    )


@router.get("/result/{job_id}", response_model=FixResultResponse)
async def get_fix_result_endpoint(
    job_id: str,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """조치 결과 조회"""
    result = get_fix_result(job_id, db)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="조치가 완료되지 않았거나 결과를 찾을 수 없습니다"
        )

    return FixResultResponse(**result)
