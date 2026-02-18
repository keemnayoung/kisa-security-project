"""
전수 점검 API
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.deps import get_db, get_admin_user
from db.models import User
from schemas.scan import (
    FullScanRequest,
    ScanProgressResponse,
    ScanResultResponse
)
from services.scan_service import (
    start_full_scan,
    get_scan_progress,
    get_scan_result
)


router = APIRouter()


@router.post("/full", status_code=status.HTTP_202_ACCEPTED)
async def start_full_scan_endpoint(
    request: FullScanRequest,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    전수 점검 시작 (OS + DB)

    Args:
        request: 점검할 서버 ID 목록
        current_user: 현재 사용자 (ADMIN 권한 필요)
        db: 데이터베이스 세션

    Returns:
        Job ID와 점검 대상 서버 수
    """
    try:
        job_id, total_servers = start_full_scan(request.server_ids, db, request.scan_type)

        return {
            "job_id": job_id,
            "message": "전수 점검을 시작했습니다",
            "total_servers": total_servers,
            "status": "queued"
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


@router.get("/progress/{job_id}", response_model=ScanProgressResponse)
async def get_scan_progress_endpoint(
    job_id: str,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    점검 진행률 조회

    Args:
        job_id: Job ID
        current_user: 현재 사용자
        db: 데이터베이스 세션

    Returns:
        진행 상황 정보
    """
    progress_data = get_scan_progress(job_id)

    total_servers = progress_data.get("total_servers", 1)
    completed_servers = int(progress_data["progress"] / 100 * total_servers)

    return ScanProgressResponse(
        job_id=job_id,
        status=progress_data["status"],
        progress=progress_data["progress"],
        current_step=progress_data["current_step"],
        current_server=None,
        completed_servers=completed_servers,
        total_servers=total_servers,
        message=progress_data["message"]
    )


@router.get("/result/{job_id}", response_model=ScanResultResponse)
async def get_scan_result_endpoint(
    job_id: str,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    점검 결과 요약 조회

    Args:
        job_id: Job ID
        current_user: 현재 사용자
        db: 데이터베이스 세션

    Returns:
        점검 결과 요약
    """
    result = get_scan_result(job_id, current_user.company, db)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="점검이 완료되지 않았거나 결과를 찾을 수 없습니다"
        )

    return ScanResultResponse(**result)
