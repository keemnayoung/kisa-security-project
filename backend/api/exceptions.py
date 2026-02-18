"""
예외 처리 API
- GET    /api/exceptions          : 예외 목록 조회
- POST   /api/exceptions          : 예외 등록 (단일 서버)
- POST   /api/exceptions/bulk     : 예외 등록 (전체 서버)
- DELETE /api/exceptions/{id}     : 예외 삭제
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.session import get_db
from db.models import User, Server, KisaItem, Exception as ExceptionModel
from core.deps import get_current_user, get_admin_user


router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────

class ExceptionCreate(BaseModel):
    server_id: str
    item_code: str
    reason: str = Field(..., min_length=1, max_length=500)
    valid_date: str  # "YYYY-MM-DD HH:MM:SS"


class ExceptionBulkCreate(BaseModel):
    item_code: str
    reason: str = Field(..., min_length=1, max_length=500)
    valid_date: str  # "YYYY-MM-DD HH:MM:SS"
    server_ids: Optional[List[str]] = None  # None이면 전체 서버


# ── Endpoints ────────────────────────────────────────────────

@router.get("")
async def get_exceptions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """예외 목록 조회 (회사별)"""
    company = current_user.company

    server_ids = [
        s.server_id for s in
        db.query(Server.server_id).filter(Server.company == company).all()
    ]

    if not server_ids:
        return {"total": 0, "active_count": 0, "expired_count": 0, "items": []}

    exceptions = db.query(
        ExceptionModel.exception_id,
        ExceptionModel.server_id,
        ExceptionModel.item_code,
        ExceptionModel.reason,
        ExceptionModel.valid_date,
        Server.hostname,
        Server.ip_address,
        KisaItem.title.label("item_title"),
        KisaItem.severity,
    ).join(
        Server, ExceptionModel.server_id == Server.server_id
    ).join(
        KisaItem, ExceptionModel.item_code == KisaItem.item_code
    ).filter(
        ExceptionModel.server_id.in_(server_ids)
    ).order_by(
        ExceptionModel.valid_date.desc()
    ).all()

    now = datetime.now()
    items = []
    active_count = 0
    expired_count = 0

    for e in exceptions:
        is_active = e.valid_date > now
        if is_active:
            active_count += 1
        else:
            expired_count += 1

        items.append({
            "exception_id": e.exception_id,
            "server_id": e.server_id,
            "hostname": e.hostname,
            "ip_address": e.ip_address,
            "item_code": e.item_code,
            "item_title": e.item_title,
            "severity": e.severity,
            "reason": e.reason,
            "valid_date": e.valid_date.strftime("%Y-%m-%d %H:%M"),
            "is_active": is_active,
        })

    return {
        "total": len(items),
        "active_count": active_count,
        "expired_count": expired_count,
        "items": items,
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_exception(
    request: ExceptionCreate,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """예외 등록 (단일 서버 + 항목)"""
    server = db.query(Server).filter(
        Server.server_id == request.server_id,
        Server.company == current_user.company
    ).first()
    if not server:
        raise HTTPException(status_code=404, detail="서버를 찾을 수 없습니다")

    item = db.query(KisaItem).filter(KisaItem.item_code == request.item_code).first()
    if not item:
        raise HTTPException(status_code=404, detail="점검 항목을 찾을 수 없습니다")

    existing = db.query(ExceptionModel).filter(
        ExceptionModel.server_id == request.server_id,
        ExceptionModel.item_code == request.item_code,
        ExceptionModel.valid_date > datetime.now()
    ).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail="해당 서버/항목에 이미 활성 예외가 존재합니다"
        )

    try:
        valid_date = datetime.strptime(request.valid_date, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise HTTPException(status_code=400, detail="날짜 형식이 올바르지 않습니다 (YYYY-MM-DD HH:MM:SS)")

    new_exception = ExceptionModel(
        server_id=request.server_id,
        item_code=request.item_code,
        reason=request.reason,
        valid_date=valid_date,
    )
    db.add(new_exception)
    db.commit()
    db.refresh(new_exception)

    return {
        "exception_id": new_exception.exception_id,
        "message": "예외가 등록되었습니다"
    }


@router.post("/bulk", status_code=status.HTTP_201_CREATED)
async def create_bulk_exception(
    request: ExceptionBulkCreate,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """예외 등록 (전체 서버 또는 선택한 서버에 동일 항목)"""
    item = db.query(KisaItem).filter(KisaItem.item_code == request.item_code).first()
    if not item:
        raise HTTPException(status_code=404, detail="점검 항목을 찾을 수 없습니다")

    query = db.query(Server).filter(
        Server.company == current_user.company,
        Server.is_active == True
    )
    if request.server_ids:
        query = query.filter(Server.server_id.in_(request.server_ids))

    servers = query.all()

    if not servers:
        raise HTTPException(status_code=404, detail="등록된 서버가 없습니다")

    try:
        valid_date = datetime.strptime(request.valid_date, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise HTTPException(status_code=400, detail="날짜 형식이 올바르지 않습니다 (YYYY-MM-DD HH:MM:SS)")

    now = datetime.now()
    created_count = 0
    skipped_count = 0

    for server in servers:
        existing = db.query(ExceptionModel).filter(
            ExceptionModel.server_id == server.server_id,
            ExceptionModel.item_code == request.item_code,
            ExceptionModel.valid_date > now
        ).first()
        if existing:
            skipped_count += 1
            continue

        new_exception = ExceptionModel(
            server_id=server.server_id,
            item_code=request.item_code,
            reason=request.reason,
            valid_date=valid_date,
        )
        db.add(new_exception)
        created_count += 1

    db.commit()

    return {
        "created_count": created_count,
        "skipped_count": skipped_count,
        "total_servers": len(servers),
        "message": f"{created_count}개 서버에 예외가 등록되었습니다"
    }


@router.delete("/{exception_id}")
async def delete_exception(
    exception_id: int,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """예외 삭제"""
    exception = db.query(ExceptionModel).filter(
        ExceptionModel.exception_id == exception_id
    ).first()

    if not exception:
        raise HTTPException(status_code=404, detail="예외를 찾을 수 없습니다")

    server = db.query(Server).filter(
        Server.server_id == exception.server_id,
        Server.company == current_user.company
    ).first()
    if not server:
        raise HTTPException(status_code=403, detail="권한이 없습니다")

    db.delete(exception)
    db.commit()

    return {"message": "예외가 삭제되었습니다"}
