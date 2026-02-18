"""
자산 분석 API
- GET /api/analysis/servers: 서버 목록 + 양호/취약 개수
- GET /api/analysis/servers/{server_id}/results: 서버별 점검 결과 (카테고리별)
- GET /api/analysis/servers/{server_id}/remediation: 서버별 조치 이력 (카테고리별)
"""

import json
import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from db.session import get_db
from datetime import datetime
from db.models import User, Server, ScanHistory, KisaItem, RemediationLog, Exception as ExceptionModel
from core.deps import get_current_user


router = APIRouter()


def _extract_field_from_evidence(raw: str, field: str) -> str:
    """raw_evidence JSON에서 특정 필드 추출 (다단계 파싱)"""
    if not raw:
        return ""

    # 1차: 직접 JSON 파싱
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and parsed.get(field):
            return str(parsed[field])
        # 이중 인코딩 시도
        if isinstance(parsed, str):
            try:
                inner = json.loads(parsed)
                if isinstance(inner, dict) and inner.get(field):
                    return str(inner[field])
            except Exception:
                pass
    except Exception:
        pass

    # 2차: 이스케이프된 JSON에서 필드 추출
    escaped_pattern = rf'\\"{field}\\"\s*:\s*\\"([\s\S]*?)\\"'
    match = re.search(escaped_pattern, raw)
    if match:
        return match.group(1).replace("\\n", "\n").replace("\\t", "\t")

    # 3차: 일반 JSON에서 필드 추출
    normal_pattern = rf'"{field}"\s*:\s*"((?:[^"\\]|\\.)*)"'
    match = re.search(normal_pattern, raw)
    if match:
        return match.group(1).replace("\\n", "\n").replace('\\"', '"')

    return ""


@router.get("/servers")
async def get_analysis_servers(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """서버 목록 + 양호/취약 개수 조회"""
    company = current_user.company

    # 모든 서버 조회
    servers = db.query(Server).filter(
        Server.company == company
    ).order_by(Server.hostname).all()

    # UPSERT 방식이므로 (server_id, item_code) 당 1행만 존재 → 바로 집계
    vuln_stats = db.query(
        ScanHistory.server_id,
        func.sum(case((ScanHistory.status == "양호", 1), else_=0)).label("secure_count"),
        func.sum(case((ScanHistory.status == "취약", 1), else_=0)).label("vulnerable_count")
    ).join(
        KisaItem, ScanHistory.item_code == KisaItem.item_code
    ).filter(
        KisaItem.category != "unknown"
    ).group_by(
        ScanHistory.server_id
    ).all()

    stats_map = {
        s.server_id: {
            "secure_count": int(s.secure_count or 0),
            "vulnerable_count": int(s.vulnerable_count or 0)
        }
        for s in vuln_stats
    }

    # 서버별 활성 예외 개수
    now = datetime.now()
    exception_counts = db.query(
        ExceptionModel.server_id,
        func.count(ExceptionModel.exception_id).label("exception_count")
    ).filter(
        ExceptionModel.valid_date > now
    ).group_by(
        ExceptionModel.server_id
    ).all()
    exception_map = {e.server_id: int(e.exception_count) for e in exception_counts}

    return [
        {
            "server_id": s.server_id,
            "hostname": s.hostname,
            "ip_address": s.ip_address,
            "os_type": s.os_type,
            "db_type": s.db_type,
            "is_active": s.is_active,
            "secure_count": stats_map.get(s.server_id, {}).get("secure_count", 0),
            "vulnerable_count": stats_map.get(s.server_id, {}).get("vulnerable_count", 0),
            "exception_count": exception_map.get(s.server_id, 0)
        }
        for s in servers
    ]


@router.get("/servers/{server_id}/results")
async def get_server_results(
    server_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """서버별 점검 결과 (카테고리별 그룹핑)"""
    company = current_user.company

    # 서버 확인
    server = db.query(Server).filter(
        Server.server_id == server_id,
        Server.company == company
    ).first()

    if not server:
        raise HTTPException(status_code=404, detail="서버를 찾을 수 없습니다")

    # UPSERT 방식이므로 (server_id, item_code) 당 1행 → 바로 조회
    results = db.query(
        ScanHistory.item_code,
        ScanHistory.status,
        ScanHistory.raw_evidence,
        ScanHistory.scan_date,
        KisaItem.category,
        KisaItem.title,
        KisaItem.auto_fix,
        KisaItem.severity,
        KisaItem.guide,
        KisaItem.auto_fix_description
    ).join(
        KisaItem, ScanHistory.item_code == KisaItem.item_code
    ).filter(
        ScanHistory.server_id == server_id,
        KisaItem.category != "unknown"
    ).order_by(
        ScanHistory.item_code
    ).all()

    # 활성 예외 항목 조회
    now = datetime.now()
    active_exceptions = db.query(ExceptionModel.item_code).filter(
        ExceptionModel.server_id == server_id,
        ExceptionModel.valid_date > now
    ).all()
    exception_item_codes = {e.item_code for e in active_exceptions}

    # OS / DB 분리 및 카테고리별 그룹핑
    os_categories = {
        "account": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
        "directory": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
        "service": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
        "patch": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
        "log": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
    }

    db_categories = {
        "account": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
        "access": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
        "option": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
        "patch": {"secure_count": 0, "vulnerable_count": 0, "exception_count": 0, "items": []},
    }

    for r in results:
        # raw_evidence에서 guide 파싱, 없으면 KisaItem.guide 폴백
        evidence_guide = _extract_field_from_evidence(r.raw_evidence, "guide")
        guide = evidence_guide if evidence_guide else (r.guide or "")

        # 예외 상태 오버레이
        has_exception = r.item_code in exception_item_codes
        display_status = "예외" if has_exception and r.status == "취약" else r.status

        item = {
            "item_code": r.item_code,
            "title": r.title,
            "status": display_status,
            "has_exception": has_exception,
            "auto_fix": r.auto_fix,
            "severity": r.severity,
            "raw_evidence": r.raw_evidence,
            "scan_date": r.scan_date.strftime("%Y-%m-%d %H:%M") if r.scan_date else "",
            "guide": guide,
            "auto_fix_description": r.auto_fix_description or ""
        }

        if r.item_code.startswith("U-"):
            cat = r.category
            if cat in os_categories:
                os_categories[cat]["items"].append(item)
                if display_status == "예외":
                    os_categories[cat]["exception_count"] += 1
                    os_categories[cat]["secure_count"] += 1
                elif r.status == "양호":
                    os_categories[cat]["secure_count"] += 1
                else:
                    os_categories[cat]["vulnerable_count"] += 1
        elif r.item_code.startswith("D-") or r.item_code.startswith("PG-D-") or r.item_code.startswith("MY-D-"):
            cat = r.category
            if cat in db_categories:
                db_categories[cat]["items"].append(item)
                if display_status == "예외":
                    db_categories[cat]["exception_count"] += 1
                    db_categories[cat]["secure_count"] += 1
                elif r.status == "양호":
                    db_categories[cat]["secure_count"] += 1
                else:
                    db_categories[cat]["vulnerable_count"] += 1

    return {
        "server_info": {
            "server_id": server.server_id,
            "hostname": server.hostname,
            "ip_address": server.ip_address,
            "os_type": server.os_type,
            "db_type": server.db_type,
            "is_active": server.is_active
        },
        "os_results": os_categories,
        "db_results": db_categories
    }


@router.get("/servers/{server_id}/remediation")
async def get_server_remediation(
    server_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """서버별 조치 이력 (카테고리별 그룹핑)"""
    company = current_user.company

    # 서버 확인
    server = db.query(Server).filter(
        Server.server_id == server_id,
        Server.company == company
    ).first()

    if not server:
        raise HTTPException(status_code=404, detail="서버를 찾을 수 없습니다")

    # item_code별 최신 log_id 서브쿼리
    latest_logs = db.query(
        func.max(RemediationLog.log_id).label("max_log_id")
    ).filter(
        RemediationLog.server_id == server_id
    ).group_by(
        RemediationLog.item_code
    ).subquery()

    results = db.query(
        RemediationLog.item_code,
        RemediationLog.is_success,
        RemediationLog.failure_reason,
        RemediationLog.raw_evidence,
        RemediationLog.action_date,
        KisaItem.category,
        KisaItem.title,
        KisaItem.severity,
        KisaItem.auto_fix
    ).join(
        KisaItem, RemediationLog.item_code == KisaItem.item_code
    ).filter(
        RemediationLog.log_id.in_(db.query(latest_logs.c.max_log_id))
    ).order_by(
        RemediationLog.item_code
    ).all()

    # OS / DB 분리 및 카테고리별 그룹핑
    os_categories = {
        "account": {"success_count": 0, "fail_count": 0, "items": []},
        "directory": {"success_count": 0, "fail_count": 0, "items": []},
        "service": {"success_count": 0, "fail_count": 0, "items": []},
        "patch": {"success_count": 0, "fail_count": 0, "items": []},
        "log": {"success_count": 0, "fail_count": 0, "items": []},
    }

    db_categories = {
        "account": {"success_count": 0, "fail_count": 0, "items": []},
        "access": {"success_count": 0, "fail_count": 0, "items": []},
        "option": {"success_count": 0, "fail_count": 0, "items": []},
        "patch": {"success_count": 0, "fail_count": 0, "items": []},
    }

    for r in results:
        item = {
            "item_code": r.item_code,
            "title": r.title,
            "is_success": r.is_success,
            "failure_reason": r.failure_reason or "",
            "raw_evidence": r.raw_evidence or "",
            "action_date": r.action_date.strftime("%Y-%m-%d %H:%M") if r.action_date else "",
            "severity": r.severity,
            "auto_fix": r.auto_fix
        }

        if r.item_code.startswith("U-"):
            cat = r.category
            if cat in os_categories:
                os_categories[cat]["items"].append(item)
                if r.is_success:
                    os_categories[cat]["success_count"] += 1
                else:
                    os_categories[cat]["fail_count"] += 1
        elif r.item_code.startswith("D-") or r.item_code.startswith("PG-D-") or r.item_code.startswith("MY-D-"):
            cat = r.category
            if cat in db_categories:
                db_categories[cat]["items"].append(item)
                if r.is_success:
                    db_categories[cat]["success_count"] += 1
                else:
                    db_categories[cat]["fail_count"] += 1

    return {
        "os_results": os_categories,
        "db_results": db_categories
    }


@router.get("/history")
async def get_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """전체 점검 이력 + 조치 이력 (플랫 리스트)"""
    company = current_user.company

    # 해당 회사 서버 ID 목록
    server_ids = [
        s.server_id for s in
        db.query(Server.server_id).filter(Server.company == company).all()
    ]

    if not server_ids:
        return {"scans": [], "remediations": []}

    # 점검 이력 (scan_history는 UPSERT이므로 (server_id, item_code) 당 1행)
    scans = db.query(
        ScanHistory.scan_date,
        ScanHistory.server_id,
        ScanHistory.item_code,
        ScanHistory.status,
        KisaItem.title
    ).join(
        KisaItem, ScanHistory.item_code == KisaItem.item_code
    ).filter(
        ScanHistory.server_id.in_(server_ids),
        KisaItem.category != "unknown"
    ).order_by(
        ScanHistory.scan_date.desc()
    ).all()

    # 조치 이력 (전체 로그)
    remediations = db.query(
        RemediationLog.action_date,
        RemediationLog.server_id,
        RemediationLog.item_code,
        RemediationLog.is_success,
        KisaItem.title
    ).join(
        KisaItem, RemediationLog.item_code == KisaItem.item_code
    ).filter(
        RemediationLog.server_id.in_(server_ids)
    ).order_by(
        RemediationLog.action_date.desc()
    ).all()

    return {
        "scans": [
            {
                "scan_date": s.scan_date.strftime("%Y-%m-%d %H:%M") if s.scan_date else "",
                "server_id": s.server_id,
                "item_code": s.item_code,
                "title": s.title,
                "status": s.status
            }
            for s in scans
        ],
        "remediations": [
            {
                "action_date": r.action_date.strftime("%Y-%m-%d %H:%M") if r.action_date else "",
                "server_id": r.server_id,
                "item_code": r.item_code,
                "title": r.title,
                "is_success": r.is_success
            }
            for r in remediations
        ]
    }
