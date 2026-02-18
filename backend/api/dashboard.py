"""
대시보드 API
- GET /api/dashboard/data: 메인 대시보드 전체 데이터
"""

from fastapi import APIRouter, Depends
from sqlalchemy import func, case, distinct
from sqlalchemy.orm import Session

from db.session import get_db
from db.models import User, Server, ScanHistory, KisaItem
from core.deps import get_current_user


router = APIRouter()


@router.get("/data")
async def get_dashboard_data(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    메인 대시보드 전체 데이터 조회
    UPSERT 방식이므로 (server_id, item_code) 당 1행만 존재 → time_threshold 불필요
    """
    company = current_user.company

    # ===== 1. 상단 정보 =====

    # 최근 점검 시간 (모든 점검 이력에서 가장 최근 것)
    last_scan = db.query(func.max(ScanHistory.scan_date)).join(
        Server, ScanHistory.server_id == Server.server_id
    ).filter(
        Server.company == company,
        Server.is_active == True
    ).scalar()

    # 점검한 서버 개수
    total_servers = db.query(func.count(distinct(Server.id))).filter(
        Server.company == company,
        Server.is_active == True
    ).scalar() or 0

    # OS 버전 정보 (가장 많이 사용하는 버전 2개)
    os_versions = db.query(
        Server.os_type,
        func.count(Server.id).label("count")
    ).filter(
        Server.company == company,
        Server.is_active == True
    ).group_by(
        Server.os_type
    ).order_by(
        func.count(Server.id).desc()
    ).limit(2).all()

    # DB 버전 정보 (가장 많이 사용하는 버전 2개)
    db_versions = db.query(
        Server.db_type,
        func.count(Server.id).label("count")
    ).filter(
        Server.company == company,
        Server.is_active == True,
        Server.db_type.isnot(None)
    ).group_by(
        Server.db_type
    ).order_by(
        func.count(Server.id).desc()
    ).limit(2).all()

    os_info = " • ".join([v.os_type for v in os_versions]) if os_versions else "N/A"
    db_info = " • ".join([v.db_type for v in db_versions]) if db_versions else "N/A"

    # ===== 2. OS 보안 카테고리 =====
    os_categories_raw = db.query(
        KisaItem.category,
        func.count(ScanHistory.scan_id).label("count")
    ).join(
        ScanHistory, KisaItem.item_code == ScanHistory.item_code
    ).join(
        Server, ScanHistory.server_id == Server.server_id
    ).filter(
        Server.company == company,
        Server.is_active == True,
        ScanHistory.status == "취약",
        KisaItem.item_code.like("U-%"),
        KisaItem.category != "unknown"
    ).group_by(
        KisaItem.category
    ).all()

    os_categories = {
        "account": 0,
        "directory": 0,
        "service": 0,
        "patch": 0,
        "log": 0
    }
    for cat in os_categories_raw:
        if cat.category in os_categories:
            os_categories[cat.category] = cat.count

    # ===== 3. DB 보안 카테고리 =====
    db_categories_raw = db.query(
        KisaItem.category,
        func.count(ScanHistory.scan_id).label("count")
    ).join(
        ScanHistory, KisaItem.item_code == ScanHistory.item_code
    ).join(
        Server, ScanHistory.server_id == Server.server_id
    ).filter(
        Server.company == company,
        Server.is_active == True,
        ScanHistory.status == "취약",
        KisaItem.item_code.like("D-%"),
        KisaItem.category != "unknown"
    ).group_by(
        KisaItem.category
    ).all()

    # 카테고리 매핑 (한글/영문 모두 지원)
    category_mapping = {
        "계정관리": "account", "account": "account",
        "접근관리": "access",  "access": "access",
        "패치관리": "patch",   "patch": "patch",
        "옵션관리": "option",  "option": "option"
    }

    db_categories = {
        "account": 0,
        "access": 0,
        "patch": 0,
        "option": 0
    }
    for cat in db_categories_raw:
        eng_cat = category_mapping.get(cat.category)
        if eng_cat and eng_cat in db_categories:
            db_categories[eng_cat] = cat.count

    # ===== 4. 미해결 취약점 =====
    unresolved_count = db.query(func.count(ScanHistory.scan_id)).join(
        Server, ScanHistory.server_id == Server.server_id
    ).join(
        KisaItem, ScanHistory.item_code == KisaItem.item_code
    ).filter(
        Server.company == company,
        Server.is_active == True,
        ScanHistory.status == "취약",
        KisaItem.category != "unknown"
    ).scalar() or 0

    # ===== 5. OS 보안 취약 서버 TOP 5 =====
    os_top_servers = db.query(
        Server.server_id,
        Server.hostname,
        Server.ip_address,
        func.count(ScanHistory.scan_id).label("vuln_count")
    ).join(
        ScanHistory, Server.server_id == ScanHistory.server_id
    ).join(
        KisaItem, ScanHistory.item_code == KisaItem.item_code
    ).filter(
        Server.company == company,
        Server.is_active == True,
        ScanHistory.status == "취약",
        KisaItem.item_code.like("U-%"),
        KisaItem.category != "unknown"
    ).group_by(
        Server.server_id, Server.hostname, Server.ip_address
    ).order_by(
        func.count(ScanHistory.scan_id).desc()
    ).limit(5).all()

    # ===== 6. DB 보안 취약 서버 TOP 5 =====
    db_top_servers = db.query(
        Server.server_id,
        Server.hostname,
        Server.ip_address,
        func.count(ScanHistory.scan_id).label("vuln_count")
    ).join(
        ScanHistory, Server.server_id == ScanHistory.server_id
    ).join(
        KisaItem, ScanHistory.item_code == KisaItem.item_code
    ).filter(
        Server.company == company,
        Server.is_active == True,
        ScanHistory.status == "취약",
        KisaItem.item_code.like("D-%"),
        KisaItem.category != "unknown"
    ).group_by(
        Server.server_id, Server.hostname, Server.ip_address
    ).order_by(
        func.count(ScanHistory.scan_id).desc()
    ).limit(5).all()

    # ===== 7. 리스크 분포 (저/중/고) =====
    risk_dist_raw = db.query(
        func.sum(case((KisaItem.severity == "상", 1), else_=0)).label("high"),
        func.sum(case((KisaItem.severity == "중", 1), else_=0)).label("medium"),
        func.sum(case((KisaItem.severity == "하", 1), else_=0)).label("low")
    ).join(
        ScanHistory, KisaItem.item_code == ScanHistory.item_code
    ).join(
        Server, ScanHistory.server_id == Server.server_id
    ).filter(
        Server.company == company,
        Server.is_active == True,
        ScanHistory.status == "취약",
        KisaItem.category != "unknown"
    ).first()

    high_count = int(risk_dist_raw.high or 0)
    medium_count = int(risk_dist_raw.medium or 0)
    low_count = int(risk_dist_raw.low or 0)
    total_risk = high_count + medium_count + low_count

    if total_risk > 0:
        risk_distribution = {
            "low": low_count,
            "medium": medium_count,
            "high": high_count,
            "low_percent": int(low_count / total_risk * 100),
            "medium_percent": int(medium_count / total_risk * 100),
            "high_percent": int(high_count / total_risk * 100),
            "total": total_risk
        }
    else:
        risk_distribution = {
            "low": 0, "medium": 0, "high": 0,
            "low_percent": 0, "medium_percent": 0, "high_percent": 0,
            "total": 0
        }

    # ===== 8. 양호/위험 비율 =====
    vuln_stats = db.query(
        func.sum(case((ScanHistory.status == "취약", 1), else_=0)).label("vulnerable"),
        func.sum(case((ScanHistory.status == "양호", 1), else_=0)).label("secure")
    ).join(
        Server, ScanHistory.server_id == Server.server_id
    ).join(
        KisaItem, ScanHistory.item_code == KisaItem.item_code
    ).filter(
        Server.company == company,
        Server.is_active == True,
        KisaItem.category != "unknown"
    ).first()

    vulnerable_count = int(vuln_stats.vulnerable or 0)
    secure_count = int(vuln_stats.secure or 0)
    total_checks = vulnerable_count + secure_count

    if total_checks > 0:
        vulnerability_ratio = {
            "vulnerable": vulnerable_count,
            "secure": secure_count,
            "vulnerable_percent": int(vulnerable_count / total_checks * 100),
            "secure_percent": int(secure_count / total_checks * 100),
            "total": total_checks
        }
    else:
        vulnerability_ratio = {
            "vulnerable": 0, "secure": 0,
            "vulnerable_percent": 0, "secure_percent": 0,
            "total": 0
        }

    # ===== 응답 =====
    return {
        "summary": {
            "company": company,
            "last_scan_date": last_scan.strftime("%Y-%m-%d %H:%M:%S") if last_scan else "N/A",
            "total_servers": total_servers,
            "os_info": os_info,
            "db_info": db_info
        },
        "os_categories": os_categories,
        "db_categories": db_categories,
        "unresolved_count": unresolved_count,
        "os_top_servers": [
            {
                "rank": idx + 1,
                "server_id": s.server_id,
                "hostname": s.hostname,
                "ip_address": s.ip_address,
                "vuln_count": s.vuln_count
            }
            for idx, s in enumerate(os_top_servers)
        ],
        "db_top_servers": [
            {
                "rank": idx + 1,
                "server_id": s.server_id,
                "hostname": s.hostname,
                "ip_address": s.ip_address,
                "vuln_count": s.vuln_count
            }
            for idx, s in enumerate(db_top_servers)
        ],
        "risk_distribution": risk_distribution,
        "vulnerability_ratio": vulnerability_ratio
    }
