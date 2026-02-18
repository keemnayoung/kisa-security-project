"""
자동조치 서비스
"""

import json
import os
import requests
import time
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from db.models import Server, ScanHistory, KisaItem, RemediationLog

# 조치 대상 item_codes / server_id를 Ansible에 전달하기 위한 파일 경로
FIX_ITEM_CODES_FILE = "/tmp/audit/fix_item_codes.json"
FIX_TARGET_SERVER_FILE = "/tmp/audit/fix_target_server.json"


# Job API 엔드포인트
JOB_API_URL = "http://localhost:8001"

# Job별 조치 정보 저장 (job_id → {server_id(s), item_codes, os_job_id, db_job_id})
_job_fix_info: dict[str, dict] = {}


def get_affected_servers(item_codes: List[str], company: str, db: Session) -> dict:
    """
    주어진 item_codes가 취약한 서버 목록을 반환

    Args:
        item_codes: 점검 항목 코드 목록
        company: 회사 스코프
        db: DB 세션

    Returns:
        {"item_codes", "servers": [...], "total_servers", "total_fixable"}
    """
    # ScanHistory + Server + KisaItem JOIN: 취약 + auto_fix 가능 항목만
    rows = db.query(
        ScanHistory.server_id,
        ScanHistory.item_code,
        Server.hostname,
        Server.ip_address,
        Server.os_type,
    ).join(
        Server, ScanHistory.server_id == Server.server_id
    ).join(
        KisaItem, ScanHistory.item_code == KisaItem.item_code
    ).filter(
        ScanHistory.item_code.in_(item_codes),
        ScanHistory.status == '취약',
        KisaItem.auto_fix == True,
        Server.is_active == True,
        Server.company == company,
    ).all()

    # 서버별 취약 항목 그룹핑
    server_map: dict[str, dict] = {}
    for row in rows:
        sid = row.server_id
        if sid not in server_map:
            server_map[sid] = {
                "server_id": sid,
                "hostname": row.hostname,
                "ip_address": row.ip_address,
                "os_type": row.os_type,
                "vulnerable_items": [],
            }
        if row.item_code not in server_map[sid]["vulnerable_items"]:
            server_map[sid]["vulnerable_items"].append(row.item_code)

    servers = []
    total_fixable = 0
    for info in server_map.values():
        info["vulnerable_count"] = len(info["vulnerable_items"])
        total_fixable += info["vulnerable_count"]
        servers.append(info)

    # server_id 기준 정렬
    servers.sort(key=lambda s: s["server_id"])

    return {
        "item_codes": item_codes,
        "servers": servers,
        "total_servers": len(servers),
        "total_fixable": total_fixable,
    }


def start_batch_fix(server_ids: List[str], item_codes: List[str], db: Session) -> Tuple[str, int]:
    """
    다중 서버 일괄 자동조치 시작

    Args:
        server_ids: 서버 ID 목록
        item_codes: 조치할 항목 코드 목록
        db: DB 세션

    Returns:
        (job_id, total_items)
    """
    if not server_ids:
        raise ValueError("조치할 서버가 없습니다")
    if not item_codes:
        raise ValueError("조치할 항목이 없습니다")

    # 모든 서버 존재/활성 검증
    active_servers = db.query(Server).filter(
        Server.server_id.in_(server_ids),
        Server.is_active == True
    ).all()
    active_ids = {s.server_id for s in active_servers}

    missing = [sid for sid in server_ids if sid not in active_ids]
    if missing:
        raise ValueError(f"서버를 찾을 수 없습니다: {', '.join(missing)}")

    # 서버별 실제 취약 항목 필터링
    vuln_rows = db.query(
        ScanHistory.server_id,
        ScanHistory.item_code
    ).filter(
        ScanHistory.server_id.in_(server_ids),
        ScanHistory.item_code.in_(item_codes),
        ScanHistory.status == '취약'
    ).all()

    per_server: dict[str, list] = {}
    all_codes_set: set = set()
    for row in vuln_rows:
        per_server.setdefault(row.server_id, [])
        if row.item_code not in per_server[row.server_id]:
            per_server[row.server_id].append(row.item_code)
            all_codes_set.add(row.item_code)

    if not all_codes_set:
        raise ValueError("조치할 취약 항목이 없습니다 (모든 항목이 이미 양호 상태)")

    # 실제 취약 항목이 있는 서버만 남김
    effective_server_ids = [sid for sid in server_ids if sid in per_server]
    if not effective_server_ids:
        raise ValueError("조치할 취약 항목이 있는 서버가 없습니다")

    all_codes = list(all_codes_set)

    # OS(U-*) / DB(D-*) 분리
    os_items = [c for c in all_codes if c.startswith("U-")]
    db_items = [c for c in all_codes if c.startswith("D-") or c.startswith("PG-D-") or c.startswith("MY-D-")]

    os_job_id = None
    db_job_id = None
    primary_job_id = None

    try:
        # 조치 대상 파일 저장
        os.makedirs("/tmp/audit", exist_ok=True)
        with open(FIX_TARGET_SERVER_FILE, "w") as f:
            json.dump({"server_ids": effective_server_ids}, f)
        with open(FIX_ITEM_CODES_FILE, "w") as f:
            json.dump(all_codes, f)

        # OS 조치 항목이 있으면 fix 작업 실행
        if os_items:
            response = requests.post(f"{JOB_API_URL}/jobs/fix", timeout=5)
            response.raise_for_status()
            job_data = response.json()
            os_job_id = job_data["job"]["job_id"]
            primary_job_id = os_job_id

        # DB 조치 항목이 있으면 fix-db 작업 실행
        if db_items:
            response = requests.post(f"{JOB_API_URL}/jobs/fix-db", timeout=5)
            response.raise_for_status()
            job_data = response.json()
            db_job_id = job_data["job"]["job_id"]
            if not primary_job_id:
                primary_job_id = db_job_id

        if not primary_job_id:
            raise ValueError("조치할 항목이 없습니다")

        # 총 조치 건수 = 서버별 취약 항목 수 합계
        total_items = sum(len(codes) for codes in per_server.values()
                         if any(c in all_codes_set for c in codes))

        # 조치 정보 저장
        _job_fix_info[primary_job_id] = {
            "server_ids": effective_server_ids,
            "server_id": effective_server_ids[0],  # 하위 호환
            "item_codes": all_codes,
            "per_server": per_server,
            "os_job_id": os_job_id,
            "db_job_id": db_job_id,
        }

        return primary_job_id, total_items

    except requests.RequestException as e:
        raise RuntimeError(f"조치 작업 실행 실패: {str(e)}")


def start_fix(server_id: str, item_codes: List[str], db: Session) -> Tuple[str, int]:
    """
    자동조치 시작 (단일 서버)

    Args:
        server_id: 서버 ID
        item_codes: 조치할 항목 코드 목록
        db: 데이터베이스 세션

    Returns:
        (job_id, total_items)
    """
    # 서버 존재 확인
    server = db.query(Server).filter(
        Server.server_id == server_id,
        Server.is_active == True
    ).first()

    if not server:
        raise ValueError("서버를 찾을 수 없습니다")

    if not item_codes:
        raise ValueError("조치할 항목이 없습니다")

    # 실제 '취약' 상태인 항목만 필터링 (이미 양호한 항목 조치 방지)
    vulnerable_items = db.query(ScanHistory.item_code).filter(
        ScanHistory.server_id == server_id,
        ScanHistory.item_code.in_(item_codes),
        ScanHistory.status == '취약'
    ).all()
    vulnerable_codes = {r.item_code for r in vulnerable_items}

    # 요청된 항목 중 실제 취약한 것만 남김
    filtered_codes = [c for c in item_codes if c in vulnerable_codes]
    if not filtered_codes:
        raise ValueError("조치할 취약 항목이 없습니다 (모든 항목이 이미 양호 상태)")

    item_codes = filtered_codes

    # OS(U-*) / DB(D-*) 분리
    os_items = [c for c in item_codes if c.startswith("U-")]
    db_items = [c for c in item_codes if c.startswith("D-") or c.startswith("PG-D-") or c.startswith("MY-D-")]

    os_job_id = None
    db_job_id = None
    primary_job_id = None

    try:
        # 조치 대상 server_id + item_codes를 파일에 저장 (run.sh / Ansible에서 사용)
        os.makedirs("/tmp/audit", exist_ok=True)
        with open(FIX_TARGET_SERVER_FILE, "w") as f:
            json.dump({"server_id": server_id}, f)
        with open(FIX_ITEM_CODES_FILE, "w") as f:
            json.dump(item_codes, f)

        # OS 조치 항목이 있으면 fix 작업 실행
        if os_items:
            response = requests.post(f"{JOB_API_URL}/jobs/fix", timeout=5)
            response.raise_for_status()
            job_data = response.json()
            os_job_id = job_data["job"]["job_id"]
            primary_job_id = os_job_id

        # DB 조치 항목이 있으면 fix-db 작업 실행
        if db_items:
            response = requests.post(f"{JOB_API_URL}/jobs/fix-db", timeout=5)
            response.raise_for_status()
            job_data = response.json()
            db_job_id = job_data["job"]["job_id"]
            if not primary_job_id:
                primary_job_id = db_job_id

        if not primary_job_id:
            raise ValueError("조치할 항목이 없습니다")

        # 조치 정보 저장
        _job_fix_info[primary_job_id] = {
            "server_id": server_id,
            "server_ids": [server_id],
            "item_codes": item_codes,
            "per_server": {server_id: item_codes},
            "os_job_id": os_job_id,
            "db_job_id": db_job_id,
        }

        return primary_job_id, len(item_codes)

    except requests.RequestException as e:
        raise RuntimeError(f"조치 작업 실행 실패: {str(e)}")


def get_fix_progress(job_id: str) -> dict:
    """
    조치 진행률 조회

    Args:
        job_id: Job ID

    Returns:
        진행 상황 정보
    """
    fix_info = _job_fix_info.get(job_id, {})
    os_job_id = fix_info.get("os_job_id")
    db_job_id = fix_info.get("db_job_id")

    # 두 job이 모두 있는 경우 결합
    jobs_to_check = []
    if os_job_id:
        jobs_to_check.append(os_job_id)
    if db_job_id and db_job_id != os_job_id:
        jobs_to_check.append(db_job_id)

    if not jobs_to_check:
        jobs_to_check = [job_id]

    try:
        combined_progress = 0
        all_completed = True
        any_failed = False

        for jid in jobs_to_check:
            response = requests.get(f"{JOB_API_URL}/jobs/{jid}", timeout=5)
            response.raise_for_status()
            job = response.json()

            status = job.get("status", "queued")
            if status == "success":
                status = "completed"

            if status != "completed":
                all_completed = False
            if status == "failed":
                any_failed = True

            # 진행률 계산
            if status == "completed":
                combined_progress += 100
            elif status == "running":
                started_at = job.get("started_at", 0)
                if started_at:
                    elapsed = time.time() - started_at
                    estimated_duration = 60
                    combined_progress += min(int((elapsed / estimated_duration) * 95), 95)
                else:
                    combined_progress += 10
            else:
                combined_progress += 0

        total_jobs = len(jobs_to_check)
        progress = combined_progress // total_jobs if total_jobs > 0 else 0

        if any_failed:
            final_status = "failed"
        elif all_completed:
            final_status = "completed"
            progress = 100
        elif progress > 0:
            final_status = "running"
        else:
            final_status = "queued"

        return {
            "job_id": job_id,
            "status": final_status,
            "progress": progress,
            "message": _get_fix_progress_message(final_status, progress),
            "total_items": len(fix_info.get("item_codes", []))
        }

    except requests.RequestException as e:
        return {
            "job_id": job_id,
            "status": "failed",
            "progress": 0,
            "message": f"진행 상황 조회 실패: {str(e)}",
            "total_items": len(fix_info.get("item_codes", []))
        }


def get_fix_result(job_id: str, db: Session) -> Optional[dict]:
    """
    조치 결과 조회 (단일/다중 서버 모두 지원)

    Args:
        job_id: Job ID
        db: 데이터베이스 세션

    Returns:
        조치 결과 요약 (servers 필드 포함)
    """
    fix_info = _job_fix_info.get(job_id, {})
    server_ids = fix_info.get("server_ids", [])
    item_codes = fix_info.get("item_codes", [])

    # 하위 호환: server_ids가 없으면 server_id 사용
    if not server_ids:
        single_id = fix_info.get("server_id")
        if single_id:
            server_ids = [single_id]

    if not server_ids or not item_codes:
        return None

    # 진행 상태 확인
    progress = get_fix_progress(job_id)
    if progress["status"] != "completed":
        return None

    # 최근 10분 이내 조치 결과 조회 (모든 서버)
    time_threshold = datetime.now() - timedelta(minutes=10)

    results = db.query(
        RemediationLog.server_id,
        RemediationLog.item_code,
        RemediationLog.is_success,
        RemediationLog.failure_reason,
        RemediationLog.raw_evidence,
        RemediationLog.action_date,
        KisaItem.title,
        Server.hostname,
    ).join(
        KisaItem, RemediationLog.item_code == KisaItem.item_code
    ).join(
        Server, RemediationLog.server_id == Server.server_id
    ).filter(
        RemediationLog.server_id.in_(server_ids),
        RemediationLog.item_code.in_(item_codes),
        RemediationLog.action_date >= time_threshold
    ).order_by(
        RemediationLog.server_id,
        RemediationLog.item_code
    ).all()

    # flat 리스트 + 서버별 그룹핑
    all_items = []
    per_server_results: dict[str, dict] = {}
    total_success = 0
    total_fail = 0

    for r in results:
        item_dict = {
            "item_code": r.item_code,
            "title": r.title,
            "is_success": r.is_success,
            "failure_reason": r.failure_reason,
            "raw_evidence": r.raw_evidence or "",
            "action_date": r.action_date.strftime("%Y-%m-%d %H:%M") if r.action_date else ""
        }
        all_items.append(item_dict)

        if r.is_success:
            total_success += 1
        else:
            total_fail += 1

        # 서버별 그룹핑
        if r.server_id not in per_server_results:
            per_server_results[r.server_id] = {
                "server_id": r.server_id,
                "hostname": r.hostname,
                "total_items": 0,
                "success_count": 0,
                "fail_count": 0,
                "items": []
            }
        srv = per_server_results[r.server_id]
        srv["items"].append(item_dict)
        srv["total_items"] += 1
        if r.is_success:
            srv["success_count"] += 1
        else:
            srv["fail_count"] += 1

    # 서버별 결과 정렬
    servers_list = sorted(per_server_results.values(), key=lambda s: s["server_id"])

    # 총 조치 대상 건수
    per_server_info = fix_info.get("per_server", {})
    total_target = sum(len(codes) for codes in per_server_info.values()) if per_server_info else len(item_codes)
    before_vuln = total_target
    after_vuln = before_vuln - total_success

    return {
        "job_id": job_id,
        "total_items": total_target,
        "success_count": total_success,
        "fail_count": total_fail,
        "servers": servers_list,
        "items": all_items,
        "improvement": {
            "before_vuln": before_vuln,
            "after_vuln": max(after_vuln, 0),
            "improved": total_success
        }
    }


def _get_fix_progress_message(status: str, progress: int) -> str:
    """진행 상황 메시지 생성"""
    if status == "queued":
        return "조치 대기 중입니다"
    elif status == "running":
        if progress < 30:
            return "보안 설정을 변경하고 있습니다"
        elif progress < 70:
            return "조치 항목을 적용하고 있습니다"
        else:
            return "조치 결과를 확인하고 있습니다"
    elif status == "completed":
        return "조치가 완료되었습니다"
    elif status == "failed":
        return "조치 중 오류가 발생했습니다"
    else:
        return "조치 진행 중"
