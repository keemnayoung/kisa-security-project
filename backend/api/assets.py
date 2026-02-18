"""
자산 관리 API 라우터
"""

import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.deps import get_db, get_admin_user
from db.models import User, Server, ScanHistory, RemediationLog, Exception
from schemas.asset import (
    ServerCreate,
    BulkServerCreate,
    ServerResponse,
    SSHTestRequest,
    DBPortTestRequest,
    DBLoginTestRequest
)
from services.asset_service import (
    test_ssh_connection,
    test_db_port,
    test_db_login,
    create_server
)

BACKEND_DIR = Path(__file__).resolve().parent.parent

router = APIRouter()


def _run_sync_inventory():
    """서버 등록/삭제 후 Ansible inventory 자동 갱신"""
    try:
        subprocess.Popen(
            ["python3", "sync_inventory.py"],
            cwd=str(BACKEND_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


@router.post("/test/ssh")
async def test_ssh(
    request: SSHTestRequest,
    current_user: User = Depends(get_admin_user)
):
    """
    SSH 연결 테스트

    Args:
        request: SSH 테스트 요청
        current_user: 현재 사용자 (ADMIN 권한 필요)

    Returns:
        테스트 결과
    """
    success, message = test_ssh_connection(
        request.ip_address,
        request.hostname,
        request.ssh_port
    )

    return {
        "success": success,
        "message": message
    }


@router.post("/test/db-port")
async def test_db_port_endpoint(
    request: DBPortTestRequest,
    current_user: User = Depends(get_admin_user)
):
    """
    DB 포트 테스트

    Args:
        request: DB 포트 테스트 요청
        current_user: 현재 사용자 (ADMIN 권한 필요)

    Returns:
        테스트 결과
    """
    success, message = test_db_port(
        request.ip_address,
        request.db_port
    )

    return {
        "success": success,
        "message": message
    }


@router.post("/test/db-login")
async def test_db_login_endpoint(
    request: DBLoginTestRequest,
    current_user: User = Depends(get_admin_user)
):
    """
    DB 로그인 테스트

    Args:
        request: DB 로그인 테스트 요청
        current_user: 현재 사용자 (ADMIN 권한 필요)

    Returns:
        테스트 결과
    """
    success, message = test_db_login(
        request.ip_address,
        request.db_type,
        request.db_port,
        request.db_user,
        request.db_passwd
    )

    return {
        "success": success,
        "message": message
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_server(
    server: ServerCreate,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    서버 등록

    Args:
        server: 서버 등록 데이터
        current_user: 현재 사용자 (ADMIN 권한 필요)
        db: 데이터베이스 세션

    Returns:
        등록된 서버 정보

    Raises:
        HTTPException: 서버 ID 중복 또는 암호화 실패
    """
    try:
        new_server = create_server(db, server)
        _run_sync_inventory()

        return {
            "id": new_server.id,
            "server_id": new_server.server_id,
            "ip_address": new_server.ip_address,
            "company": new_server.company,
            "hostname": new_server.hostname,
            "ssh_port": new_server.ssh_port,
            "os_type": new_server.os_type,
            "db_type": new_server.db_type,
            "db_port": new_server.db_port,
            "db_user": new_server.db_user,
            "manager": new_server.manager,
            "department": new_server.department,
            "is_active": new_server.is_active
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"서버 등록 실패: {str(e)}"
        )


@router.post("/bulk", status_code=status.HTTP_201_CREATED)
async def register_servers_bulk(
    request: BulkServerCreate,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """CSV 일괄 서버 등록 (SSH 검증 + DB 비밀번호 암호화 포함)"""
    results = []

    for server_data in request.servers:
        result = {
            "server_id": server_data.server_id,
            "ip_address": server_data.ip_address,
            "status": "success",
            "message": "",
            "ssh_ok": False,
        }

        # 1. SSH 연결 검증
        ssh_ok, ssh_msg = test_ssh_connection(
            server_data.ip_address,
            server_data.hostname,
            server_data.ssh_port or "22"
        )
        result["ssh_ok"] = ssh_ok
        if not ssh_ok:
            result["status"] = "fail"
            result["message"] = f"SSH 연결 실패: {ssh_msg}"
            results.append(result)
            continue

        # 2. 서버 등록 (DB 비밀번호 암호화 포함)
        try:
            new_server = create_server(db, server_data)
            result["message"] = "등록 완료"
        except ValueError as e:
            result["status"] = "fail"
            result["message"] = str(e)
        except Exception as e:
            result["status"] = "fail"
            result["message"] = f"등록 실패: {str(e)}"

        results.append(result)

    success_count = sum(1 for r in results if r["status"] == "success")
    fail_count = sum(1 for r in results if r["status"] == "fail")

    if success_count > 0:
        _run_sync_inventory()

    return {
        "total": len(results),
        "success_count": success_count,
        "fail_count": fail_count,
        "results": results,
    }


@router.get("")
async def list_servers(
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    서버 목록 조회

    Args:
        current_user: 현재 사용자 (ADMIN 권한 필요)
        db: 데이터베이스 세션

    Returns:
        서버 목록
    """
    servers = db.query(Server).filter(Server.is_active == True).all()
    return servers


@router.delete("/{server_id}")
async def delete_server(
    server_id: str,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    서버 삭제 (관련 이력 포함)

    Args:
        server_id: 삭제할 서버 ID
        current_user: 현재 사용자 (ADMIN 권한 필요)
        db: 데이터베이스 세션

    Returns:
        삭제 결과 메시지

    Raises:
        HTTPException: 서버를 찾을 수 없는 경우 또는 삭제 실패
    """
    server = db.query(Server).filter(Server.server_id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"서버 '{server_id}'를 찾을 수 없습니다"
        )

    try:
        # 관련 레코드 먼저 삭제 (외래 키 제약 조건 해결)
        # 1. 점검 이력 삭제
        deleted_scans = db.query(ScanHistory).filter(ScanHistory.server_id == server_id).delete()

        # 2. 조치 이력 삭제
        deleted_remediation = db.query(RemediationLog).filter(RemediationLog.server_id == server_id).delete()

        # 3. 예외 관리 삭제
        deleted_exceptions = db.query(Exception).filter(Exception.server_id == server_id).delete()

        # 4. 서버 삭제
        db.delete(server)
        db.commit()
        _run_sync_inventory()

        return {
            "message": f"서버 '{server_id}' 삭제 완료",
            "deleted_records": {
                "scan_history": deleted_scans,
                "remediation_logs": deleted_remediation,
                "exceptions": deleted_exceptions
            }
        }
    except Exception as e:
        db.rollback()
        error_msg = str(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"서버 삭제 실패: {error_msg}"
        )
