"""
보고서 생성/다운로드 API
"""

import os
import tempfile
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from core.deps import get_current_user
from db.models import User
from processors.generate_report import fetch_report_data, generate_report


router = APIRouter()


@router.post("/generate")
async def generate_report_endpoint(
    current_user: User = Depends(get_current_user),
):
    """
    취약점 진단 결과 엑셀 보고서 생성 및 다운로드

    - 인증된 사용자(ADMIN/VIEWER) 모두 사용 가능
    - 점검 결과가 없으면 404 반환
    """
    try:
        servers, kisa_items, kisa_map, results = fetch_report_data()
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="점검 결과가 없습니다. 먼저 전수 점검을 실행해주세요.",
        )

    company_name = servers[0].get('company', 'REPORT')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M')
    filename = f'{company_name}_취약점진단결과_{timestamp}.xlsx'

    tmp_dir = tempfile.mkdtemp()
    output_path = os.path.join(tmp_dir, filename)

    try:
        generate_report(servers, kisa_items, kisa_map, results, output_path, company_name)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"보고서 생성 중 오류가 발생했습니다: {str(e)}",
        )

    encoded_filename = quote(filename)

    return FileResponse(
        path=output_path,
        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={
            'Content-Disposition': f"attachment; filename*=UTF-8''{encoded_filename}",
        },
    )
