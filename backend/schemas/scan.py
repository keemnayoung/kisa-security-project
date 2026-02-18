"""
전수 점검 Pydantic 스키마
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class FullScanRequest(BaseModel):
    """전수 점검 요청"""
    server_ids: List[str] = Field(..., min_length=1, description="점검할 서버 ID 목록")
    scan_type: Literal["scan-all", "scan", "scan-db"] = Field(default="scan-all", description="점검 유형")


class ScanProgressResponse(BaseModel):
    """점검 진행 상황 응답"""
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    progress: int = Field(ge=0, le=100, description="진행률 (0-100)")
    current_step: int = Field(ge=1, le=4, description="현재 단계 (1-4)")
    current_server: Optional[str] = None
    completed_servers: int
    total_servers: int
    message: str


class TopVulnerableServer(BaseModel):
    """최다 취약점 서버"""
    server_id: str
    hostname: str
    count: int


class RiskDistribution(BaseModel):
    """위험도 분포"""
    low: int = Field(description="저위험 비율 (%)")
    medium: int = Field(description="중위험 비율 (%)")
    high: int = Field(description="고위험 비율 (%)")


class ScanResultResponse(BaseModel):
    """점검 결과 요약"""
    job_id: str
    company: str
    total_servers: int
    scan_duration: str
    vulnerable_count: int
    secure_count: int
    risk_percentage: int
    top_vulnerable_server: Optional[TopVulnerableServer]
    risk_distribution: RiskDistribution
    scan_completed_at: str
