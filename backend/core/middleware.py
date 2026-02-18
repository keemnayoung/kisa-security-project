"""
FastAPI 미들웨어
- IP 필터링
- CORS 설정
"""

from ipaddress import ip_address, ip_network
from typing import Callable, List, Tuple
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# IP 필터링 캐시
_ALLOWED_NETS_CACHE: Tuple[str, Tuple] = ("", tuple())


def _parse_allowed_networks(cidrs_str: str) -> Tuple:
    """
    CIDR 문자열을 ip_network 객체 튜플로 변환

    Args:
        cidrs_str: 쉼표로 구분된 CIDR 문자열 (예: "192.168.0.0/16,10.0.0.0/8")

    Returns:
        Tuple: ip_network 객체 튜플
    """
    global _ALLOWED_NETS_CACHE

    # 캐시 확인 (CIDR 문자열이 변경되지 않았으면 재사용)
    if _ALLOWED_NETS_CACHE[0] == cidrs_str:
        return _ALLOWED_NETS_CACHE[1]

    nets = []
    for raw in (cidrs_str or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            nets.append(ip_network(raw, strict=False))
        except Exception:
            # 잘못된 CIDR은 무시
            continue

    # 캐시 업데이트
    _ALLOWED_NETS_CACHE = (cidrs_str, tuple(nets))
    return _ALLOWED_NETS_CACHE[1]


def is_allowed_ip(client_ip: str, allowed_cidrs: str) -> bool:
    """
    클라이언트 IP가 허용된 네트워크에 속하는지 확인

    Args:
        client_ip: 클라이언트 IP 주소
        allowed_cidrs: 허용된 CIDR 문자열

    Returns:
        bool: 허용 여부
    """
    if not client_ip:
        return False

    try:
        ip = ip_address(client_ip)
    except Exception:
        return False

    allowed_nets = _parse_allowed_networks(allowed_cidrs)
    if not allowed_nets:
        return False

    return any(ip in network for network in allowed_nets)


class IPFilterMiddleware(BaseHTTPMiddleware):
    """
    IP 필터링 미들웨어
    허용된 네트워크에서만 API 접근 가능
    """

    def __init__(self, app, allowed_cidrs: str):
        """
        Args:
            app: FastAPI 앱
            allowed_cidrs: 허용된 CIDR 문자열 (쉼표 구분)
        """
        super().__init__(app)
        self.allowed_cidrs = allowed_cidrs

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        요청 처리

        Args:
            request: HTTP 요청
            call_next: 다음 미들웨어/핸들러

        Returns:
            Response: HTTP 응답
        """
        # IP 필터링 제외 경로 (API 문서만 제외)
        excluded_paths = ["/", "/docs", "/redoc", "/openapi.json"]
        if request.url.path in excluded_paths:
            # 필터링 없이 바로 통과
            response = await call_next(request)
            return response

        # 클라이언트 IP 추출
        client_ip = self._get_client_ip(request)

        # IP 필터링 확인
        if not is_allowed_ip(client_ip, self.allowed_cidrs):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Access denied from external network",
                    "client_ip": client_ip
                }
            )

        # 다음 미들웨어/핸들러 호출
        response = await call_next(request)
        return response

    def _get_client_ip(self, request: Request) -> str:
        """
        클라이언트 IP 추출 (프록시 고려)

        Args:
            request: HTTP 요청

        Returns:
            str: 클라이언트 IP
        """
        # X-Forwarded-For 헤더 확인 (프록시 사용 시)
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            # 여러 IP가 있는 경우 첫 번째 (원본 클라이언트)
            return xff.split(",")[0].strip()

        # X-Real-IP 헤더 확인
        xri = request.headers.get("X-Real-IP")
        if xri:
            return xri.strip()

        # 직접 연결된 클라이언트 IP
        if request.client and request.client.host:
            return request.client.host

        return ""
