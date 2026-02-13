"""
1_Dashboard.py
SECURITYCORE - 메인 대시보드
"""

import os
import sys
import pandas as pd
import streamlit as st
import altair as alt
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "components"))
from db_helper import run_query

# ============================================================
# 페이지 설정
# ============================================================
st.set_page_config(
    page_title="SECURITYCORE - Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# 커스텀 CSS 스타일
# ============================================================
st.markdown(
    """
<style>
    /* 폰트 임포트 */
    @import url('https://fonts.googleapis.com/css2?family=Pretendard:wght@300;400;500;600;700;800;900&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');
    
    /* 기본 설정 */
    * {
        font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, system-ui, sans-serif !important;
    }
    
    /* 메인 컨테이너 */
    .main .block-container {
        padding-top: 2rem !important;
        padding-bottom: 3rem !important;
        max-width: 1600px !important;
    }
    
    /* 배경색 */
    .stApp {
        background: #f5f7fa !important;
    }
    
    /* 헤더/푸터 숨기기 */
    #MainMenu, footer, header {
        visibility: hidden;
    }
    
    /* 사이드바 스타일 */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a2332 0%, #0f1419 100%) !important;
    }
    
    [data-testid="stSidebar"] .css-1d391kg {
        color: #ffffff !important;
    }
    
    /* 페이지 헤더 */
    .page-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 24px;
        padding-bottom: 16px;
        border-bottom: 1px solid #e5e9f0;
    }
    
    .page-header-icon {
        font-size: 28px;
        line-height: 1;
    }
    
    .page-header-text {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    
    .page-header-title {
        font-size: 24px;
        font-weight: 800;
        color: #1a2332;
        letter-spacing: -0.5px;
    }
    
    .page-header-subtitle {
        font-size: 13px;
        font-weight: 500;
        color: #6b7684;
        letter-spacing: 0.3px;
    }
    
    /* 상단 정보 바 */
    .info-bar {
        background: white;
        border-radius: 16px;
        padding: 20px 28px;
        border: 1px solid #e5e9f0;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        gap: 32px;
    }
    
    .info-item {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    
    .info-label {
        font-size: 11px;
        font-weight: 600;
        color: #8b95a5;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .info-value {
        font-size: 16px;
        font-weight: 700;
        color: #1a2332;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .info-divider {
        width: 1px;
        height: 40px;
        background: linear-gradient(180deg, transparent 0%, #e5e9f0 50%, transparent 100%);
    }
    
    /* KPI 카드 */
    .kpi-card {
        background: white;
        border-radius: 18px;
        padding: 24px 26px;
        border: 1px solid #e5e9f0;
        box-shadow: 0 2px 12px rgba(0, 0, 0, 0.04);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
        min-height: 140px;
    }
    
    .kpi-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(90deg, var(--kpi-color), var(--kpi-color-light));
        opacity: 0;
        transition: opacity 0.3s;
    }
    
    .kpi-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
        border-color: var(--kpi-color);
    }
    
    .kpi-card:hover::before {
        opacity: 1;
    }
    
    .kpi-label {
        font-size: 12px;
        font-weight: 600;
        color: #8b95a5;
        margin-bottom: 14px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .kpi-value {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 36px;
        font-weight: 800;
        line-height: 1;
        margin-bottom: 12px;
        letter-spacing: -1px;
    }
    
    .kpi-sub {
        font-size: 12px;
        color: #9aa5b5;
        font-weight: 500;
    }
    
    .kpi-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 4px 10px;
        background: rgba(37, 99, 235, 0.08);
        color: #2563eb;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 600;
        margin-top: 8px;
    }
    
    /* 섹션 타이틀 */
    .section-title {
        font-size: 16px;
        font-weight: 800;
        color: #1a2332;
        margin: 32px 0 16px 0;
        letter-spacing: -0.3px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .section-title::before {
        content: '';
        width: 4px;
        height: 18px;
        background: linear-gradient(180deg, #2563eb, #3b82f6);
        border-radius: 2px;
    }
    
    /* 패널 */
    .panel {
        background: white;
        border-radius: 18px;
        padding: 24px;
        border: 1px solid #e5e9f0;
        box-shadow: 0 2px 12px rgba(0, 0, 0, 0.04);
    }
    
    /* 차트 컨테이너 */
    .chart-container {
        background: white;
        border-radius: 18px;
        padding: 28px;
        border: 1px solid #e5e9f0;
        box-shadow: 0 2px 12px rgba(0, 0, 0, 0.04);
    }
    
    /* 버튼 스타일 */
    .stButton > button {
        background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 12px 24px !important;
        font-weight: 700 !important;
        font-size: 14px !important;
        letter-spacing: 0.3px !important;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3) !important;
        transition: all 0.3s !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(37, 99, 235, 0.4) !important;
    }
    
    /* 데이터프레임 스타일 */
    [data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid #e5e9f0;
    }
    
    [data-testid="stDataFrame"] th {
        background: #f8f9fc !important;
        color: #6b7684 !important;
        font-weight: 700 !important;
        font-size: 11px !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
        padding: 14px 16px !important;
    }
    
    [data-testid="stDataFrame"] td {
        padding: 14px 16px !important;
        font-size: 13px !important;
        color: #1a2332 !important;
        border-bottom: 1px solid #f0f2f5 !important;
    }
    
    /* 인포 메시지 */
    .stInfo {
        background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%) !important;
        border-left: 4px solid #3b82f6 !important;
        border-radius: 12px !important;
        padding: 16px 20px !important;
        color: #1e40af !important;
    }
    
    /* 스크롤바 */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #f1f3f5;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #cbd5e0;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #a0aec0;
    }
</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# 헬퍼 함수
# ============================================================
def _pct(numerator, denominator):
    """백분율 계산"""
    if not denominator:
        return 0.0
    return round((numerator / denominator) * 100, 1)


def format_number(num):
    """숫자 포맷팅 (천 단위 콤마)"""
    return f"{num:,}"


# ============================================================
# 데이터 조회
# ============================================================
@st.cache_data(ttl=300)
def load_dashboard_data():
    """대시보드 데이터 로드 (5분 캐시)"""
    
    # 전체 서버 수
    total_servers_row = run_query("SELECT COUNT(*) AS cnt FROM servers WHERE is_active = 1")
    total_servers = int(total_servers_row[0]["cnt"]) if total_servers_row else 0

    # 마지막 점검 시각
    last_scan_row = run_query("SELECT MAX(scan_date) AS last_scan FROM scan_history")
    last_scan = last_scan_row[0]["last_scan"] if last_scan_row and last_scan_row[0]["last_scan"] else None
    last_scan_str = last_scan.strftime("%Y-%m-%d %H:%M") if last_scan else "-"

    # 점검된 서버 수
    scanned_row = run_query(
        """
        SELECT COUNT(DISTINCT server_id) AS cnt
        FROM scan_history
        WHERE scan_date = (SELECT MAX(scan_date) FROM scan_history)
        """
    )
    scanned_servers = int(scanned_row[0]["cnt"]) if scanned_row else 0
    coverage = _pct(scanned_servers, total_servers)

    # 최신 스냅샷
    latest_snapshot = run_query(
        """
        SELECT
            SUM(CASE WHEN sh.status = '양호' THEN 1 ELSE 0 END) AS pass_count,
            SUM(CASE WHEN sh.status = '취약' THEN 1 ELSE 0 END) AS fail_count,
            SUM(CASE WHEN sh.status = '취약' AND (ki.severity IN ('상', 'HIGH', 'High', 'high')) THEN 1 ELSE 0 END) AS high_risk_count,
            COUNT(*) AS total_count
        FROM scan_history sh
        LEFT JOIN kisa_items ki ON sh.item_code = ki.item_code
        WHERE sh.scan_date = (SELECT MAX(scan_date) FROM scan_history)
        """
    )
    pass_count = int((latest_snapshot[0]["pass_count"] if latest_snapshot else 0) or 0)
    fail_count = int((latest_snapshot[0]["fail_count"] if latest_snapshot else 0) or 0)
    high_risk_count = int((latest_snapshot[0]["high_risk_count"] if latest_snapshot else 0) or 0)
    total_count = int((latest_snapshot[0]["total_count"] if latest_snapshot else 0) or 0)
    compliance_rate = _pct(pass_count, total_count)

    # 최근 조치 성공률
    recent_fix_row = run_query(
        """
        SELECT
            SUM(CASE WHEN is_success = 1 THEN 1 ELSE 0 END) AS success_count,
            COUNT(*) AS total_count
        FROM remediation_logs
        WHERE action_date >= NOW() - INTERVAL 24 HOUR
        """
    )
    fix_success_count = int((recent_fix_row[0]["success_count"] if recent_fix_row else 0) or 0)
    fix_total_count = int((recent_fix_row[0]["total_count"] if recent_fix_row else 0) or 0)
    fix_success_rate = _pct(fix_success_count, fix_total_count)

    # 추이 데이터
    trend_rows = run_query(
        """
        SELECT
            DATE(scan_date) AS scan_day,
            ROUND(SUM(CASE WHEN status = '양호' THEN 1 ELSE 0 END) / COUNT(*) * 100, 1) AS compliance_rate,
            SUM(CASE WHEN status = '취약' THEN 1 ELSE 0 END) AS vuln_count
        FROM scan_history
        GROUP BY DATE(scan_date)
        ORDER BY scan_day
        LIMIT 30
        """
    )

    # TOP 5 서버
    top_action_rows = run_query(
        """
        SELECT
            s.server_id,
            s.company,
            SUM(CASE WHEN sh.status = '취약' THEN 1 ELSE 0 END) AS vuln_count,
            SUM(CASE WHEN sh.status = '취약' AND ki.severity IN ('상', 'HIGH', 'High', 'high') THEN 1 ELSE 0 END) AS high_risk_count,
            MAX(sh.scan_date) AS last_scan
        FROM servers s
        LEFT JOIN (
            SELECT sh1.*
            FROM scan_history sh1
            JOIN (
                SELECT server_id, MAX(scan_date) AS max_scan_date
                FROM scan_history
                GROUP BY server_id
            ) x ON sh1.server_id = x.server_id AND sh1.scan_date = x.max_scan_date
        ) sh ON s.server_id = sh.server_id
        LEFT JOIN kisa_items ki ON sh.item_code = ki.item_code
        WHERE s.is_active = 1
        GROUP BY s.server_id, s.company
        HAVING vuln_count > 0
        ORDER BY high_risk_count DESC, vuln_count DESC, last_scan DESC
        LIMIT 5
        """
    )

    # 최근 조치 이력
    recent_fix_rows = run_query(
        """
        SELECT
            rl.action_date,
            rl.server_id,
            rl.item_code,
            COALESCE(ki.title, '항목 설명 없음') AS item_title,
            CASE WHEN rl.is_success = 1 THEN '✅ 성공' ELSE '❌ 실패' END AS result
        FROM remediation_logs rl
        LEFT JOIN kisa_items ki ON rl.item_code = ki.item_code
        ORDER BY rl.action_date DESC
        LIMIT 10
        """
    )
    
    return {
        "total_servers": total_servers,
        "last_scan_str": last_scan_str,
        "scanned_servers": scanned_servers,
        "coverage": coverage,
        "compliance_rate": compliance_rate,
        "fail_count": fail_count,
        "high_risk_count": high_risk_count,
        "fix_success_rate": fix_success_rate,
        "fix_success_count": fix_success_count,
        "fix_total_count": fix_total_count,
        "trend_rows": trend_rows,
        "top_action_rows": top_action_rows,
        "recent_fix_rows": recent_fix_rows,
    }


# 데이터 로드
data = load_dashboard_data()


# ============================================================
# 헤더
# ============================================================
st.markdown(
    """
<div class="page-header">
    <div class="page-header-icon">🛡️</div>
    <div class="page-header-text">
        <div class="page-header-title">DASHBOARD</div>
        <div class="page-header-subtitle">보안 점검 현황 및 주요 지표</div>
    </div>
</div>
""",
    unsafe_allow_html=True,
)


# ============================================================
# 상단 정보 바 + 버튼
# ============================================================
bar_left, bar_right = st.columns([5, 1], gap="medium")

with bar_left:
    st.markdown(
        f"""
    <div class="info-bar">
        <div class="info-item">
            <div class="info-label">마지막 점검</div>
            <div class="info-value">{data['last_scan_str']}</div>
        </div>
        <div class="info-divider"></div>
        <div class="info-item">
            <div class="info-label">점검 대상</div>
            <div class="info-value">{format_number(data['total_servers'])}대</div>
        </div>
        <div class="info-divider"></div>
        <div class="info-item">
            <div class="info-label">커버리지</div>
            <div class="info-value">{data['coverage']}%</div>
        </div>
        <div class="info-divider"></div>
        <div class="info-item">
            <div class="info-label">점검 완료</div>
            <div class="info-value">{data['scanned_servers']}/{data['total_servers']}</div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

with bar_right:
    if st.button("🔄 전수 점검", key="run_full_scan_button", use_container_width=True):
        st.success("전수 점검이 시작되었습니다!")


# ============================================================
# KPI 카드 4개
# ============================================================
st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

kpi1, kpi2, kpi3, kpi4 = st.columns(4, gap="medium")

with kpi1:
    st.markdown(
        f"""
    <div class="kpi-card" style="--kpi-color: #2563eb; --kpi-color-light: #3b82f6;">
        <div class="kpi-label">보안 준수율</div>
        <div class="kpi-value" style="color: #2563eb;">{data['compliance_rate']}%</div>
        <div class="kpi-sub">최신 점검 기준</div>
        <div class="kpi-badge">
            <span>📊</span>
            <span>Today</span>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

with kpi2:
    st.markdown(
        f"""
    <div class="kpi-card" style="--kpi-color: #f59e0b; --kpi-color-light: #fbbf24;">
        <div class="kpi-label">미해결 취약점</div>
        <div class="kpi-value" style="color: #f59e0b;">{format_number(data['fail_count'])}</div>
        <div class="kpi-sub">조치 필요 항목</div>
        <div class="kpi-badge" style="background: rgba(245, 158, 11, 0.08); color: #f59e0b;">
            <span>⚠️</span>
            <span>Action Required</span>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

with kpi3:
    st.markdown(
        f"""
    <div class="kpi-card" style="--kpi-color: #dc2626; --kpi-color-light: #ef4444;">
        <div class="kpi-label">고위험 취약점</div>
        <div class="kpi-value" style="color: #dc2626;">{format_number(data['high_risk_count'])}</div>
        <div class="kpi-sub">심각도 상/HIGH</div>
        <div class="kpi-badge" style="background: rgba(220, 38, 38, 0.08); color: #dc2626;">
            <span>🚨</span>
            <span>Critical</span>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

with kpi4:
    st.markdown(
        f"""
    <div class="kpi-card" style="--kpi-color: #059669; --kpi-color-light: #10b981;">
        <div class="kpi-label">24시간 조치율</div>
        <div class="kpi-value" style="color: #059669;">{data['fix_success_rate']}%</div>
        <div class="kpi-sub">성공 {format_number(data['fix_success_count'])} / 전체 {format_number(data['fix_total_count'])}</div>
        <div class="kpi-badge" style="background: rgba(5, 150, 105, 0.08); color: #059669;">
            <span>✅</span>
            <span>Success</span>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )


# ============================================================
# 보안 준수율 추이 차트
# ============================================================
st.markdown('<div class="section-title">📈 보안 준수율 및 취약점 추이</div>', unsafe_allow_html=True)

if data["trend_rows"]:
    df_trend = pd.DataFrame(data["trend_rows"])
    df_trend["scan_day"] = pd.to_datetime(df_trend["scan_day"])
    
    # 차트 생성
    base = alt.Chart(df_trend).encode(
        x=alt.X(
            "scan_day:T",
            title="점검 일자",
            axis=alt.Axis(
                format="%m/%d",
                labelAngle=-45,
                labelFontSize=11,
                titleFontSize=12,
                titleFontWeight=600,
                labelColor="#6b7684",
                titleColor="#1a2332",
            ),
        )
    )
    
    # 막대 차트 (취약점 수)
    bars = base.mark_bar(
        opacity=0.6,
        color="#fbbf24",
        cornerRadiusTopLeft=4,
        cornerRadiusTopRight=4,
    ).encode(
        y=alt.Y(
            "vuln_count:Q",
            title="미해결 취약점 수",
            axis=alt.Axis(
                labelFontSize=11,
                titleFontSize=12,
                titleFontWeight=600,
                labelColor="#6b7684",
                titleColor="#1a2332",
                grid=True,
                gridOpacity=0.3,
            ),
        ),
        tooltip=[
            alt.Tooltip("scan_day:T", title="날짜", format="%Y-%m-%d"),
            alt.Tooltip("vuln_count:Q", title="취약점 수"),
        ],
    )
    
    # 라인 차트 (준수율)
    line = base.mark_line(
        color="#2563eb",
        strokeWidth=3,
        point=alt.OverlayMarkDef(
            filled=True,
            fill="white",
            size=80,
            stroke="#2563eb",
            strokeWidth=3,
        ),
    ).encode(
        y=alt.Y(
            "compliance_rate:Q",
            title="보안 준수율 (%)",
            axis=alt.Axis(
                labelFontSize=11,
                titleFontSize=12,
                titleFontWeight=600,
                labelColor="#6b7684",
                titleColor="#1a2332",
            ),
        ),
        tooltip=[
            alt.Tooltip("scan_day:T", title="날짜", format="%Y-%m-%d"),
            alt.Tooltip("compliance_rate:Q", title="준수율", format=".1f"),
        ],
    )
    
    # 차트 결합
    chart = (
        (bars + line)
        .resolve_scale(y="independent")
        .properties(height=350)
        .configure_view(strokeWidth=0)
        .configure_axis(domainColor="#e5e9f0", gridColor="#f0f2f5")
    )
    
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.altair_chart(chart, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)
else:
    st.info("📊 점검 추이 데이터가 아직 없습니다. 점검을 실행해주세요.")


# ============================================================
# 하단 액션 영역 (TOP 5 서버 + 최근 조치 이력)
# ============================================================
left_col, right_col = st.columns([1.2, 1], gap="large")

# TOP 5 서버
with left_col:
    st.markdown('<div class="section-title">🎯 조치 필요 TOP 5 서버</div>', unsafe_allow_html=True)
    
    if data["top_action_rows"]:
        df_top = pd.DataFrame(data["top_action_rows"])
        df_top["last_scan"] = pd.to_datetime(df_top["last_scan"]).dt.strftime("%m/%d %H:%M")
        df_top = df_top.rename(
            columns={
                "server_id": "서버 ID",
                "company": "회사명",
                "vuln_count": "취약건수",
                "high_risk_count": "고위험",
                "last_scan": "마지막 점검",
            }
        )
        
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.dataframe(
            df_top[["서버 ID", "회사명", "취약건수", "고위험", "마지막 점검"]],
            use_container_width=True,
            hide_index=True,
            height=280,
        )
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("✅ 조치가 필요한 서버가 없습니다. 훌륭합니다!")

# 최근 조치 이력
with right_col:
    st.markdown('<div class="section-title">📋 최근 조치 이력</div>', unsafe_allow_html=True)
    
    if data["recent_fix_rows"]:
        df_fix = pd.DataFrame(data["recent_fix_rows"])
        df_fix["action_date"] = pd.to_datetime(df_fix["action_date"]).dt.strftime("%m/%d %H:%M")
        df_fix = df_fix.rename(
            columns={
                "action_date": "조치일시",
                "server_id": "서버",
                "item_code": "코드",
                "item_title": "항목명",
                "result": "결과",
            }
        )
        
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.dataframe(
            df_fix[["조치일시", "서버", "항목명", "결과"]],
            use_container_width=True,
            hide_index=True,
            height=280,
        )
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("📝 아직 조치 이력이 없습니다.")


# ============================================================
# 푸터
# ============================================================
st.markdown("<div style='height: 32px;'></div>", unsafe_allow_html=True)
st.markdown(
    """
<div style='text-align: center; color: #9aa5b5; font-size: 12px; padding: 20px 0;'>
    <strong>SECURITYCORE</strong> v1.0 | 
    마지막 업데이트: <span id="current-time"></span>
</div>
<script>
    document.getElementById('current-time').textContent = new Date().toLocaleString('ko-KR');
</script>
""",
    unsafe_allow_html=True,
)
