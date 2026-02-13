"""
app.py
SECURITYCORE 대시보드 메인
"""

import streamlit as st

st.set_page_config(
    page_title="SECURITYCORE",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 사이드바 스타일 + 전체 CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Pretendard:wght@400;500;600;700;800&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&display=swap');

    * { font-family: 'Pretendard', sans-serif !important; }

    /* 사이드바 */
    [data-testid="stSidebar"] {
        background: #0f1923 !important;
        padding-top: 0 !important;
    }
    [data-testid="stSidebar"] * {
        color: #8899aa !important;
    }
    [data-testid="stSidebar"] .stRadio label {
        padding: 12px 20px !important;
        border-radius: 8px !important;
        margin-bottom: 4px !important;
        transition: all 0.2s !important;
    }
    [data-testid="stSidebar"] .stRadio label:hover {
        background: rgba(59, 130, 246, 0.1) !important;
        color: white !important;
    }

    /* 메인 배경 */
    .main .block-container {
        padding-top: 2rem !important;
        max-width: 1400px !important;
        background: #f8f9fc !important;
    }
    .stApp { background: #f8f9fc !important; }

    /* KPI 카드 */
    .kpi-card {
        background: white;
        border-radius: 16px;
        padding: 24px 28px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        border: 1px solid #eef0f4;
        position: relative;
        overflow: hidden;
    }
    .kpi-label {
        font-size: 13px;
        font-weight: 500;
        color: #8893a4;
        margin-bottom: 8px;
        letter-spacing: -0.2px;
    }
    .kpi-value {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 36px;
        font-weight: 700;
        line-height: 1.1;
        margin-bottom: 4px;
    }
    .kpi-sub {
        font-size: 12px;
        color: #a0aab4;
        font-weight: 500;
    }
    .kpi-icon {
        position: absolute;
        top: 24px;
        right: 24px;
        width: 40px;
        height: 40px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 18px;
    }
    .blue { color: #3b82f6; }
    .green { color: #10b981; }
    .red { color: #ef4444; }
    .purple { color: #8b5cf6; }
    .icon-blue { background: #eff6ff; }
    .icon-green { background: #f0fdf4; }
    .icon-red { background: #fef2f2; }
    .icon-purple { background: #f5f3ff; }

    /* 상단 바 */
    .top-bar {
        background: white;
        border-radius: 12px;
        padding: 16px 24px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border: 1px solid #eef0f4;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .top-bar-info {
        display: flex;
        gap: 32px;
        align-items: center;
    }
    .top-bar-label {
        font-size: 12px;
        color: #8893a4;
        margin-bottom: 2px;
    }
    .top-bar-value {
        font-size: 14px;
        font-weight: 600;
        color: #1a2332;
    }
    .top-bar-divider {
        width: 1px;
        height: 36px;
        background: #e5e7eb;
    }

    /* 버튼 */
    .btn-primary {
        background: #3b82f6;
        color: white !important;
        padding: 10px 24px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        border: none;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        text-decoration: none;
    }
    .btn-outline {
        background: white;
        color: #374151 !important;
        padding: 10px 24px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        border: 1px solid #d1d5db;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        text-decoration: none;
    }

    /* 섹션 타이틀 */
    .section-title {
        font-size: 16px;
        font-weight: 700;
        color: #1a2332;
        margin: 32px 0 16px 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* 테이블 커스텀 */
    .stDataFrame { border-radius: 12px !important; overflow: hidden !important; }

    /* 페이지 헤더 */
    .page-header {
        font-size: 11px;
        font-weight: 700;
        color: #3b82f6;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .page-header::before {
        content: '';
        width: 3px;
        height: 16px;
        background: #3b82f6;
        border-radius: 2px;
    }

    /* Streamlit 기본 요소 숨기기 */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# 사이드바
with st.sidebar:
    st.markdown("""
    <div style="padding: 20px 16px 30px 16px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
            <div style="width: 32px; height: 32px; background: #3b82f6; border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                <span style="color: white; font-size: 16px;">🛡️</span>
            </div>
            <span style="color: white !important; font-size: 18px; font-weight: 700; letter-spacing: -0.5px;">SECURITYCORE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown('<div class="page-header">OVERVIEW</div>', unsafe_allow_html=True)
st.markdown("메인 화면입니다. 좌측 사이드바에서 페이지를 선택하세요.")