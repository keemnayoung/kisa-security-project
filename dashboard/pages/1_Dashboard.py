"""
1_Dashboard.py
SECURITYCORE - 메인 대시보드
"""

import streamlit as st
import pandas as pd
import sys, os
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'components'))
from db_helper import run_query

st.set_page_config(
    page_title="SECURITYCORE - Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded" # 'auto'가 아니라 'expanded'로 고정!
)

# CSS 로드
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Pretendard:wght@400;500;600;700;800&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&display=swap');
    * { font-family: 'Pretendard', sans-serif !important; }
    .main .block-container { padding-top: 2rem !important; max-width: 1400px !important; }
    .stApp { background: #f8f9fc !important; }
    #MainMenu, footer, header { visibility: hidden; }

    .page-header {
        font-size: 11px; font-weight: 700; color: #3b82f6;
        letter-spacing: 1px; text-transform: uppercase;
        margin-bottom: 20px; display: flex; align-items: center; gap: 8px;
    }
    .page-header::before {
        content: ''; width: 3px; height: 16px; background: #3b82f6; border-radius: 2px;
    }
    .top-bar {
        background: white; border-radius: 12px; padding: 16px 28px;
        margin-bottom: 24px; border: 1px solid #eef0f4;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .kpi-card {
        background: white; border-radius: 16px; padding: 24px 28px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04); border: 1px solid #eef0f4;
        height: 140px; position: relative;
    }
    .kpi-label { font-size: 13px; font-weight: 500; color: #8893a4; margin-bottom: 8px; }
    .kpi-value {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 32px; font-weight: 700; line-height: 1.2; margin-bottom: 6px;
    }
    .kpi-sub { font-size: 12px; color: #a0aab4; font-weight: 500; }
    .kpi-icon {
        position: absolute; top: 24px; right: 24px;
        width: 40px; height: 40px; border-radius: 10px;
        display: flex; align-items: center; justify-content: center; font-size: 18px;
    }
    .section-title {
        font-size: 16px; font-weight: 700; color: #1a2332;
        margin: 28px 0 16px 0; display: flex; align-items: center; gap: 8px;
    }
    .chart-container {
        background: white; border-radius: 16px; padding: 28px;
        border: 1px solid #eef0f4; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .table-container {
        background: white; border-radius: 16px; padding: 20px 24px;
        border: 1px solid #eef0f4; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
</style>
""", unsafe_allow_html=True)

# 사이드바
with st.sidebar:
    st.markdown("""
    <div style="padding: 20px 16px 30px 16px;">
        <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 32px; height: 32px; background: #3b82f6; border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                <span style="color: white; font-size: 16px;">🛡️</span>
            </div>
            <span style="color: white !important; font-size: 18px; font-weight: 700;">SECURITYCORE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# 데이터 조회
# ============================================================
total_servers = run_query("SELECT COUNT(*) AS cnt FROM servers WHERE is_active = 1")
total_servers_cnt = total_servers[0]['cnt'] if total_servers else 0

latest_scan_info = run_query("SELECT MAX(scan_date) AS last_scan FROM scan_history")
last_scan = latest_scan_info[0]['last_scan'] if latest_scan_info and latest_scan_info[0]['last_scan'] else None

# 최신 점검 기준 집계
latest_stats = run_query("""
    SELECT
        SUM(CASE WHEN status = '양호' THEN 1 ELSE 0 END) AS pass_count,
        SUM(CASE WHEN status = '취약' THEN 1 ELSE 0 END) AS fail_count,
        COUNT(*) AS total_count
    FROM scan_history
    WHERE scan_date = (SELECT MAX(scan_date) FROM scan_history)
""")

if latest_stats and latest_stats[0]['total_count']:
    pass_count = int(latest_stats[0]['pass_count'] or 0)
    fail_count = int(latest_stats[0]['fail_count'] or 0)
    total_count = int(latest_stats[0]['total_count'] or 0)
    compliance_rate = round((pass_count / total_count) * 100, 1) if total_count > 0 else 0
else:
    pass_count = fail_count = total_count = 0
    compliance_rate = 0

# 이전 점검 대비 변화율
prev_stats = run_query("""
    SELECT
        SUM(CASE WHEN status = '양호' THEN 1 ELSE 0 END) AS pass_count,
        COUNT(*) AS total_count
    FROM scan_history
    WHERE scan_date = (
        SELECT DISTINCT scan_date FROM scan_history ORDER BY scan_date DESC LIMIT 1 OFFSET 1
    )
""")
if prev_stats and prev_stats[0]['total_count'] and prev_stats[0]['total_count'] > 0:
    prev_rate = round((int(prev_stats[0]['pass_count'] or 0) / int(prev_stats[0]['total_count'])) * 100, 1)
    rate_change = round(compliance_rate - prev_rate, 1)
    rate_change_str = f"+{rate_change}%" if rate_change >= 0 else f"{rate_change}%"
else:
    rate_change_str = "-"

# 예외 항목
exceptions = run_query("SELECT COUNT(*) AS cnt FROM exceptions WHERE valid_date > NOW()")
exception_cnt = exceptions[0]['cnt'] if exceptions else 0

# 최근 24H 이벤트 (점검 + 조치)
recent_events = run_query("""
    SELECT COUNT(*) AS cnt FROM (
        SELECT scan_id FROM scan_history WHERE scan_date >= NOW() - INTERVAL 24 HOUR
        UNION ALL
        SELECT log_id FROM remediation_logs WHERE action_date >= NOW() - INTERVAL 24 HOUR
    ) t
""")
event_cnt = recent_events[0]['cnt'] if recent_events else 0

# 자동 조치 건수
auto_fix_cnt = run_query("""
    SELECT COUNT(*) AS cnt FROM remediation_logs
    WHERE action_date >= NOW() - INTERVAL 24 HOUR AND is_success = 1
""")
auto_fix = auto_fix_cnt[0]['cnt'] if auto_fix_cnt else 0

# 점검된 서버 수
scanned_servers = run_query("""
    SELECT COUNT(DISTINCT server_id) AS cnt FROM scan_history
    WHERE scan_date = (SELECT MAX(scan_date) FROM scan_history)
""")
scanned_cnt = scanned_servers[0]['cnt'] if scanned_servers else 0

# ============================================================
# 상단 헤더
# ============================================================
st.markdown('<div class="page-header">OVERVIEW</div>', unsafe_allow_html=True)

# 상단 바
last_scan_str = last_scan.strftime('%Y-%m-%d %H:%M:%S') if last_scan else '-'
os_types = run_query("SELECT DISTINCT os_type FROM servers WHERE is_active = 1")
os_list = '/'.join(set(o['os_type'].split()[0] for o in os_types)) if os_types else '-'
db_types = run_query("SELECT DISTINCT db_type FROM servers WHERE is_active = 1 AND db_type IS NOT NULL")
db_list = '/'.join(set(d['db_type'].split()[0] for d in db_types)) if db_types else ''
asset_desc = f"총 {total_servers_cnt}대 ({os_list}/{db_list})" if db_list else f"총 {total_servers_cnt}대 ({os_list})"

st.markdown(f"""
<div class="top-bar">
    <div style="display: flex; gap: 40px; align-items: center;">
        <div>
            <div style="font-size: 12px; color: #8893a4; margin-bottom: 2px;">마지막 전체 점검</div>
            <div style="font-size: 14px; font-weight: 700; color: #1a2332;">{last_scan_str}</div>
        </div>
        <div style="width: 1px; height: 36px; background: #e5e7eb;"></div>
        <div>
            <div style="font-size: 12px; color: #8893a4; margin-bottom: 2px;">점검 대상 자산</div>
            <div style="font-size: 14px; font-weight: 700; color: #1a2332;">{asset_desc}</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================
# KPI 카드 4개
# ============================================================
col1, col2, col3, col4 = st.columns(4, gap="medium")

with col1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">전체 보안 준수율</div>
        <div class="kpi-value" style="color: #3b82f6;">{compliance_rate}%</div>
        <div class="kpi-sub">지난 점검 대비 {rate_change_str}</div>
        <div class="kpi-icon" style="background: #eff6ff;"><span style="font-size: 20px;">✓</span></div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">운영 자산 현황</div>
        <div class="kpi-value" style="color: #1a2332;">{scanned_cnt} / {total_servers_cnt}</div>
        <div class="kpi-sub">{total_servers_cnt}대 정상 가동 중</div>
        <div class="kpi-icon" style="background: #f0fdf4;"><span style="font-size: 20px;">🖥</span></div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">미해결 취약점</div>
        <div class="kpi-value" style="color: #ef4444;">{fail_count}건</div>
        <div class="kpi-sub">조치 예약 {exception_cnt}건</div>
        <div class="kpi-icon" style="background: #fef2f2;"><span style="font-size: 20px;">⚠</span></div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">최근 24H 이벤트</div>
        <div class="kpi-value" style="color: #8b5cf6;">{event_cnt}건</div>
        <div class="kpi-sub">자동 조치 {auto_fix}건</div>
        <div class="kpi-icon" style="background: #f5f3ff;"><span style="font-size: 20px;">📊</span></div>
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# 주간 보안 준수율 변화 추이
# ============================================================
st.markdown('<div class="section-title">📈 주간 보안 준수율 변화 추이 (전체 자산 평균)</div>', unsafe_allow_html=True)

trend_data = run_query("""
    SELECT
        DATE(scan_date) AS scan_day,
        ROUND(SUM(CASE WHEN status = '양호' THEN 1 ELSE 0 END) / COUNT(*) * 100, 1) AS compliance
    FROM scan_history
    GROUP BY DATE(scan_date)
    ORDER BY scan_day
""")

if trend_data:
    df_trend = pd.DataFrame(trend_data)
    df_trend['scan_day'] = pd.to_datetime(df_trend['scan_day'])
    df_trend = df_trend.set_index('scan_day')

    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.area_chart(df_trend['compliance'], color="#3b82f6", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)
else:
    st.markdown('<div class="chart-container"><p style="color:#8893a4; text-align:center; padding:40px;">점검 데이터가 없습니다.</p></div>', unsafe_allow_html=True)

# ============================================================
# 회사별 현황 + 최근 이벤트
# ============================================================
col_left, col_right = st.columns([1.2, 1], gap="medium")

with col_left:
    st.markdown('<div class="section-title">🏢 회사별 점검 현황</div>', unsafe_allow_html=True)

    company_stats = run_query("""
        SELECT
            s.company,
            COUNT(DISTINCT s.server_id) AS server_count,
            SUM(CASE WHEN sh.status = '양호' THEN 1 ELSE 0 END) AS pass_cnt,
            SUM(CASE WHEN sh.status = '취약' THEN 1 ELSE 0 END) AS fail_cnt,
            COUNT(sh.scan_id) AS total_cnt
        FROM servers s
        LEFT JOIN scan_history sh ON s.server_id = sh.server_id
            AND sh.scan_date = (SELECT MAX(scan_date) FROM scan_history sh2 WHERE sh2.server_id = sh.server_id)
        WHERE s.is_active = 1
        GROUP BY s.company
        ORDER BY s.company
    """)

    if company_stats:
        df_company = pd.DataFrame(company_stats)
        df_company['준수율'] = df_company.apply(
            lambda r: f"{round(int(r['pass_cnt'] or 0) / int(r['total_cnt']) * 100, 1)}%" if int(r['total_cnt'] or 0) > 0 else '-', axis=1
        )
        df_company = df_company.rename(columns={
            'company': '회사', 'server_count': '서버 수',
            'pass_cnt': '양호', 'fail_cnt': '취약', 'total_cnt': '전체'
        })
        st.markdown('<div class="table-container">', unsafe_allow_html=True)
        st.dataframe(df_company[['회사', '서버 수', '양호', '취약', '준수율']], use_container_width=True, hide_index=True)
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("데이터가 없습니다.")

with col_right:
    st.markdown('<div class="section-title">🕐 최근 이벤트</div>', unsafe_allow_html=True)

    recent = run_query("""
        (SELECT scan_date AS event_date, server_id, item_code,
                CONCAT(status) AS detail, 'SCAN' AS type
         FROM scan_history ORDER BY scan_date DESC LIMIT 5)
        UNION ALL
        (SELECT action_date, server_id, item_code,
                IF(is_success, '조치 성공', '조치 실패'), 'FIX'
         FROM remediation_logs ORDER BY action_date DESC LIMIT 5)
        ORDER BY event_date DESC LIMIT 8
    """)

    if recent:
        st.markdown('<div class="table-container">', unsafe_allow_html=True)
        for r in recent:
            icon = "🔍" if r['type'] == 'SCAN' else "🔧"
            color = "#10b981" if r['detail'] in ['양호', '조치 성공'] else "#ef4444"
            st.markdown(f"""
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #f3f4f6;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span>{icon}</span>
                    <div>
                        <span style="font-size: 13px; font-weight: 600; color: #1a2332;">{r['server_id']}</span>
                        <span style="font-size: 12px; color: #8893a4; margin-left: 8px;">{r['item_code']}</span>
                    </div>
                </div>
                <span style="font-size: 12px; font-weight: 600; color: {color};">{r['detail']}</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("이벤트가 없습니다.")