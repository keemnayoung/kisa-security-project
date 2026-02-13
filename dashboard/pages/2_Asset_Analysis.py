"""
2_Analysis.py
SECURITYCORE - 자산별 분석
"""

import streamlit as st
import pandas as pd
import json, sys, os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'components'))
from db_helper import run_query

st.set_page_config(page_title="SECURITYCORE - Analysis", page_icon="🛡️", layout="wide")

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
    .page-header::before { content: ''; width: 3px; height: 16px; background: #3b82f6; border-radius: 2px; }
    .kpi-card {
        background: white; border-radius: 16px; padding: 24px 28px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04); border: 1px solid #eef0f4; height: 120px;
    }
    .kpi-label { font-size: 13px; font-weight: 500; color: #8893a4; margin-bottom: 8px; }
    .kpi-value { font-family: 'JetBrains Mono', monospace !important; font-size: 28px; font-weight: 700; }
    .table-container {
        background: white; border-radius: 16px; padding: 20px 24px;
        border: 1px solid #eef0f4; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .section-title {
        font-size: 16px; font-weight: 700; color: #1a2332;
        margin: 28px 0 16px 0; display: flex; align-items: center; gap: 8px;
    }
    .evidence-box {
        background: #f8f9fc; border-radius: 12px; padding: 16px;
        border: 1px solid #eef0f4; margin-top: 12px;
    }
</style>
""", unsafe_allow_html=True)

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

st.markdown('<div class="page-header">ANALYSIS</div>', unsafe_allow_html=True)

# 서버 선택
servers = run_query("SELECT server_id, company, os_type, ip_address FROM servers WHERE is_active = 1 ORDER BY company, server_id")
if not servers:
    st.warning("등록된 서버가 없습니다.")
    st.stop()

server_options = {f"{s['server_id']} ({s['company']} / {s['ip_address']})": s['server_id'] for s in servers}
col_sel1, col_sel2 = st.columns([2, 1])
with col_sel1:
    selected_label = st.selectbox("서버 선택", options=list(server_options.keys()))
selected_server = server_options[selected_label]

# 점검 회차
scan_dates = run_query("SELECT DISTINCT scan_date FROM scan_history WHERE server_id = %s ORDER BY scan_date DESC", (selected_server,))
if not scan_dates:
    st.info(f"{selected_server}의 점검 이력이 없습니다.")
    st.stop()

with col_sel2:
    date_options = [str(d['scan_date']) for d in scan_dates]
    selected_date = st.selectbox("점검 회차", options=date_options)

# 상세 결과
results = run_query("""
    SELECT sh.item_code, ki.category, ki.title, ki.severity, sh.status, sh.raw_evidence
    FROM scan_history sh
    JOIN kisa_items ki ON sh.item_code = ki.item_code
    WHERE sh.server_id = %s AND sh.scan_date = %s
    ORDER BY sh.item_code
""", (selected_server, selected_date))

if results:
    total = len(results)
    p_cnt = sum(1 for r in results if r['status'] == '양호')
    f_cnt = sum(1 for r in results if r['status'] == '취약')
    score = round((p_cnt / total) * 100, 1) if total > 0 else 0

    col1, col2, col3 = st.columns(3, gap="medium")
    with col1:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">보안 점수</div><div class="kpi-value" style="color: #3b82f6;">{score}점</div></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">양호</div><div class="kpi-value" style="color: #10b981;">{p_cnt}건</div></div>', unsafe_allow_html=True)
    with col3:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">취약</div><div class="kpi-value" style="color: #ef4444;">{f_cnt}건</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="section-title">📋 점검 항목 상세</div>', unsafe_allow_html=True)

    categories = list(set(r['category'] for r in results))
    selected_cat = st.multiselect("카테고리 필터", options=categories, default=categories)
    filtered = [r for r in results if r['category'] in selected_cat]

    df = pd.DataFrame(filtered)
    df = df.rename(columns={
        'item_code': '항목코드', 'category': '카테고리', 'title': '항목명',
        'severity': '중요도', 'status': '결과', 'raw_evidence': '증적'
    })
    st.markdown('<div class="table-container">', unsafe_allow_html=True)
    st.dataframe(df[['항목코드', '카테고리', '항목명', '중요도', '결과']], use_container_width=True, hide_index=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # 증적 상세
    st.markdown('<div class="section-title">🔍 증적 상세</div>', unsafe_allow_html=True)
    item_options = {f"{r['item_code']} - {r['title']}": r for r in filtered}
    selected_item = st.selectbox("항목 선택", options=list(item_options.keys()))
    evidence_path = item_options[selected_item]['raw_evidence']

    if os.path.exists(evidence_path):
        with open(evidence_path, 'r', encoding='utf-8') as f:
            st.markdown('<div class="evidence-box">', unsafe_allow_html=True)
            st.json(json.load(f))
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(f"증적 파일 없음: {evidence_path}")
else:
    st.info("점검 결과가 없습니다.")