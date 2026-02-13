"""
4_Exception_Log.py
예외 처리 관리 - 예외 항목 조회, 등록, 삭제
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'components'))
from db_helper import run_query, run_execute

st.set_page_config(page_title="예외 처리", page_icon="📝", layout="wide")
st.title("📝 예외 처리 관리")

tab1, tab2 = st.tabs(["📋 예외 항목 현황", "➕ 예외 등록"])

# ============================================================
# Tab 1: 예외 항목 현황
# ============================================================
with tab1:
    st.subheader("현재 예외 처리 항목")

    exceptions = run_query("""
        SELECT
            e.exception_id,
            e.server_id,
            e.item_code,
            ki.title,
            ki.severity,
            e.reason,
            e.valid_date
        FROM exceptions e
        JOIN kisa_items ki ON e.item_code = ki.item_code
        ORDER BY e.valid_date DESC
    """)

    if exceptions:
        # 유효/만료 분리
        now = datetime.now()
        valid = [e for e in exceptions if e['valid_date'] > now]
        expired = [e for e in exceptions if e['valid_date'] <= now]

        col1, col2 = st.columns(2)
        with col1:
            st.metric("유효한 예외", f"{len(valid)}건")
        with col2:
            st.metric("만료된 예외", f"{len(expired)}건")

        st.divider()

        # 유효한 예외
        if valid:
            st.markdown("#### ✅ 유효한 예외 항목")
            df_valid = pd.DataFrame(valid)
            df_valid['valid_date'] = pd.to_datetime(df_valid['valid_date']).dt.strftime('%Y-%m-%d')
            df_valid = df_valid.rename(columns={
                'exception_id': 'ID',
                'server_id': '서버',
                'item_code': '항목코드',
                'title': '항목명',
                'severity': '중요도',
                'reason': '예외 사유',
                'valid_date': '만료일',
            })
            st.dataframe(df_valid, width="stretch", hide_index=True)

            # 예외 삭제
            st.divider()
            st.markdown("#### 🗑️ 예외 삭제")
            delete_options = {f"[{e['server_id']}] {e['item_code']} - {e['reason'][:30]}": e['exception_id'] for e in valid}
            selected_delete = st.selectbox("삭제할 예외 선택", options=list(delete_options.keys()))

            if st.button("예외 삭제", type="secondary"):
                exception_id = delete_options[selected_delete]
                success = run_execute("DELETE FROM exceptions WHERE exception_id = %s", (exception_id,))
                if success:
                    st.success("예외가 삭제되었습니다.")
                    st.rerun()
                else:
                    st.error("삭제에 실패했습니다.")

        # 만료된 예외
        if expired:
            st.divider()
            st.markdown("#### ⏰ 만료된 예외 항목")
            df_expired = pd.DataFrame(expired)
            df_expired['valid_date'] = pd.to_datetime(df_expired['valid_date']).dt.strftime('%Y-%m-%d')
            df_expired = df_expired.rename(columns={
                'exception_id': 'ID',
                'server_id': '서버',
                'item_code': '항목코드',
                'title': '항목명',
                'severity': '중요도',
                'reason': '예외 사유',
                'valid_date': '만료일',
            })
            st.dataframe(df_expired, width="stretch", hide_index=True)
    else:
        st.info("예외 처리된 항목이 없습니다.")

# ============================================================
# Tab 2: 예외 등록
# ============================================================
with tab2:
    st.subheader("새 예외 등록")

    # 서버 선택
    servers = run_query("SELECT server_id FROM servers WHERE is_active = 1")
    if not servers:
        st.warning("등록된 서버가 없습니다.")
        st.stop()

    server_list = [s['server_id'] for s in servers]
    selected_server = st.selectbox("서버 선택", options=server_list)

    # 항목 선택 (현재 취약한 항목만)
    vuln_items = run_query("""
        SELECT DISTINCT sh.item_code, ki.title
        FROM scan_history sh
        JOIN kisa_items ki ON sh.item_code = ki.item_code
        WHERE sh.server_id = %s
          AND sh.status = '취약'
          AND sh.scan_date = (
              SELECT MAX(scan_date) FROM scan_history WHERE server_id = %s
          )
        ORDER BY sh.item_code
    """, (selected_server, selected_server))

    if vuln_items:
        item_options = {f"{v['item_code']} - {v['title']}": v['item_code'] for v in vuln_items}
        selected_item = st.selectbox("예외 처리할 항목", options=list(item_options.keys()))
        item_code = item_options[selected_item]
    else:
        st.info(f"{selected_server}에 취약한 항목이 없습니다.")
        st.stop()

    # 예외 사유
    reason = st.text_area("예외 사유", placeholder="예: 개발 서버로 root 접속이 필요하여 예외 처리합니다.")

    # 만료일
    valid_date = st.date_input("예외 만료일", value=datetime.now() + timedelta(days=180))

    # 등록 버튼
    if st.button("예외 등록", type="primary"):
        if not reason.strip():
            st.error("예외 사유를 입력해주세요.")
        else:
            success = run_execute(
                """
                INSERT INTO exceptions (server_id, item_code, reason, valid_date)
                VALUES (%s, %s, %s, %s)
                """,
                (selected_server, item_code, reason.strip(), valid_date.strftime('%Y-%m-%d 00:00:00'))
            )
            if success:
                st.success(f"{item_code} 항목이 예외 등록되었습니다. (만료: {valid_date})")
                st.rerun()
            else:
                st.error("예외 등록에 실패했습니다.")