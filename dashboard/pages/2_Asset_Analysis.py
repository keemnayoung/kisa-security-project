"""
2_Asset_Analysis.py
SECURITYCORE - 자산 분석/관리
"""

import json
import os
import re
import sys
import pandas as pd
import streamlit as st

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "components"))
from db_helper import run_query

# ============================================================
# 설정 상수 (하드코딩 중앙화)
# ============================================================
PAGE_TITLE = "SECURITYCORE - Assets"
PAGE_ICON = "🛡️"
LEFT_LIST_HEIGHT = 650
TABLE_ROW_HEIGHT = 40
TABLE_BASE_HEIGHT = 50
TABLE_MAX_HEIGHT = 450
REASON_MAX_LEN = 220

DOMAIN_LINUX = "Linux"
DOMAIN_DB = "DB"
DOMAIN_TAB_LABELS = ["🐧 Linux", "🗄️ Database"]

TEXT_NO_LINUX_ITEMS = "🐧 Linux 점검 항목이 없습니다."
TEXT_NO_DB_ITEMS = "🗄️ Database 점검 항목이 없습니다."
TEXT_NO_SERVERS = "⚠️ 등록된 활성 서버가 없습니다."
TEXT_NO_SCAN_HISTORY = "해당 서버의 점검 이력이 없습니다. 점검을 실행해주세요."
TEXT_SEARCH_NO_RESULT = "검색 결과가 없습니다."
TEXT_ASSETS = "ASSETS"

# ============================================================
# 페이지 설정
# ============================================================
st.set_page_config(
    page_title=PAGE_TITLE,
    page_icon=PAGE_ICON,
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
        padding-top: 1.5rem !important;
        padding-bottom: 2rem !important;
        max-width: 100% !important;
    }
    
    /* 배경색 */
    .stApp {
        background: #f8f9fa !important;
    }
    
    /* 헤더/푸터 숨기기 */
    #MainMenu, footer, header {
        visibility: hidden;
    }
    
    /* 사이드바 스타일 */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a2332 0%, #0f1419 100%) !important;
    }
    
    /* 좌측 서버 목록 패널 */
    .server-list-panel {
        background: white;
        border-radius: 12px;
        border: 1px solid #e5e7eb;
        padding: 16px;
        height: calc(100vh - 120px);
        overflow-y: auto;
    }
    
    .server-list-header {
        font-size: 11px;
        font-weight: 700;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid #e5e7eb;
    }
    
    /* 서버 카드 - 기본 */
    .server-card {
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 12px 14px;
        margin-bottom: 8px;
        cursor: pointer;
        transition: all 0.2s ease;
    }
    
    .server-card:hover {
        border-color: #d1d5db;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    }
    
    /* 서버 카드 - 선택됨 */
    .server-card.active {
        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
        border-color: #2563eb;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
    }
    
    .server-card-name {
        font-size: 13px;
        font-weight: 700;
        color: #111827;
        margin-bottom: 4px;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .server-card.active .server-card-name {
        color: white !important;
    }
    
    .server-card-ip {
        font-size: 11px;
        color: #6b7280;
        margin-bottom: 8px;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .server-card.active .server-card-ip {
        color: rgba(255, 255, 255, 0.85) !important;
    }
    
    .server-card-footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-top: 8px;
        border-top: 1px solid #e5e7eb;
    }
    
    .server-card.active .server-card-footer {
        border-top-color: rgba(255, 255, 255, 0.2);
    }
    
    .server-card-score {
        font-size: 16px;
        font-weight: 800;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .score-excellent { color: #10b981; }
    .score-good { color: #3b82f6; }
    .score-warning { color: #f59e0b; }
    .score-danger { color: #ef4444; }
    
    .server-card.active .server-card-score {
        color: white !important;
    }
    
    .server-card-status {
        font-size: 9px;
        font-weight: 700;
        padding: 3px 8px;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.3px;
        background: rgba(16, 185, 129, 0.1);
        color: #10b981;
    }
    
    .server-card.active .server-card-status {
        background: rgba(255, 255, 255, 0.2);
        color: white;
    }
    
    /* 서버 상세 헤더 */
    .server-detail-header {
        background: white;
        border-radius: 12px;
        border: 1px solid #e5e7eb;
        padding: 20px 24px;
        margin-bottom: 16px;
    }
    
    .server-detail-title {
        font-size: 20px;
        font-weight: 800;
        color: #111827;
        margin-bottom: 12px;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .server-detail-meta {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
    }
    
    .meta-item {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        color: #6b7280;
        font-weight: 500;
    }
    
    .meta-icon {
        font-size: 13px;
    }
    
    .meta-divider {
        width: 1px;
        height: 10px;
        background: #d1d5db;
    }
    
    /* 탭 스타일 */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0px;
        background: transparent;
        border-bottom: 2px solid #e5e7eb;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 0;
        padding: 12px 24px;
        font-weight: 600;
        font-size: 13px;
        color: #6b7280;
        border: none;
        background: transparent;
        border-bottom: 2px solid transparent;
        margin-bottom: -2px;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        color: #111827;
    }
    
    .stTabs [aria-selected="true"] {
        color: #2563eb !important;
        border-bottom: 2px solid #2563eb !important;
        background: transparent !important;
    }
    
    /* 카테고리 섹션 */
    .category-section {
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        margin-bottom: 12px;
        overflow: hidden;
    }
    
    .category-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 18px;
        background: #f9fafb;
        cursor: pointer;
        border-bottom: 1px solid #e5e7eb;
    }
    
    .category-title {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 13px;
        font-weight: 700;
        color: #111827;
    }
    
    .category-icon {
        font-size: 16px;
    }
    
    .category-stats {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    
    .stat-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .badge-vuln {
        background: #fef2f2;
        color: #dc2626;
    }
    
    .badge-pass {
        background: #f0fdf4;
        color: #16a34a;
    }
    
    .badge-total {
        background: #f3f4f6;
        color: #6b7280;
    }
    
    /* 데이터프레임 스타일 */
    [data-testid="stDataFrame"] {
        border: none !important;
    }
    
    [data-testid="stDataFrame"] th {
        background: #f9fafb !important;
        color: #6b7280 !important;
        font-weight: 700 !important;
        font-size: 11px !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
        padding: 12px 14px !important;
        border-bottom: 1px solid #e5e7eb !important;
    }
    
    [data-testid="stDataFrame"] td {
        padding: 12px 14px !important;
        font-size: 12px !important;
        color: #111827 !important;
        border-bottom: 1px solid #f3f4f6 !important;
    }
    
    /* 상태 배지 */
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.3px;
    }
    
    .status-safe {
        background: #f0fdf4;
        color: #16a34a;
    }
    
    .status-vulnerable {
        background: #fef2f2;
        color: #dc2626;
    }
    
    /* 중요도 배지 */
    .severity-badge {
        display: inline-flex;
        align-items: center;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.3px;
    }
    
    .severity-high {
        background: #fef2f2;
        color: #dc2626;
    }
    
    .severity-medium {
        background: #fffbeb;
        color: #d97706;
    }
    
    .severity-low {
        background: #eff6ff;
        color: #2563eb;
    }
    
    /* 검색 입력 */
    .stTextInput > div > div > input {
        border-radius: 8px !important;
        border: 1px solid #e5e7eb !important;
        padding: 10px 14px !important;
        font-size: 12px !important;
        transition: all 0.2s !important;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #2563eb !important;
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1) !important;
    }
    
    /* 컨테이너 스크롤바 */
    .server-list-panel::-webkit-scrollbar {
        width: 6px;
    }
    
    .server-list-panel::-webkit-scrollbar-track {
        background: #f3f4f6;
        border-radius: 3px;
    }
    
    .server-list-panel::-webkit-scrollbar-thumb {
        background: #d1d5db;
        border-radius: 3px;
    }
    
    .server-list-panel::-webkit-scrollbar-thumb:hover {
        background: #9ca3af;
    }
    
    /* 인포 메시지 */
    .stInfo {
        background: #eff6ff !important;
        border-left: 3px solid #3b82f6 !important;
        border-radius: 8px !important;
        padding: 14px 18px !important;
        color: #1e40af !important;
    }
    
    /* 경고 메시지 */
    .stWarning {
        background: #fffbeb !important;
        border-left: 3px solid #f59e0b !important;
        border-radius: 8px !important;
        padding: 14px 18px !important;
        color: #92400e !important;
    }
</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# 헬퍼 함수
# ============================================================
def _extract_reason(raw_evidence):
    """증적 데이터에서 판단 근거 추출"""
    if not raw_evidence:
        return "-"

    if isinstance(raw_evidence, str) and raw_evidence.startswith("/"):
        if os.path.exists(raw_evidence):
            try:
                with open(raw_evidence, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                raw_evidence = payload.get("raw_evidence", raw_evidence)
            except Exception:
                return "증적 파싱 실패"
        else:
            return "legacy 경로 데이터(파일 삭제됨)"

    parsed = raw_evidence
    for _ in range(3):
        if not isinstance(parsed, str):
            break
        try:
            parsed = json.loads(parsed)
        except Exception:
            break

    if isinstance(parsed, dict):
        detail = str(parsed.get("detail", "")).strip()
        if detail:
            return detail.splitlines()[0].strip()[:REASON_MAX_LEN]

    if isinstance(raw_evidence, str):
        m = re.search(r'"detail"\s*:\s*"(?P<detail>.*?)"\s*,\s*"target_file"', raw_evidence, re.DOTALL)
        if not m:
            m = re.search(r'"detail"\s*:\s*"(?P<detail>.*?)"\s*(,|\})', raw_evidence, re.DOTALL)
        if m:
            detail = m.group("detail").replace("\\n", "\n").replace('\\"', '"').strip()
            if detail:
                return detail.splitlines()[0].strip()[:REASON_MAX_LEN]

    return "-"


def _normalize_category(raw):
    """카테고리 정규화"""
    text = str(raw or "").strip().lower().replace(" ", "")
    return text


# 카테고리 매핑
LINUX_CATEGORY_MAP = {
    "계정관리": "계정 관리",
    "account": "계정 관리",
    "파일및디렉토리관리": "파일 및 디렉토리 관리",
    "directory": "파일 및 디렉토리 관리",
    "서비스관리": "서비스 관리",
    "service": "서비스 관리",
    "패치관리": "패치 관리",
    "patch": "패치 관리",
    "로그관리": "로그 관리",
    "log": "로그 관리",
}

DB_CATEGORY_MAP = {
    "계정관리": "계정 관리",
    "account": "계정 관리",
    "접근관리": "접근 관리",
    "access": "접근 관리",
    "옵션관리": "옵션 관리",
    "option": "옵션 관리",
    "패치관리": "패치 관리",
    "patch": "패치 관리",
}

LINUX_ORDER = ["계정 관리", "파일 및 디렉토리 관리", "서비스 관리", "패치 관리", "로그 관리"]
DB_ORDER = ["계정 관리", "접근 관리", "옵션 관리", "패치 관리"]

# 카테고리 아이콘
CATEGORY_ICONS = {
    "계정 관리": "👤",
    "파일 및 디렉토리 관리": "📁",
    "서비스 관리": "⚙️",
    "패치 관리": "🔧",
    "로그 관리": "📋",
    "접근 관리": "🔐",
    "옵션 관리": "⚡",
    "기타": "📦",
}

# DB 타입별 적용 항목 룰 (현재 구현된 DB 항목 기준)
DB_ITEM_COMPATIBILITY = {
    "D-01": "postgres",
    "D-04": "mysql",
}


def _to_domain_category(domain, raw_category):
    """도메인별 카테고리 변환"""
    normalized = _normalize_category(raw_category)
    if domain == DOMAIN_LINUX:
        return LINUX_CATEGORY_MAP.get(normalized, "기타")
    return DB_CATEGORY_MAP.get(normalized, "기타")


def _group_items_for_domain(items, domain):
    """도메인별 항목 그룹화"""
    grouped = {k: [] for k in (LINUX_ORDER if domain == DOMAIN_LINUX else DB_ORDER)}
    grouped["기타"] = []
    for item in items:
        label = _to_domain_category(domain, item.get("category"))
        grouped.setdefault(label, []).append(item)
    return grouped


def _is_item_compatible_with_server_db(item_code, server_db_type):
    """DB 항목 호환성 체크"""
    code = str(item_code or "").upper()
    dbt = str(server_db_type or "").lower()
    required = DB_ITEM_COMPATIBILITY.get(code)
    if not required:
        return True
    return required in dbt


def render_category_table(cat, rows, domain_key, default_open=False):
    """카테고리별 테이블 렌더링"""
    vuln_cnt = sum(1 for r in rows if r.get("status") == "취약")
    pass_cnt = sum(1 for r in rows if r.get("status") == "양호")
    state_key = f"asset_cat_open_{domain_key}_{cat}"
    if state_key not in st.session_state:
        st.session_state[state_key] = default_open

    is_open = st.session_state[state_key]
    arrow = "▾" if is_open else "▸"
    header_label = f"{CATEGORY_ICONS.get(cat, '📦')} {cat}  |  취약 {vuln_cnt}건 / 양호 {pass_cnt}건 / 전체 {len(rows)}건  {arrow}"

    if st.button(header_label, key=f"{state_key}_btn", width="stretch", type="tertiary"):
        st.session_state[state_key] = not st.session_state[state_key]
        st.rerun()

    # 테이블 표시
    if st.session_state[state_key]:
        view = []
        for r in rows:
            view.append({
                "코드": r["item_code"],
                "항목명": r["title"],
                "중요도": r["severity"],
                "결과": r["status"],
                "판단근거": r["reason"],
            })
        
        df = pd.DataFrame(view)
        st.dataframe(
            df,
            width="stretch",
            hide_index=True,
            height=min(TABLE_MAX_HEIGHT, len(df) * TABLE_ROW_HEIGHT + TABLE_BASE_HEIGHT),
            column_config={
                "중요도": st.column_config.Column(width="small"),
                "결과": st.column_config.Column(width="small"),
                "판단근거": st.column_config.Column(width="large"),
            }
        )


# ============================================================
# 데이터 로드
# ============================================================
@st.cache_data(ttl=300)
def load_servers():
    """서버 목록 로드"""
    return run_query(
        """
        SELECT server_id, company, hostname, ip_address, os_type, db_type
        FROM servers
        WHERE is_active = 1
        ORDER BY company, server_id
        """
    )


servers = load_servers()
if not servers:
    st.warning(TEXT_NO_SERVERS)
    st.stop()


# ============================================================
# 레이아웃: 서버 목록 (좌) + 상세 정보 (우)
# ============================================================
left_col, right_col = st.columns([1, 3.5], gap="medium")

# ============================================================
# 좌측: 서버 목록
# ============================================================
with left_col:
    # 검색
    search_query = st.text_input(
        "",
        placeholder="🔍 서버ID, IP, 호스트명으로 검색",
        key="asset_live_search",
        label_visibility="collapsed",
    )
    
    # 검색 필터링
    search_term = (search_query or "").lower().strip()
    filtered_servers = []
    for s in servers:
        search_text = f"{s['server_id']} {s['hostname']} {s['ip_address']} {s['company']}".lower()
        if search_term in search_text:
            filtered_servers.append(s)
    
    # 선택된 서버 상태 관리
    if "asset_selected_server" not in st.session_state:
        st.session_state.asset_selected_server = filtered_servers[0]["server_id"] if filtered_servers else servers[0]["server_id"]
    
    if not filtered_servers:
        st.info(TEXT_SEARCH_NO_RESULT)
    else:
        # 현재 선택 서버가 필터 결과에 없으면 첫 행으로 자동 보정
        filtered_ids = [s["server_id"] for s in filtered_servers]
        if st.session_state.asset_selected_server not in filtered_ids:
            st.session_state.asset_selected_server = filtered_ids[0]

        # 서버 목록 패널 (Streamlit 컨테이너 사용)
        st.markdown(f"**{TEXT_ASSETS}**")
        list_container = st.container(height=LEFT_LIST_HEIGHT, border=True)
        with list_container:
            for s in filtered_servers:
                sid = s["server_id"]
                ip = s["ip_address"]
                selected = (sid == st.session_state.asset_selected_server)
                label = f"{'● ' if selected else ''}{sid}  {ip}"
                btn_type = "primary" if selected else "secondary"
                if st.button(label, key=f"btn_{sid}", width="stretch", type=btn_type):
                    if sid != st.session_state.asset_selected_server:
                        st.session_state.asset_selected_server = sid
                        st.rerun()


# ============================================================
# 우측: 서버 상세 정보
# ============================================================
selected_server = st.session_state.asset_selected_server
selected_info = next((s for s in servers if s["server_id"] == selected_server), servers[0])

# 최신 점검 시각 조회
latest_scan_row = run_query(
    "SELECT MAX(scan_date) AS latest FROM scan_history WHERE server_id = %s",
    (selected_server,)
)
latest_scan = latest_scan_row[0]["latest"] if latest_scan_row and latest_scan_row[0]["latest"] else None

with right_col:
    if not latest_scan:
        st.markdown(
            f"""
        <div class="server-detail-header">
            <div class="server-detail-title">⚠️ 점검 이력 없음</div>
            <div class="meta-item">{TEXT_NO_SCAN_HISTORY}</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        st.stop()
    
    # 서버 상세 헤더
    st.markdown(
        f"""
    <div class="server-detail-header">
        <div class="server-detail-title">{selected_info['server_id']} • {selected_info['ip_address']}</div>
        <div class="server-detail-meta">
            <div class="meta-item">
                <span class="meta-icon">💻</span>
                <span>{selected_info.get('os_type') or '-'}</span>
            </div>
            <div class="meta-divider"></div>
            <div class="meta-item">
                <span class="meta-icon">🗄️</span>
                <span>{selected_info.get('db_type') or 'DB 없음'}</span>
            </div>
            <div class="meta-divider"></div>
            <div class="meta-item">
                <span class="meta-icon">📅</span>
                <span>마지막 점검: {latest_scan.strftime('%Y-%m-%d %H:%M')}</span>
            </div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )
    
    # 도메인 선택 탭
    domain_tabs = st.tabs(DOMAIN_TAB_LABELS)
    
    # 점검 항목 조회
    items = run_query(
        """
        SELECT sh.item_code, sh.status, sh.raw_evidence, ki.title, ki.category, ki.severity, sh.scan_date
        FROM scan_history sh
        JOIN (
            SELECT server_id, item_code, MAX(scan_date) AS max_scan_date
            FROM scan_history
            WHERE server_id = %s
            GROUP BY server_id, item_code
        ) latest
          ON sh.server_id = latest.server_id
         AND sh.item_code = latest.item_code
         AND sh.scan_date = latest.max_scan_date
        JOIN kisa_items ki ON ki.item_code = sh.item_code
        WHERE sh.server_id = %s
        ORDER BY sh.item_code
        """,
        (selected_server, selected_server),
    )
    
    # 데이터 전처리
    for row in items:
        row["reason"] = _extract_reason(row.get("raw_evidence"))
        code = str(row["item_code"])
        row["domain"] = DOMAIN_LINUX if code.startswith("U-") or code.startswith("U") else DOMAIN_DB
    
    # Linux 탭
    with domain_tabs[0]:
        linux_items = [r for r in items if r["domain"] == DOMAIN_LINUX]
        
        if not linux_items:
            st.info(TEXT_NO_LINUX_ITEMS)
        else:
            grouped = _group_items_for_domain(linux_items, DOMAIN_LINUX)
            
            for cat in LINUX_ORDER + ["기타"]:
                rows = grouped.get(cat, [])
                if not rows:
                    continue
                render_category_table(cat, rows, "linux", default_open=(cat == LINUX_ORDER[0]))
    
    # DB 탭
    with domain_tabs[1]:
        db_items = [r for r in items if r["domain"] == DOMAIN_DB]
        db_items = [
            r for r in db_items
            if _is_item_compatible_with_server_db(r.get("item_code"), selected_info.get("db_type"))
        ]
        
        if not db_items:
            st.info(TEXT_NO_DB_ITEMS)
        else:
            grouped = _group_items_for_domain(db_items, DOMAIN_DB)
            
            for cat in DB_ORDER + ["기타"]:
                rows = grouped.get(cat, [])
                if not rows:
                    continue
                render_category_table(cat, rows, "db", default_open=(cat == DB_ORDER[0]))
