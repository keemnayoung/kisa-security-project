"""
4_Asset_Reg.py
SECURITYCORE - 자산 등록/관리
"""

import streamlit as st
import pandas as pd
import sys, os
import subprocess
import socket
from pathlib import Path

ANSIBLE_CFG = "/home/manager/kisa-security-project/ansible/ansible.cfg"
VAULT_PASS_FILE = os.getenv(
    "ANSIBLE_VAULT_PASSWORD_FILE",
    "/home/manager/kisa-security-project/ansible/.vault_pass"
)


def vault_encrypt_string(plain: str, varname: str = "db_passwd") -> str:
    if not plain:
        return None

    vault_path = Path(VAULT_PASS_FILE)
    if not vault_path.exists():
        raise RuntimeError(f"Vault password file not found: {VAULT_PASS_FILE}")

    env = os.environ.copy()
    env["ANSIBLE_CONFIG"] = ANSIBLE_CFG

    cmd = [
        "ansible-vault", "encrypt_string",
        "--encrypt-vault-id", "default",
        "--vault-password-file", str(vault_path),
        "--name", varname
    ]

    try:
        p = subprocess.run(
            cmd,
            input=plain + "\n",   # ← 이게 중요합니다 (개행 포함)
            capture_output=True,
            text=True,
            timeout=10,
            env=env
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("ansible-vault encrypt_string timeout (10s)")

    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).strip())

    return p.stdout.strip()


def run_ansible_ping(ip, ssh_user, ssh_port, timeout_sec=10):
    env = os.environ.copy()
    env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    env["ANSIBLE_TIMEOUT"] = "5"
    cmd = ["ansible","all","-i",f"{ip},","-m","ping","-u",ssh_user,"-e",f"ansible_port={ssh_port}"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, env=env)

        out = (p.stdout or "") + "\n" + (p.stderr or "")
        ok = ("SUCCESS" in out) and ("UNREACHABLE" not in out) and (p.returncode == 0)
        return ok, out.strip()
    except subprocess.TimeoutExpired:
        return False, f"Timeout: ansible ping exceeded {timeout_sec}s"

def tcp_port_check(ip: str, port: str, timeout_sec: int = 2) -> bool:
    """
    DB 포트 오픈 여부만 빠르게 체크(자격증명 불필요).
    """
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout_sec):
            return True
    except Exception:
        return False

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'components'))
from db_helper import run_query, run_execute

st.set_page_config(page_title="SECURITYCORE - Asset Reg", page_icon="🛡️", layout="wide")

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
    .section-title {
        font-size: 16px; font-weight: 700; color: #1a2332;
        margin: 20px 0 16px 0; display: flex; align-items: center; gap: 8px;
    }
    .table-container {
        background: white; border-radius: 16px; padding: 20px 24px;
        border: 1px solid #eef0f4; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .form-container {
        background: white; border-radius: 16px; padding: 28px;
        border: 1px solid #eef0f4; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        .asset-card {
  background: #ffffff;
  border: 1px solid #eef0f4;
  box-shadow: 0 18px 40px rgba(15, 23, 42, 0.08);
  border-radius: 22px;
  padding: 26px 28px;
  max-width: 860px;
  margin: 18px auto 0 auto;
}

.asset-head {
  display:flex; align-items:center; gap:14px;
  padding-bottom: 14px;
  border-bottom: 1px solid #f1f3f8;
  margin-bottom: 18px;
}
.asset-icon {
  width: 44px; height: 44px;
  border-radius: 14px;
  background: #2563eb;
  display:flex; align-items:center; justify-content:center;
  color:#fff; font-size: 20px;
}
.asset-title { margin:0; font-weight:800; font-size:22px; color:#111827; line-height:1.1; }
.asset-sub { margin:4px 0 0 0; font-size:11px; letter-spacing: .10em; color:#94a3b8; font-weight:800; }

/* 카드 내부 입력 위젯 스타일 */
.asset-card div[data-testid="stTextInput"] input,
.asset-card div[data-testid="stSelectbox"] div[role="combobox"],
.asset-card div[data-testid="stNumberInput"] input {
  background: #f3f5f9 !important;
  border: 1px solid #e6e9f2 !important;
  border-radius: 14px !important;
  padding: 10px 12px !important;
}

.asset-card label {
  color:#475569 !important;
  font-weight:700 !important;
}

.asset-divider {
  height: 1px;
  background: #f1f3f8;
  margin: 14px 0;
}

/* Stepper */
.stepper {
  background: #f8fafc;
  border: 1px solid #eef2f7;
  border-radius: 16px;
  padding: 14px 16px;
  margin-top: 14px;
}
.stepper-row {
  display:flex; align-items:center; justify-content:space-between;
  font-size: 12px; color:#64748b; font-weight:800;
}
.step-dot {
  width: 22px; height: 22px; border-radius: 999px;
  background:#e2e8f0; color:#475569;
  display:flex; align-items:center; justify-content:center;
  font-size: 12px; font-weight:900;
}
.step-line {
  flex:1; height: 3px; background:#e2e8f0; margin: 0 10px; border-radius: 99px;
}
.step-item { display:flex; align-items:center; gap:8px; }

.asset-actions .stButton > button {
  border-radius: 14px !important;
  height: 44px !important;
  font-weight: 800 !important;
}
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

st.markdown('<div class="page-header">ASSET REGISTRATION</div>', unsafe_allow_html=True)

tab1, tab2 = st.tabs(["📋 자산 목록", "➕ 신규 등록"])

# ============================================================
# Tab 1: 자산 목록
# ============================================================
with tab1:
    st.markdown('<div class="section-title">🖥️ 등록된 자산</div>', unsafe_allow_html=True)

    servers = run_query("""
        SELECT server_id, company, hostname, ip_address, ssh_port, os_type,
               db_type, db_port, is_active, manager, department
        FROM servers ORDER BY company, server_id
    """)

    if servers:
        df = pd.DataFrame(servers)
        df['is_active'] = df['is_active'].map({1: '✅ 활성', 0: '❌ 비활성'})
        df['db_type'] = df['db_type'].fillna('-')
        df = df.rename(columns={
            'server_id': '자산명', 'company': '회사', 'hostname': '계정',
            'ip_address': 'IP', 'ssh_port': 'SSH', 'os_type': 'OS',
            'db_type': 'DB', 'db_port': 'DB포트', 'is_active': '상태',
            'manager': '담당자', 'department': '부서'
        })
        st.markdown('<div class="table-container">', unsafe_allow_html=True)
        st.dataframe(df[['자산명', '회사', 'IP', 'OS', 'DB', '상태', '담당자', '부서']], width="stretch", hide_index=True)
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("등록된 자산이 없습니다.")

# ============================================================
# Tab 2: 신규 자산 등록
# ============================================================
with tab2:
    # ====== 카드 UI 시작 ======
    st.markdown("""
    <div class="asset-card">
      <div class="asset-head">
        <div class="asset-icon">＋</div>
        <div>
          <div class="asset-title">신규 자산 등록</div>
          <div class="asset-sub">ASSET PROVISIONING</div>
        </div>
      </div>
    """, unsafe_allow_html=True)

    # 초기값/키
    form_keys = [
        "f_server_id","f_ip","f_os","f_db_type",
        "f_company","f_manager","f_dept",
        "f_ssh_user","f_ssh_port",
        "f_db_port","f_db_user","f_db_passwd",
        "f_key_preloaded"
    ]
    for k in form_keys:
        st.session_state.setdefault(k, "")

    # 기본값
    if not st.session_state["f_ssh_port"]:
        st.session_state["f_ssh_port"] = "22"
    if not st.session_state["f_os"]:
        st.session_state["f_os"] = "Rocky Linux 9.7"
    if not st.session_state.get("f_db_type"):
        st.session_state["f_db_type"] = "없음"
    if st.session_state.get("f_key_preloaded","") == "":
        st.session_state["f_key_preloaded"] = True

    with st.form("asset_provision_form", clear_on_submit=False):
        c1, c2 = st.columns(2, gap="medium")
        with c1:
            server_id = st.text_input("서버 명칭", placeholder="예: SRV-NAME", key="f_server_id")
        with c2:
            ip_address = st.text_input("IP 주소", placeholder="예: 0.0.0.0", key="f_ip")

        c3, c4, c5 = st.columns(3, gap="medium")
        with c3:
            company = st.text_input("회사명", placeholder="예: NAVER", key="f_company")
        with c4:
            manager_name = st.text_input("담당자", placeholder="예: 홍길동", key="f_manager")
        with c5:
            department = st.text_input("부서명", placeholder="예: 개발팀", key="f_dept")

        c6, c7 = st.columns(2, gap="medium")
        with c6:
            os_type = st.selectbox("운영체제", ["Rocky Linux 9.7", "Rocky Linux 10.1"], key="f_os")
        with c7:
            db_type = st.selectbox("데이터베이스", ["없음", "MySQL 8.0.4", "PostgreSQL 16.11"], key="f_db_type")

        c8, c9 = st.columns(2, gap="medium")
        with c8:
            ssh_user = st.text_input("SSH 계정", placeholder="예: manager", key="f_ssh_user")
        with c9:
            ssh_port = st.text_input("SSH 포트", key="f_ssh_port")

        # 키 배포 시나리오 체크
        is_key_preloaded = st.checkbox("이미 키가 등록된 서버입니다 (비밀번호 생략)", key="f_key_preloaded")

        # DB 입력(옵션)
        db_port = None
        db_user = None
        db_passwd = None

        if db_type != "없음":
            # DB 포트 기본값 자동 설정
            default_port = "3306" if "MySQL" in db_type else "5432"
            if not st.session_state.get("f_db_port"):
                st.session_state["f_db_port"] = default_port

            c10, c11 = st.columns(2, gap="medium")
            with c10:
                db_user = st.text_input("DB 계정", placeholder="예: audit_user", key="f_db_user")
            with c11:
                db_port = st.text_input("DB 포트", key="f_db_port")

            db_passwd = st.text_input("DB 비밀번호 (Vault 암호화 저장)", type="password", key="f_db_passwd")
        else:
            # DB 없는 경우는 값 비워두기
            st.session_state["f_db_user"] = ""
            st.session_state["f_db_port"] = ""
            st.session_state["f_db_passwd"] = ""

        # Stepper (고정 표시)
        st.markdown("""
        <div class="stepper">
          <div class="stepper-row">
            <div class="step-item"><div class="step-dot">1</div><div>SSH 연결</div></div>
            <div class="step-line"></div>
            <div class="step-item"><div class="step-dot">2</div><div>DB 링크</div></div>
            <div class="step-line"></div>
            <div class="step-item"><div class="step-dot">3</div><div>등록 완료</div></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="asset-actions">', unsafe_allow_html=True)
        b1, b2 = st.columns([1, 1], gap="medium")
        with b1:
            clear_clicked = st.form_submit_button("CLEAR", width="stretch")
        with b2:
            register_clicked = st.form_submit_button("REGISTER", type="primary", width="stretch")
        st.markdown('</div>', unsafe_allow_html=True)

    # CLEAR 처리
    if clear_clicked:
        for k in form_keys:
            st.session_state[k] = ""
        st.session_state["f_ssh_port"] = "22"
        st.session_state["f_os"] = "Rocky Linux 9.7"
        st.session_state["f_db_type"] = "없음"
        st.session_state["f_key_preloaded"] = True
        st.rerun()

    # REGISTER 처리
    if register_clicked:
        # 필수값 검증
        required = [server_id, ip_address, company, manager_name, department, ssh_user, ssh_port]
        if not all([str(x).strip() for x in required]):
            st.error("필수 항목(서버명칭/IP/회사명/담당자/부서명/SSH계정/SSH포트)을 모두 입력해주세요.")
        elif db_type != "없음" and (not db_user or not db_port or not db_passwd):
            st.error("DB를 선택하셨다면 DB 계정/포트/비밀번호를 모두 입력해주세요.")
        else:
            # 진행 상태 출력
            status = st.status("자산 등록 프로세스 진행 중...", expanded=True)
            status.write("1) DB 저장...")


            # 1) DB에 우선 등록(비활성) -> 실패 목록 관리에 유리
            # DB 비번은 vault 암호화 문자열로 저장
            try:
                encrypted_db_pw = None
                db_t = None if db_type == "없음" else db_type
                db_p = None if db_type == "없음" else db_port
                db_u = None if db_type == "없음" else db_user

                if db_type != "없음":
                    encrypted_db_pw = vault_encrypt_string(db_passwd, varname="db_passwd")
                else:
                    encrypted_db_pw = None

                with status:
                    st.write("1) DB에 자산 기본정보 저장(초기 상태: 비활성)…")
                inserted = run_execute("""
                    INSERT INTO servers
                    (server_id, company, hostname, ip_address, ssh_port, os_type,
                     db_type, db_port, db_user, db_passwd, is_active, manager, department)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s,%s)
                """, (server_id, company, ssh_user, ip_address, ssh_port, os_type,
                      db_t, db_p, db_u, encrypted_db_pw, manager_name, department))

                if not inserted:
                    status.update(label="등록 실패", state="error")
                    st.error("등록에 실패했습니다. 자산 이름(server_id)이 중복이거나 DB 저장에 문제가 있을 수 있습니다.")
                    st.stop()

                # 2) SSH 연결 확인 (Ping)
                with status:
                    st.write("2) SSH 연결 확인(Ansible Ping)…")
                ok, log = run_ansible_ping(ip_address, ssh_user, ssh_port)

                if not ok:
                    with status:
                        st.code(log)
                        st.error("❌ 연결 실패: 고객사에 키 배포 여부를 확인해주세요. (is_active=0으로 저장됨)")
                    status.update(label="연결 실패", state="error")
                    st.stop()

                # 3) DB 포트 체크(옵션)
                if db_type != "없음":
                    with status:
                        st.write("3) DB 포트 오픈 여부 확인…")
                    port_ok = tcp_port_check(ip_address, db_port)
                    if not port_ok:
                        with status:
                            st.warning(f"⚠️ DB 포트({db_port})가 열려있지 않거나 접근이 제한되어 보입니다. (등록은 진행합니다)")

                # 4) 활성화 업데이트
                with status:
                    st.write("4) 연결 확인 완료 → 자산 활성화 처리…")
                run_execute("""
                    UPDATE servers SET is_active=1
                    WHERE server_id=%s
                """, (server_id,))

                status.update(label="등록 완료", state="complete")
                st.success(f"✅ {server_id} 등록 완료! (Key 인증 기반 Ping 성공)")
                st.rerun()

            except Exception as e:
                status.update(label="오류 발생", state="error")
                st.error(f"처리 중 오류가 발생했습니다: {e}")

    # ====== 카드 UI 종료 ======
    st.markdown("</div>", unsafe_allow_html=True)


    