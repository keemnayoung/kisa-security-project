#!/usr/bin/env python3
"""
DB에서 자산 정보를 읽어 Ansible inventory 및 group_vars를 자동 생성
- db_passwd는 hosts.ini에 평문으로 쓰지 않고 host_vars/vault.yml에 Ansible Vault로 암호화
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from collections import defaultdict

backend_dir = Path(__file__).resolve().parent
current_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(current_dir))

from db.connection import run_query
from config import ANSIBLE_INVENTORY, get_db_port, get_db_user, normalize_db_type
from services.encryption import decrypt_password

HOSTS_INI = Path(ANSIBLE_INVENTORY)
GROUP_VARS_DIR = HOSTS_INI.parent / "group_vars"
HOST_VARS_DIR = HOSTS_INI.parent / "host_vars"
VAULT_PASS_FILE = HOSTS_INI.parent.parent / ".vault_pass"


def fetch_active_servers():
    """DB에서 활성화된 서버 목록 조회"""
    sql = """
    SELECT server_id, company, hostname, ip_address, ssh_port, os_type,
           db_type, db_port, db_user, db_passwd
    FROM servers
    WHERE is_active = 1
    ORDER BY company, server_id
    """
    result = run_query(sql)
    return result if result else []


def _vault_encrypt_file(file_path: Path) -> bool:
    """ansible-vault encrypt로 파일 암호화 (in-place)"""
    if not VAULT_PASS_FILE.exists():
        print(f"⚠️  Vault password file not found: {VAULT_PASS_FILE}")
        return False

    try:
        subprocess.run(
            ["ansible-vault", "encrypt",
             "--vault-password-file", str(VAULT_PASS_FILE),
             str(file_path)],
            check=True,
            capture_output=True,
            text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Vault encrypt failed: {e.stderr}")
        return False


def generate_host_vars(servers):
    """호스트별 vault.yml 생성 (db_passwd 암호화 저장)"""
    HOST_VARS_DIR.mkdir(parents=True, exist_ok=True)

    for srv in servers:
        server_id = srv["server_id"]
        db_type = srv.get("db_type")
        raw_passwd = srv.get("db_passwd") or ""

        if not db_type or not raw_passwd:
            continue

        # DB 비밀번호 복호화 (Fernet → 평문)
        db_passwd_plain = ""
        if raw_passwd != "VAULT_MANAGED":
            try:
                db_passwd_plain = decrypt_password(raw_passwd)
            except Exception as e:
                print(f"⚠️  {server_id}: DB 비밀번호 복호화 실패 ({e}), 원본 사용")
                db_passwd_plain = raw_passwd

        if not db_passwd_plain:
            continue

        # host_vars/<hostname>/ 디렉토리 생성
        host_name = str(server_id)
        host_dir = HOST_VARS_DIR / host_name
        host_dir.mkdir(parents=True, exist_ok=True)

        vault_file = host_dir / "vault.yml"

        # 평문 YAML 작성 후 ansible-vault encrypt
        vault_file.write_text(f"db_passwd: \"{db_passwd_plain}\"\n")

        if _vault_encrypt_file(vault_file):
            print(f"  🔒 {host_name}: vault.yml 암호화 완료")
        else:
            # 암호화 실패 시 평문 파일 삭제 (보안)
            vault_file.unlink(missing_ok=True)
            print(f"  ❌ {host_name}: vault.yml 암호화 실패, 파일 삭제됨")


def generate_hosts_ini(servers):
    """hosts.ini 파일 생성 (db_passwd 제외)"""
    groups = defaultdict(list)

    for srv in servers:
        server_id = srv["server_id"]
        company = srv["company"]
        ip = srv["ip_address"]
        ssh_port = srv.get("ssh_port", 22)
        os_type = srv.get("os_type", "")
        db_type = srv.get("db_type")

        host_name = str(server_id)
        actual_hostname = str(srv.get("hostname") or "").strip()

        # 호스트 라인 생성 (db_passwd 제외 — vault로 관리)
        host_line = (
            f"{host_name} "
            f"ansible_host={ip} "
            f"ansible_port={ssh_port} "
            f"ansible_user=manager "
            f"server_id={server_id} "
            f"company={company}"
        )
        if actual_hostname:
            host_line += f" real_hostname={actual_hostname}"

        # 그룹 분류
        # OS 그룹
        if "rocky" in os_type.lower():
            if "9" in os_type:
                groups["rocky9"].append(host_line)
            elif "10" in os_type:
                groups["rocky10"].append(host_line)
            else:
                groups["rocky"].append(host_line)
        elif "ubuntu" in os_type.lower():
            groups["ubuntu"].append(host_line)
        elif "centos" in os_type.lower():
            groups["centos"].append(host_line)

        # DB 그룹
        if db_type:
            normalized_db = normalize_db_type(db_type)
            if normalized_db == "mysql":
                groups["rocky9_mysql"].append(host_line)
            elif normalized_db == "postgresql":
                groups["rocky10_postgres"].append(host_line)

    # hosts.ini 파일 작성
    content = "# Auto-generated by sync_inventory.py\n"
    content += "# Do not edit manually - changes will be overwritten\n"
    content += "# NOTE: db_passwd is stored in host_vars/<host>/vault.yml (Ansible Vault encrypted)\n\n"

    content += "[all:vars]\n"
    content += "ansible_python_interpreter=/usr/bin/python3\n\n"

    for group_name, hosts in sorted(groups.items()):
        content += f"[{group_name}]\n"
        for host in hosts:
            content += f"{host}\n"
        content += "\n"

    HOSTS_INI.parent.mkdir(parents=True, exist_ok=True)
    HOSTS_INI.write_text(content)
    print(f"✅ Generated: {HOSTS_INI}")
    return groups


def generate_group_vars(servers, groups):
    """group_vars 파일 생성"""
    GROUP_VARS_DIR.mkdir(parents=True, exist_ok=True)

    # rocky9_mysql.yml 생성
    if "rocky9_mysql" in groups:
        # 첫 번째 MySQL 서버의 사용자 정보 사용
        mysql_user = get_db_user("mysql")
        for srv in servers:
            if normalize_db_type(srv.get("db_type", "")) == "mysql":
                mysql_user = srv.get("db_user") or get_db_user("mysql")
                break

        mysql_port = get_db_port("mysql")
        mysql_content = f"""# MySQL/MariaDB 공통 설정
db_type: mysql
db_port: {mysql_port}
db_user: {mysql_user}
"""
        mysql_file = GROUP_VARS_DIR / "rocky9_mysql.yml"
        mysql_file.write_text(mysql_content)
        print(f"✅ Generated: {mysql_file}")

    # rocky10_postgres.yml 생성
    if "rocky10_postgres" in groups:
        pg_user = get_db_user("postgresql")
        pg_port = get_db_port("postgresql")
        pg_content = f"""# PostgreSQL 공통 설정
db_type: postgresql
db_port: {pg_port}
db_user: {pg_user}
db_name: postgres
"""
        pg_file = GROUP_VARS_DIR / "rocky10_postgres.yml"
        pg_file.write_text(pg_content)
        print(f"✅ Generated: {pg_file}")


def main():
    print("=" * 60)
    print("🔄 Syncing Ansible Inventory from Database")
    print("=" * 60)

    servers = fetch_active_servers()
    if not servers:
        print("⚠️  No active servers found in database")
        return

    print(f"📊 Found {len(servers)} active server(s)")

    groups = generate_hosts_ini(servers)
    generate_host_vars(servers)
    generate_group_vars(servers, groups)

    print("=" * 60)
    print("✅ Inventory sync completed!")
    print(f"   hosts.ini:  {HOSTS_INI}")
    print(f"   host_vars:  {HOST_VARS_DIR}")
    print(f"   group_vars: {GROUP_VARS_DIR}")
    print("=" * 60)

if __name__ == "__main__":
    main()
