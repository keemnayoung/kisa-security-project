#!/usr/bin/env python3
"""
Manage dashboard users (hash-based passwords).

Usage examples (run inside venv):
  python3 scripts/manage_users.py list
  python3 scripts/manage_users.py create --username naver1234 --password '...' --role VIEWER --company NAVER
  python3 scripts/manage_users.py set-password --username naver1234 --password '...'
  python3 scripts/manage_users.py set-role --username naver1234 --role ADMIN
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import sys
from datetime import datetime

try:
    import mysql.connector  # from mysql-connector-python
except ModuleNotFoundError as e:
    raise SystemExit(
        "Missing dependency: mysql-connector-python.\n"
        "Run inside the project venv:\n"
        "  source venv/bin/activate\n"
        "  pip install -r requirements.txt\n"
    ) from e

try:
    from dotenv import load_dotenv
except ModuleNotFoundError as e:
    raise SystemExit(
        "Missing dependency: python-dotenv.\n"
        "Run inside the project venv:\n"
        "  source venv/bin/activate\n"
        "  pip install -r requirements.txt\n"
    ) from e


ROLE_ADMIN = "ADMIN"
ROLE_VIEWER = "VIEWER"


def _b64_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def hash_password(password: str, iterations: int = 260_000) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("password required")
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64_nopad(salt)}${_b64_nopad(dk)}"


def load_db_env() -> dict:
    # Load project root .env (works when called from repo root).
    load_dotenv()
    host = os.getenv("DB_HOST", "127.0.0.1")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    database = os.getenv("DB_NAME", "kisa_security")
    if not user or not password:
        raise SystemExit("Missing DB_USER/DB_PASSWORD in .env")
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "database": database,
        "charset": "utf8mb4",
    }


def connect():
    cfg = load_db_env()
    return mysql.connector.connect(**cfg)


def cmd_list(_args) -> int:
    conn = connect()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT user_id, user_name, role, company, last_login, created_at
            FROM users
            ORDER BY user_id
            """
        )
        rows = cur.fetchall()
        if not rows:
            print("(no users)")
            return 0
        for r in rows:
            print(
                f"{r['user_id']:>3}  {r['user_name']:<20}  {r['role']:<6}  {r['company']:<16}  "
                f"last_login={r['last_login']}  created_at={r['created_at']}"
            )
        return 0
    finally:
        conn.close()


def _read_password(p: str | None) -> str:
    if p:
        return p
    p1 = getpass.getpass("Password: ")
    p2 = getpass.getpass("Confirm: ")
    if p1 != p2:
        raise SystemExit("password mismatch")
    return p1


def cmd_create(args) -> int:
    username = args.username.strip()
    company = args.company.strip()
    role = args.role.upper().strip()
    if role not in (ROLE_ADMIN, ROLE_VIEWER):
        raise SystemExit("role must be ADMIN or VIEWER")
    password = _read_password(args.password)
    pw_hash = hash_password(password)

    # Ensure optional policy columns exist if possible (best-effort).
    _ensure_policy_columns()

    conn = connect()
    try:
        cur = conn.cursor()
        cols_force = _has_column(conn, "must_change_password")
        cols_changed = _has_column(conn, "password_changed_at")
        force_change = 0 if args.no_force_change else 1
        if cols_force and cols_changed:
            cur.execute(
                """
                INSERT INTO users (user_name, user_passwd, role, company, must_change_password, password_changed_at, last_login, created_at)
                VALUES (%s, %s, %s, %s, %s, NULL, NOW(), NOW())
                """,
                (username, pw_hash, role, company, force_change),
            )
        elif cols_force:
            cur.execute(
                """
                INSERT INTO users (user_name, user_passwd, role, company, must_change_password, last_login, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                """,
                (username, pw_hash, role, company, force_change),
            )
        else:
            cur.execute(
                """
                INSERT INTO users (user_name, user_passwd, role, company, last_login, created_at)
                VALUES (%s, %s, %s, %s, NOW(), NOW())
                """,
                (username, pw_hash, role, company),
            )
        conn.commit()
        print(f"created user: {username} ({role}, {company})")
        return 0
    except mysql.connector.Error as e:
        conn.rollback()
        raise SystemExit(f"DB error: {e}")
    finally:
        conn.close()


def cmd_set_password(args) -> int:
    username = args.username.strip()
    password = _read_password(args.password)
    pw_hash = hash_password(password)

    _ensure_policy_columns()

    conn = connect()
    try:
        cur = conn.cursor()
        cols_force = _has_column(conn, "must_change_password")
        cols_changed = _has_column(conn, "password_changed_at")
        cols_prev = _has_column(conn, "prev_user_passwd")
        if cols_force and cols_changed:
            if cols_prev:
                cur.execute(
                    "UPDATE users SET prev_user_passwd=user_passwd, user_passwd=%s, must_change_password=0, password_changed_at=NOW() WHERE user_name=%s",
                    (pw_hash, username),
                )
            else:
                cur.execute(
                    "UPDATE users SET user_passwd=%s, must_change_password=0, password_changed_at=NOW() WHERE user_name=%s",
                    (pw_hash, username),
                )
        elif cols_force:
            if cols_prev:
                cur.execute(
                    "UPDATE users SET prev_user_passwd=user_passwd, user_passwd=%s, must_change_password=0 WHERE user_name=%s",
                    (pw_hash, username),
                )
            else:
                cur.execute(
                    "UPDATE users SET user_passwd=%s, must_change_password=0 WHERE user_name=%s",
                    (pw_hash, username),
                )
        else:
            if cols_prev:
                cur.execute(
                    "UPDATE users SET prev_user_passwd=user_passwd, user_passwd=%s WHERE user_name=%s",
                    (pw_hash, username),
                )
            else:
                cur.execute(
                    "UPDATE users SET user_passwd = %s WHERE user_name = %s",
                    (pw_hash, username),
                )
        conn.commit()
        if cur.rowcount != 1:
            raise SystemExit("user not found (or multiple rows updated)")
        print(f"updated password: {username}")
        return 0
    except mysql.connector.Error as e:
        conn.rollback()
        raise SystemExit(f"DB error: {e}")
    finally:
        conn.close()


def cmd_set_role(args) -> int:
    username = args.username.strip()
    role = args.role.upper().strip()
    if role not in (ROLE_ADMIN, ROLE_VIEWER):
        raise SystemExit("role must be ADMIN or VIEWER")

    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET role = %s WHERE user_name = %s",
            (role, username),
        )
        conn.commit()
        if cur.rowcount != 1:
            raise SystemExit("user not found (or multiple rows updated)")
        print(f"updated role: {username} -> {role}")
        return 0
    except mysql.connector.Error as e:
        conn.rollback()
        raise SystemExit(f"DB error: {e}")
    finally:
        conn.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="list users")
    sp.set_defaults(fn=cmd_list)

    sp = sub.add_parser("create", help="create user (hashed password)")
    sp.add_argument("--username", required=True)
    sp.add_argument("--company", required=True)
    sp.add_argument("--role", default=ROLE_VIEWER)
    sp.add_argument("--password", help="if omitted, prompt securely")
    sp.add_argument("--no-force-change", action="store_true", help="do not force password change on first login")
    sp.set_defaults(fn=cmd_create)

    sp = sub.add_parser("set-password", help="set user password (hashed)")
    sp.add_argument("--username", required=True)
    sp.add_argument("--password", help="if omitted, prompt securely")
    sp.set_defaults(fn=cmd_set_password)

    sp = sub.add_parser("set-role", help="set role (ADMIN/VIEWER)")
    sp.add_argument("--username", required=True)
    sp.add_argument("--role", required=True)
    sp.set_defaults(fn=cmd_set_role)

    sp = sub.add_parser("migrate", help="add optional password policy columns to users table")
    sp.set_defaults(fn=cmd_migrate)

    sp = sub.add_parser("seed-admin", help="create initial admin user and force password change")
    sp.add_argument("--username", default="admin")
    sp.add_argument("--company", default="INTERNAL")
    sp.add_argument("--password", help="if omitted, generate random and print once")
    sp.add_argument("--reset-existing", action="store_true", help="reset password if user already exists (destructive)")
    sp.set_defaults(fn=cmd_seed_admin)

    sp = sub.add_parser("seed-defaults", help="seed default admin/user accounts (fixed passwords, force change)")
    sp.add_argument("--admin-user", default="admin")
    sp.add_argument("--admin-pass", default="admin1234")
    sp.add_argument("--viewer-user", default="user")
    sp.add_argument("--viewer-pass", default="user1234")
    sp.add_argument("--company", default="INTERNAL")
    sp.add_argument("--reset-existing", action="store_true", help="reset passwords if users already exist (destructive)")
    sp.set_defaults(fn=cmd_seed_defaults)

    return p


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.fn(args))


def _has_column(conn, col: str) -> bool:
    cur = conn.cursor()
    cur.execute("SHOW COLUMNS FROM users LIKE %s", (col,))
    return cur.fetchone() is not None


def _ensure_policy_columns() -> None:
    # Best-effort: add columns if missing.
    try:
        conn = connect()
    except Exception:
        return
    try:
        need_force = not _has_column(conn, "must_change_password")
        need_changed = not _has_column(conn, "password_changed_at")
        need_prev = not _has_column(conn, "prev_user_passwd")
        if not (need_force or need_changed or need_prev):
            return
        cur = conn.cursor()
        if need_force:
            cur.execute("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 1")
        if need_changed:
            cur.execute("ALTER TABLE users ADD COLUMN password_changed_at DATETIME NULL")
        if need_prev:
            cur.execute("ALTER TABLE users ADD COLUMN prev_user_passwd VARCHAR(255) NULL")
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        conn.close()


def cmd_migrate(_args) -> int:
    _ensure_policy_columns()
    print("migration done (best-effort).")
    return 0


def cmd_seed_admin(args) -> int:
    _ensure_policy_columns()
    username = args.username.strip()
    company = args.company.strip()
    password = args.password or base64.urlsafe_b64encode(os.urandom(18)).decode("ascii").rstrip("=")
    pw_hash = hash_password(password)

    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM users WHERE user_name=%s LIMIT 1", (username,))
        existing = cur.fetchone()
        if existing and not args.reset_existing:
            print(f"user already exists: {username} (no changes; pass --reset-existing to overwrite password)")
            return 0

        cols_force = _has_column(conn, "must_change_password")
        cols_changed = _has_column(conn, "password_changed_at")
        if existing:
            # Reset password and force change.
            if cols_force and cols_changed:
                cur.execute(
                    """
                    UPDATE users
                    SET user_passwd=%s, role=%s, company=%s, must_change_password=1, password_changed_at=NULL
                    WHERE user_name=%s
                    """,
                    (pw_hash, ROLE_ADMIN, company, username),
                )
            elif cols_force:
                cur.execute(
                    "UPDATE users SET user_passwd=%s, role=%s, company=%s, must_change_password=1 WHERE user_name=%s",
                    (pw_hash, ROLE_ADMIN, company, username),
                )
            else:
                cur.execute(
                    "UPDATE users SET user_passwd=%s, role=%s, company=%s WHERE user_name=%s",
                    (pw_hash, ROLE_ADMIN, company, username),
                )
        else:
            if cols_force and cols_changed:
                cur.execute(
                    """
                    INSERT INTO users (user_name, user_passwd, role, company, must_change_password, password_changed_at, last_login, created_at)
                    VALUES (%s,%s,%s,%s,1,NULL,NOW(),NOW())
                    """,
                    (username, pw_hash, ROLE_ADMIN, company),
                )
            elif cols_force:
                cur.execute(
                    """
                    INSERT INTO users (user_name, user_passwd, role, company, must_change_password, last_login, created_at)
                    VALUES (%s,%s,%s,%s,1,NOW(),NOW())
                    """,
                    (username, pw_hash, ROLE_ADMIN, company),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO users (user_name, user_passwd, role, company, last_login, created_at)
                    VALUES (%s,%s,%s,%s,NOW(),NOW())
                    """,
                    (username, pw_hash, ROLE_ADMIN, company),
                )

        conn.commit()
        if existing:
            print(f"updated admin user: {username} (forced password change)")
        else:
            print(f"seeded admin user: {username} (forced password change)")
        if args.password:
            print("initial password: (provided via --password)")
        else:
            print(f"initial password (print-once): {password}")
        return 0
    except mysql.connector.Error as e:
        conn.rollback()
        raise SystemExit(f"DB error: {e}")
    finally:
        conn.close()


def _upsert_user(conn, username: str, password: str, role: str, company: str, reset_existing: bool) -> None:
    username = username.strip()
    pw_hash = hash_password(password)
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM users WHERE user_name=%s LIMIT 1", (username,))
    existing = cur.fetchone()

    cols_force = _has_column(conn, "must_change_password")
    cols_changed = _has_column(conn, "password_changed_at")

    if existing and not reset_existing:
        print(f"user already exists: {username} (no changes; pass --reset-existing to overwrite password)")
        return

    if existing:
        if cols_force and cols_changed:
            cur.execute(
                """
                UPDATE users
                SET user_passwd=%s, role=%s, company=%s, must_change_password=1, password_changed_at=NULL
                WHERE user_name=%s
                """,
                (pw_hash, role, company, username),
            )
        elif cols_force:
            cur.execute(
                "UPDATE users SET user_passwd=%s, role=%s, company=%s, must_change_password=1 WHERE user_name=%s",
                (pw_hash, role, company, username),
            )
        else:
            cur.execute(
                "UPDATE users SET user_passwd=%s, role=%s, company=%s WHERE user_name=%s",
                (pw_hash, role, company, username),
            )
        print(f"updated user: {username} ({role}) (forced password change)")
        return

    if cols_force and cols_changed:
        cur.execute(
            """
            INSERT INTO users (user_name, user_passwd, role, company, must_change_password, password_changed_at, last_login, created_at)
            VALUES (%s,%s,%s,%s,1,NULL,NOW(),NOW())
            """,
            (username, pw_hash, role, company),
        )
    elif cols_force:
        cur.execute(
            """
            INSERT INTO users (user_name, user_passwd, role, company, must_change_password, last_login, created_at)
            VALUES (%s,%s,%s,%s,1,NOW(),NOW())
            """,
            (username, pw_hash, role, company),
        )
    else:
        cur.execute(
            """
            INSERT INTO users (user_name, user_passwd, role, company, last_login, created_at)
            VALUES (%s,%s,%s,%s,NOW(),NOW())
            """,
            (username, pw_hash, role, company),
        )
    print(f"seeded user: {username} ({role}) (forced password change)")


def cmd_seed_defaults(args) -> int:
    _ensure_policy_columns()
    conn = connect()
    try:
        _upsert_user(
            conn,
            username=args.admin_user,
            password=args.admin_pass,
            role=ROLE_ADMIN,
            company=args.company,
            reset_existing=bool(args.reset_existing),
        )
        _upsert_user(
            conn,
            username=args.viewer_user,
            password=args.viewer_pass,
            role=ROLE_VIEWER,
            company=args.company,
            reset_existing=bool(args.reset_existing),
        )
        conn.commit()
        return 0
    except mysql.connector.Error as e:
        conn.rollback()
        raise SystemExit(f"DB error: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
