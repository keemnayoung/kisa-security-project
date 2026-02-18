"""
connection.py
Compatibility helper for simple SQL queries.

Some utility scripts expect `from db.connection import run_query`.
This wraps DBConnector for basic SELECT/SHOW/DESCRIBE-style queries.
"""

from __future__ import annotations

from typing import Any

from .connector import DBConnector


def run_query(sql: str, params: tuple[Any, ...] | None = None):
    sql = (sql or "").strip()
    params = params or ()
    if not sql:
        return []

    db = DBConnector()
    if not db.connect():
        raise RuntimeError("DB 연결 실패")
    try:
        head = sql.split(None, 1)[0].lower() if sql.split(None, 1) else ""
        if head in ("select", "show", "describe", "desc", "explain"):
            return db._fetch(sql, params) or []
        # For non-SELECT statements, return lastrowid (or None on failure).
        return db._execute(sql, params)
    finally:
        db.disconnect()

