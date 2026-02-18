#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OS_DIR = PROJECT_ROOT / "scripts" / "os"
OUT_PATH = PROJECT_ROOT / "backend" / "db" / "seeds" / "kisa_items_os_seed.sql"

CATEGORY_MAP = {
    "account": "account",
    "directory": "directory",
    "service": "service",
    "patch": "patch",
    "log": "log",
}


def _sql_str(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"


def _extract(patterns: list[str], text: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip()
    return None


def _detect_auto_fix(fix_path: Path) -> int:
    if not fix_path.exists():
        return 0
    try:
        lines = fix_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return 0

    meaningful = 0
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            continue
        if s.startswith("#!/"):
            continue
        meaningful += 1
        if meaningful >= 3:
            return 1
    return 0


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


def main() -> int:
    scripts = sorted(OS_DIR.rglob("check_U*.sh"))
    rows: list[tuple] = []

    for p in scripts:
        rel = p.relative_to(OS_DIR)
        top = rel.parts[0] if rel.parts else ""
        category = CATEGORY_MAP.get(top, "os")

        text = p.read_text(encoding="utf-8", errors="ignore")

        item_code = (
            _extract([r'^\s*ID\s*=\s*"(U-[0-9]{2})"'], text)
            or _extract([r'@Check_ID\s*:\s*(U-[0-9]{2})'], text)
        )
        if not item_code:
            m = re.search(r"check_(U)(\d{2})\.sh$", p.name)
            if not m:
                continue
            item_code = f"{m.group(1)}-{m.group(2)}"

        title = _extract(
            [r'@Title\s*:\s*(.+)$', r'^\s*TITLE\s*=\s*"(.+?)"'],
            text,
        ) or f"{item_code}"

        severity = _extract(
            [r'@Importance\s*:?\s*(상|중|하)\b', r'@IMPORTANCE\s*:?\s*(상|중|하)\b'],
            text,
        ) or "중"

        description = _extract(
            [r'@Description\s*:\s*(.+)$', r'^\s*DESCRIPTION\s*=\s*"(.+?)"'],
            text,
        ) or "점검 항목"

        fix_name = p.name.replace("check_", "fix_")
        fix_path = p.parent / fix_name
        auto_fix = _detect_auto_fix(fix_path)

        if auto_fix == 1:
            auto_fix_desc = "자동 조치 스크립트(fix_*.sh) 수행 시 서비스 영향이 있을 수 있으니 적용 전 검증이 필요합니다."
            guide = "fix_*.sh 스크립트의 조치 내용을 검토한 뒤 변경관리 절차에 따라 적용하십시오."
        else:
            auto_fix_desc = "운영 영향 및 의존성 판단이 필요하여 자동 조치를 제공하지 않습니다."
            guide = "점검 결과에 따라 기관 정책 및 KISA 가이드에 맞게 수동 조치하십시오."

        rows.append(
            (
                item_code,
                category,
                _truncate(title, 200),
                severity,
                _truncate(description, 500),
                auto_fix,
                _truncate(auto_fix_desc, 500),
                _truncate(guide, 1000),
            )
        )

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    out: list[str] = []
    out.append("-- Seed data for kisa_items (OS items, generated from scripts/os).")
    out.append("-- Idempotent via ON DUPLICATE KEY UPDATE.")
    out.append("USE kisa_security;\n")
    out.append(
        "INSERT INTO kisa_items (item_code, category, title, severity, description, auto_fix, auto_fix_description, guide) VALUES"
    )

    for i, r in enumerate(rows):
        line = "(" + ",".join(
            [
                _sql_str(str(r[0])),
                _sql_str(str(r[1])),
                _sql_str(str(r[2])),
                _sql_str(str(r[3])),
                _sql_str(str(r[4])),
                str(int(r[5])),
                _sql_str(str(r[6])),
                _sql_str(str(r[7])),
            ]
        ) + ")"
        if i < len(rows) - 1:
            line += ","
        else:
            line += "\nAS new"
        out.append(line)

    out.append("ON DUPLICATE KEY UPDATE")
    out.append("  category=new.category,")
    out.append("  title=new.title,")
    out.append("  severity=new.severity,")
    out.append("  description=new.description,")
    out.append("  auto_fix=new.auto_fix,")
    out.append("  auto_fix_description=new.auto_fix_description,")
    out.append("  guide=new.guide;\n")

    OUT_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
