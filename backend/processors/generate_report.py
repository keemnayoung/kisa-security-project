"""
generate_report.py  (v3.1 - 가독성 개선)
취약점 진단 결과 엑셀(.xlsx) 보고서 생성

시트 구성:
  1. 표지           - 프로젝트명, 진단 기간, 수행자, 버전
  2. 대시보드       - Executive Summary (차트 + 하위 Top 5 서버)
  3. 항목별 요약    - 항목별 통계 + 취약 서버 리스트 (UNIX/DB 구분)
  4. 자산 목록      - 진단 대상 서버/DB 목록 (서버 시트 하이퍼링크)
  5~N. [서버별 시트] - 서버 1대마다 개별 상세 결과 (샘플4 형식)

사용법:
  python generate_report.py                     # DB에서 최신 데이터 조회
  python generate_report.py --company AUTOEVER  # 특정 회사만
"""

import os
import sys
import re
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

import pandas as pd
import xlsxwriter

# backend/ 경로 추가 (resolve()로 ../ 정규화하여 config.py의 PROJECT_ROOT가 올바르게 계산되도록 함)
_backend_dir = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, _backend_dir)
from db.connector import DBConnector
from config import DB_CONFIG

# ──────────────────────────────────────────────
# 색상 팔레트
# ──────────────────────────────────────────────
COLOR = {
    'navy':        '#1B2A4A',
    'navy_light':  '#2C3E6B',
    'white':       '#FFFFFF',
    'light_gray':  '#F5F6FA',
    'border':      '#D1D5DB',
    'text_dark':   '#1F2937',
    'text_gray':   '#6B7280',
    'pass_bg':     '#ECFDF5',
    'pass_text':   '#059669',
    'fail_bg':     '#FEF2F2',
    'fail_text':   '#DC2626',
    'na_bg':       '#F3F4F6',
    'na_text':     '#9CA3AF',
    'high_bg':     '#FEE2E2',
    'high_text':   '#991B1B',
    'mid_bg':      '#FEF3C7',
    'mid_text':    '#92400E',
    'low_bg':      '#DBEAFE',
    'low_text':    '#1E40AF',
    'os_stripe':   '#E8F0FE',
    'db_stripe':   '#FFF3E0',
    'os_section':  '#1565C0',
    'db_section':  '#BF360C',
    'chart_pass':  '#10B981',
    'chart_fail':  '#EF4444',
    'chart_na':    '#9CA3AF',
    'chart_high':  '#DC2626',
    'chart_mid':   '#F59E0B',
    'chart_low':   '#3B82F6',
    'warn_bg':     '#FFFBEB',
    'warn_text':   '#B45309',
    'zebra':       '#F9FAFB',
}

# 카테고리 한글 매핑
CATEGORY_KR = {
    'account':   '계정 관리',
    'directory': '파일 및 디렉터리 관리',
    'service':   '서비스 관리',
    'patch':     '패치 관리',
    'log':       '로그 관리',
    'access':    '접근 제어',
    'option':    '옵션 관리',
}

SEVERITY_KR = {'상': 'H', '중': 'M', '하': 'L'}

# severity별 가중치 (score_calculator.py와 동일)
SEVERITY_WEIGHT = {'상': 3, '중': 2, '하': 1}

# 항목별 배점 (샘플4 형식 점수 표시용)
ITEM_SCORE = {'상': 10, '중': 8, '하': 6}

# 카테고리 표시 순서
CATEGORY_ORDER = ['계정 관리', '파일 및 디렉터리 관리', '서비스 관리', '접근 제어', '옵션 관리', '패치 관리', '로그 관리']


# ──────────────────────────────────────────────
# 엑셀 시트명 안전 처리
# ──────────────────────────────────────────────
_SHEET_NAME_BAD_CHARS = re.compile(r'[:\\/?*\[\]]')


def safe_sheet_name(name, max_len=31):
    """
    엑셀 시트 이름 규칙에 맞게 정제
    - 특수문자 : \\ / ? * [ ] 제거
    - 31자 제한
    - 빈 문자열 방지
    """
    sanitized = _SHEET_NAME_BAD_CHARS.sub('', name).strip()
    if not sanitized:
        sanitized = 'Sheet'
    return sanitized[:max_len]


def build_sheet_name_map(servers):
    """
    서버 목록에서 중복 없는 시트명 매핑 생성
    hostname이 같은 서버가 있으면 server_id 접미사를 붙임

    Returns:
        dict: {server_id: sheet_name}
    """
    # hostname 중복 카운트
    hostname_count = defaultdict(list)
    for srv in servers:
        hostname_count[srv['hostname']].append(srv['server_id'])

    sheet_map = {}
    used_names = set()
    for srv in servers:
        sid = srv['server_id']
        hostname = srv['hostname']

        if len(hostname_count[hostname]) > 1:
            # 중복 hostname → server_id 접미사 추가
            base = safe_sheet_name(f"{hostname}({sid})")
        else:
            base = safe_sheet_name(hostname)

        # 최종 중복 방지
        name = base
        counter = 2
        while name in used_names:
            suffix = f"_{counter}"
            name = base[:31 - len(suffix)] + suffix
            counter += 1

        used_names.add(name)
        sheet_map[sid] = name

    return sheet_map


def fetch_report_data(company=None):
    """DB에서 보고서용 데이터 조회"""
    db = DBConnector()
    if not db.connect():
        raise RuntimeError("DB 연결 실패")

    # 서버 목록
    if company:
        servers = db._fetch(
            "SELECT * FROM servers WHERE is_active=1 AND company=%s ORDER BY server_id",
            (company,),
        )
    else:
        servers = db._fetch(
            "SELECT * FROM servers WHERE is_active=1 ORDER BY server_id", ()
        )

    if not servers:
        db.disconnect()
        raise RuntimeError("활성 서버가 없습니다.")

    # kisa_items 전체
    kisa_items = db._fetch(
        "SELECT item_code, category, title, severity, description, guide FROM kisa_items ORDER BY item_code",
        (),
    )
    kisa_map = {r['item_code']: r for r in kisa_items}

    # 서버별 예외 항목 조회
    server_exceptions = {}
    for srv in servers:
        sid = srv['server_id']
        server_exceptions[sid] = set(db.get_exceptions(sid) or [])

    # 서버별 최신 점검 결과
    results = []
    for srv in servers:
        sid = srv['server_id']
        rows = db.get_latest_scan(sid)
        if rows:
            for r in rows:
                raw_status = r['status']
                is_exception = r['item_code'] in server_exceptions.get(sid, set())
                effective_status = '양호(예외)' if is_exception else raw_status

                results.append({
                    'server_id': sid,
                    'hostname':  srv['hostname'],
                    'ip_address': srv['ip_address'],
                    'os_type':   srv.get('os_type', ''),
                    'db_type':   srv.get('db_type', ''),
                    'manager':   srv.get('manager', ''),
                    'department': srv.get('department', ''),
                    'item_code': r['item_code'],
                    'title':     r.get('title', kisa_map.get(r['item_code'], {}).get('title', '')),
                    'category':  r.get('category', kisa_map.get(r['item_code'], {}).get('category', '')),
                    'severity':  r.get('severity', kisa_map.get(r['item_code'], {}).get('severity', '')),
                    'status':    effective_status,
                    'scan_date': str(r.get('scan_date', '')),
                    'raw_evidence': r.get('raw_evidence', ''),
                    'guide':     kisa_map.get(r['item_code'], {}).get('guide', ''),
                    'description': kisa_map.get(r['item_code'], {}).get('description', ''),
                })

    db.disconnect()
    return servers, kisa_items, kisa_map, results


def item_type(item_code):
    """항목 코드로 UNIX/DB 구분"""
    if item_code.startswith('U-'):
        return 'UNIX'
    return 'DB'


def parse_evidence(raw_evidence):
    """
    raw_evidence JSON 파싱하여 (detail, command) 튜플 반환

    - detail: 사용자가 읽을 수 있는 한글 설명 (셀에 표시)
    - command: 점검에 사용된 명령어 (메모로 첨부)

    NOTE: raw_evidence는 쉘 명령어 등으로 인해 이스케이프되지 않은
    따옴표/제어문자를 포함할 수 있어 표준 json.loads()가 실패하는 경우가 많음.
    단계별 fallback으로 최대한 detail을 추출한다.
    """
    if not raw_evidence:
        return '', ''

    text = str(raw_evidence).strip()

    # 1차: 표준 JSON 파싱
    try:
        data = json.loads(text)
        return (data.get('detail') or '').strip(), (data.get('command') or '').strip()
    except Exception:
        pass

    # 2차: strict=False (제어문자 허용)
    try:
        data = json.loads(text, strict=False)
        return (data.get('detail') or '').strip(), (data.get('command') or '').strip()
    except Exception:
        pass

    # 3차: 이중 이스케이프 (리터럴 \n → 실제 줄바꿈, \" → ") 복원 후 재시도
    try:
        unescaped = text.replace(r'\n', '\n').replace(r'\t', '\t').replace(r'\"', '"')
        data = json.loads(unescaped, strict=False)
        return (data.get('detail') or '').strip(), (data.get('command') or '').strip()
    except Exception:
        pass

    # 4차: 정규식으로 "detail": "..." 추출
    detail = ''
    command = ''

    # 패턴 A: 일반 JSON 형태  "detail": "..."
    m = re.search(r'"detail"\s*:\s*"(.*?)(?:"\s*[,}])', text, re.DOTALL)
    if m:
        detail = m.group(1).replace(r'\n', '\n').replace(r'\"', '"').strip()

    # 패턴 B: 이중 이스케이프 형태  \\"detail\\": \\"...\\"
    if not detail:
        m = re.search(r'\\"detail\\"\s*:\s*\\"(.*?)(?:\\"\s*[,}])', text, re.DOTALL)
        if m:
            detail = m.group(1).replace(r'\n', '\n').replace(r'\"', '"').strip()

    # command 추출 (동일하게 두 패턴)
    m = re.search(r'"command"\s*:\s*"(.*?)(?:"\s*,)', text, re.DOTALL)
    if m:
        command = m.group(1).replace(r'\n', '\n').replace(r'\"', '"').strip()
    if not command:
        m = re.search(r'\\"command\\"\s*:\s*\\"(.*?)(?:\\"\s*,)', text, re.DOTALL)
        if m:
            command = m.group(1).replace(r'\n', '\n').replace(r'\"', '"').strip()

    if detail:
        return detail, command

    # 최종 fallback: 원문 첫 500자
    return text[:500], ''


def generate_report(servers, kisa_items, kisa_map, results, output_path, company_name=''):
    """엑셀 보고서 생성 (v3.1 - 가독성 개선)"""
    wb = xlsxwriter.Workbook(output_path, {'strings_to_urls': False})

    # ── 시트명 매핑 ──
    SHEET_COVER = '표지'
    SHEET_DASH  = '대시보드'
    SHEET_MATRIX = '항목별 요약'
    SHEET_ASSET = '자산 목록'

    # 서버별 시트명 매핑 (hostname 기반, 중복/특수문자 안전 처리)
    server_sheet_map = build_sheet_name_map(servers)

    # ── 양호 판정 기준 ──
    def is_pass(status):
        return '양호' in status

    # ── 공통 포맷 정의 (컴팩트) ──
    fmt = {}
    fmt['title_big'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 24, 'bold': True,
        'font_color': COLOR['navy'], 'align': 'center', 'valign': 'vcenter',
    })
    fmt['title_sub'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 12,
        'font_color': COLOR['text_gray'], 'align': 'center', 'valign': 'vcenter',
    })
    fmt['title_info'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 11,
        'font_color': COLOR['text_dark'], 'align': 'center', 'valign': 'vcenter',
    })
    fmt['cover_line'] = wb.add_format({
        'bottom': 2, 'bottom_color': COLOR['navy'],
    })
    # ── 헤더 (9pt) ──
    fmt['header'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9, 'bold': True,
        'font_color': COLOR['white'], 'bg_color': COLOR['navy'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter', 'text_wrap': True,
    })
    fmt['header_left'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9, 'bold': True,
        'font_color': COLOR['white'], 'bg_color': COLOR['navy'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'left', 'valign': 'vcenter', 'text_wrap': True,
    })
    # ── 셀 (8pt) ──
    fmt['cell'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter', 'text_wrap': True,
    })
    fmt['cell_left'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'left', 'valign': 'vcenter', 'text_wrap': True,
    })
    fmt['cell_wrap'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'left', 'valign': 'top', 'text_wrap': True,
    })
    # ── 상태 셀 (8pt) ──
    fmt['pass'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['pass_text'], 'bg_color': COLOR['pass_bg'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['fail'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['fail_text'], 'bg_color': COLOR['fail_bg'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['na'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['na_text'], 'bg_color': COLOR['na_bg'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    # ── 중요도 셀 (8pt) ──
    fmt['sev_h'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['high_text'], 'bg_color': COLOR['high_bg'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['sev_m'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['mid_text'], 'bg_color': COLOR['mid_bg'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['sev_l'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['low_text'], 'bg_color': COLOR['low_bg'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    # ── UNIX/DB 행 (8pt) ──
    fmt['os_row'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'], 'bg_color': COLOR['os_stripe'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter', 'text_wrap': True,
    })
    fmt['os_row_left'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'], 'bg_color': COLOR['os_stripe'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'left', 'valign': 'vcenter', 'text_wrap': True,
    })
    fmt['db_row'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'], 'bg_color': COLOR['db_stripe'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter', 'text_wrap': True,
    })
    fmt['db_row_left'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'], 'bg_color': COLOR['db_stripe'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'left', 'valign': 'vcenter', 'text_wrap': True,
    })
    # ── 대시보드 포맷 ──
    fmt['dash_section'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 11, 'bold': True,
        'font_color': COLOR['navy'], 'bottom': 2, 'bottom_color': COLOR['navy'],
    })
    fmt['dash_label'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9, 'bold': True,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'bg_color': COLOR['light_gray'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['dash_value'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['dash_score'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 18, 'bold': True,
        'font_color': COLOR['navy'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['pct'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
        'num_format': '0.0%',
    })
    fmt['pct8'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
        'num_format': '0.0%',
    })
    fmt['link'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': '#2563EB', 'underline': True,
    })
    fmt['link_cell'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': '#2563EB', 'underline': True,
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['warn_cell'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['warn_text'], 'bg_color': COLOR['warn_bg'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    # ── 서버 시트 정보 (9pt) ──
    fmt['srv_info_label'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9, 'bold': True,
        'font_color': COLOR['text_dark'], 'bg_color': COLOR['light_gray'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['srv_info_value'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'left', 'valign': 'vcenter',
    })
    fmt['vuln_list'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['fail_text'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'left', 'valign': 'vcenter', 'text_wrap': True,
    })
    # ── 섹션 구분 행 (UNIX/DB) ──
    fmt['section_unix'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9, 'bold': True,
        'font_color': COLOR['white'], 'bg_color': COLOR['os_section'],
        'border': 1, 'border_color': COLOR['os_section'],
        'align': 'left', 'valign': 'vcenter',
    })
    fmt['section_db'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 9, 'bold': True,
        'font_color': COLOR['white'], 'bg_color': COLOR['db_section'],
        'border': 1, 'border_color': COLOR['db_section'],
        'align': 'left', 'valign': 'vcenter',
    })
    # ── 서버 시트 통계 영역 ──
    fmt['stat_header'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['navy'], 'bg_color': COLOR['light_gray'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter', 'text_wrap': True,
    })
    fmt['stat_value'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
        'num_format': '0.0%',
    })
    fmt['stat_count'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8,
        'font_color': COLOR['text_dark'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    # ── 점수 셀 ──
    fmt['score_pass'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['pass_text'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })
    fmt['score_fail'] = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 8, 'bold': True,
        'font_color': COLOR['fail_text'],
        'border': 1, 'border_color': COLOR['border'],
        'align': 'center', 'valign': 'vcenter',
    })

    # ── 통계 계산 ──
    now = datetime.now()
    scan_dates = [r['scan_date'] for r in results if r.get('scan_date')]
    earliest = min(scan_dates) if scan_dates else str(now)
    latest = max(scan_dates) if scan_dates else str(now)

    total = len(results)
    pass_cnt = sum(1 for r in results if is_pass(r['status']))
    fail_cnt = sum(1 for r in results if r['status'] == '취약')
    except_cnt = sum(1 for r in results if r['status'] == '양호(예외)')
    na_cnt = total - pass_cnt - fail_cnt

    # 가중치 기반 보안 점수
    total_weight = sum(SEVERITY_WEIGHT.get(r['severity'], 1) for r in results)
    pass_weight = sum(SEVERITY_WEIGHT.get(r['severity'], 1) for r in results if is_pass(r['status']))
    score = round(pass_weight / total_weight * 100, 1) if total_weight > 0 else 0

    # 서버별 통계
    per_server = defaultdict(lambda: {'pass': 0, 'fail': 0, 'na': 0, 'total': 0,
                                       'pass_weight': 0, 'total_weight': 0})
    for r in results:
        sid = r['server_id']
        w = SEVERITY_WEIGHT.get(r['severity'], 1)
        per_server[sid]['total'] += 1
        per_server[sid]['total_weight'] += w
        if is_pass(r['status']):
            per_server[sid]['pass'] += 1
            per_server[sid]['pass_weight'] += w
        elif r['status'] == '취약':
            per_server[sid]['fail'] += 1
        else:
            per_server[sid]['na'] += 1

    # 서버별 점수 + hostname 매핑
    server_scores = []
    for srv in servers:
        sid = srv['server_id']
        st = per_server[sid]
        s_score = round(st['pass_weight'] / st['total_weight'] * 100, 1) if st['total_weight'] > 0 else 0
        server_scores.append({
            'server_id': sid,
            'hostname': srv['hostname'],
            'ip_address': srv['ip_address'],
            'os_type': srv.get('os_type', ''),
            'db_type': srv.get('db_type', ''),
            'score': s_score,
            'fail': st['fail'],
            'pass': st['pass'],
            'total': st['total'],
        })

    # 카테고리별 통계 (OS/DB 구분)
    per_cat = defaultdict(lambda: {'pass': 0, 'fail': 0, 'na': 0,
                                    'pass_weight': 0, 'total_weight': 0})
    for r in results:
        cat = CATEGORY_KR.get(r['category'], r['category'])
        itype = 'OS' if r['item_code'].startswith('U-') else 'DB'
        typed_cat = f"{cat}({itype})"
        w = SEVERITY_WEIGHT.get(r['severity'], 1)
        per_cat[typed_cat]['total_weight'] += w
        if is_pass(r['status']):
            per_cat[typed_cat]['pass'] += 1
            per_cat[typed_cat]['pass_weight'] += w
        elif r['status'] == '취약':
            per_cat[typed_cat]['fail'] += 1
        else:
            per_cat[typed_cat]['na'] += 1

    # 중요도별 통계
    per_sev = defaultdict(lambda: {'pass': 0, 'fail': 0, 'na': 0})
    for r in results:
        sev = r['severity']
        if is_pass(r['status']):
            per_sev[sev]['pass'] += 1
        elif r['status'] == '취약':
            per_sev[sev]['fail'] += 1
        else:
            per_sev[sev]['na'] += 1

    # 항목별 통계 (매트릭스 + 취약 서버 리스트) → server_id 사용
    item_stats = defaultdict(lambda: {'total': 0, 'vuln': 0, 'pass': 0, 'na': 0, 'vuln_servers': []})
    for r in results:
        ic = r['item_code']
        item_stats[ic]['total'] += 1
        if is_pass(r['status']):
            item_stats[ic]['pass'] += 1
        elif r['status'] == '취약':
            item_stats[ic]['vuln'] += 1
            item_stats[ic]['vuln_servers'].append(r['server_id'])
        else:
            item_stats[ic]['na'] += 1

    # 서버별 결과 그룹핑
    results_by_server = defaultdict(list)
    for r in results:
        results_by_server[r['server_id']].append(r)

    # 서버별 카테고리/중요도 통계 (샘플4 형식용)
    srv_cat_stats = defaultdict(lambda: defaultdict(lambda: {'pass': 0, 'fail': 0, 'na': 0, 'total': 0}))
    srv_sev_stats = defaultdict(lambda: defaultdict(lambda: {'pass': 0, 'fail': 0, 'na': 0}))
    for r in results:
        sid = r['server_id']
        cat = CATEGORY_KR.get(r['category'], r['category'])
        sev = r['severity']
        srv_cat_stats[sid][cat]['total'] += 1
        if is_pass(r['status']):
            srv_cat_stats[sid][cat]['pass'] += 1
            srv_sev_stats[sid][sev]['pass'] += 1
        elif r['status'] == '취약':
            srv_cat_stats[sid][cat]['fail'] += 1
            srv_sev_stats[sid][sev]['fail'] += 1
        else:
            srv_cat_stats[sid][cat]['na'] += 1
            srv_sev_stats[sid][sev]['na'] += 1

    # ════════════════════════════════════════════
    # Sheet 1: 표지
    # ════════════════════════════════════════════
    ws_cover = wb.add_worksheet(SHEET_COVER)
    ws_cover.hide_gridlines(2)
    ws_cover.set_landscape()
    ws_cover.set_column('A:H', 15)
    ws_cover.write_url('A1', f"internal:'{SHEET_DASH}'!A1", fmt['link'], '>> 대시보드')

    ws_cover.merge_range('B8:G8', '', fmt['cover_line'])
    ws_cover.merge_range('B10:G10', '서버 취약점 진단 상세 결과 보고서', fmt['title_big'])
    ws_cover.merge_range('B12:G12', 'UNIX / DB 통합 보안 진단', fmt['title_sub'])
    ws_cover.merge_range('B14:G14', '', fmt['cover_line'])

    info_fmt = fmt['title_info']
    ws_cover.merge_range('B18:G18', f'고객사: {company_name or servers[0].get("company", "")}', info_fmt)
    ws_cover.merge_range('B20:G20', f'진단 기간: {earliest[:10]} ~ {latest[:10]}', info_fmt)
    ws_cover.merge_range('B22:G22', f'대상 서버: {len(servers)}대', info_fmt)
    ws_cover.merge_range('B24:G24', f'점검 항목: UNIX {sum(1 for k in kisa_map if k.startswith("U-"))}개 / DB {sum(1 for k in kisa_map if not k.startswith("U-"))}개', info_fmt)
    ws_cover.merge_range('B26:G26', f'보고서 생성일: {now.strftime("%Y-%m-%d %H:%M")}', info_fmt)
    ws_cover.merge_range('B28:G28', 'Version 3.1.0', info_fmt)
    ws_cover.merge_range('B30:G30', '2026 KISA 주요정보통신기반시설 기술적 취약점 분석 평가 기준', fmt['title_sub'])

    # 목차
    toc_row = 33
    toc_fmt_style = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 11, 'bold': True,
        'font_color': COLOR['navy'], 'align': 'center', 'valign': 'vcenter',
    })
    ws_cover.merge_range(toc_row, 1, toc_row, 6, '[ 목차 ]', toc_fmt_style)
    toc_row += 2
    toc_link_fmt = wb.add_format({
        'font_name': '맑은 고딕', 'font_size': 10,
        'font_color': '#2563EB', 'underline': True,
        'align': 'center', 'valign': 'vcenter',
    })
    fixed_sheets = [
        ('대시보드', SHEET_DASH),
        ('항목별 요약', SHEET_MATRIX),
        ('자산 목록', SHEET_ASSET),
    ]
    for i, (label, sname) in enumerate(fixed_sheets, 1):
        ws_cover.merge_range(toc_row, 2, toc_row, 5, '')
        ws_cover.write_url(toc_row, 2, f"internal:'{sname}'!A1", toc_link_fmt, f'{i}. {label}')
        toc_row += 1

    # 서버 시트 목차
    toc_row += 1
    ws_cover.merge_range(toc_row, 1, toc_row, 6, '[ 서버별 상세 결과 ]', toc_fmt_style)
    toc_row += 1
    for srv in servers:
        sid = srv['server_id']
        sname = server_sheet_map[sid]
        st = per_server[sid]
        s_score = round(st['pass_weight'] / st['total_weight'] * 100, 1) if st['total_weight'] > 0 else 0
        label = f"{sid}  ({srv['ip_address']})  {s_score}점"
        ws_cover.merge_range(toc_row, 2, toc_row, 5, '')
        ws_cover.write_url(toc_row, 2, f"internal:'{sname}'!A1", toc_link_fmt, label)
        toc_row += 1

    # ════════════════════════════════════════════
    # Sheet 2: 대시보드
    # ════════════════════════════════════════════
    ws_dash = wb.add_worksheet(SHEET_DASH)
    ws_dash.hide_gridlines(2)
    ws_dash.set_landscape()
    ws_dash.set_column('A:A', 2)
    ws_dash.set_column('B:B', 18)
    ws_dash.set_column('C:H', 12)
    ws_dash.set_column('I:I', 2)
    ws_dash.set_column('J:O', 12)
    ws_dash.write_url('A1', f"internal:'{SHEET_COVER}'!A1", fmt['link'], '<< 표지')

    row = 1
    ws_dash.merge_range(row, 1, row, 7, 'Executive Summary - 취약점 진단 결과 요약', fmt['dash_section'])
    row += 2

    # 전체 점수
    ws_dash.merge_range(row, 1, row + 2, 2, '전체 보안 점수', fmt['dash_label'])
    ws_dash.merge_range(row, 3, row + 2, 4, f'{score}점', fmt['dash_score'])
    except_info = f' (예외 {except_cnt}건 포함)' if except_cnt > 0 else ''
    ws_dash.merge_range(row, 5, row, 7, f'총 {total}건 점검 (양호 {pass_cnt} / 취약 {fail_cnt} / N/A {na_cnt}){except_info}', fmt['dash_value'])
    row += 4

    # 도넛 차트 데이터
    chart_data_row = row
    ws_dash.write(row, 1, '구분', fmt['header'])
    ws_dash.write(row, 2, '건수', fmt['header'])
    row += 1
    ws_dash.write(row, 1, '양호', fmt['cell'])
    ws_dash.write(row, 2, pass_cnt, fmt['cell'])
    row += 1
    ws_dash.write(row, 1, '취약', fmt['cell'])
    ws_dash.write(row, 2, fail_cnt, fmt['cell'])
    row += 1
    if na_cnt > 0:
        ws_dash.write(row, 1, 'N/A', fmt['cell'])
        ws_dash.write(row, 2, na_cnt, fmt['cell'])
        row += 1

    chart_donut = wb.add_chart({'type': 'doughnut'})
    data_rows = 2 if na_cnt == 0 else 3
    chart_donut.add_series({
        'name':       '진단 결과',
        'categories': [SHEET_DASH, chart_data_row + 1, 1, chart_data_row + data_rows, 1],
        'values':     [SHEET_DASH, chart_data_row + 1, 2, chart_data_row + data_rows, 2],
        'points': [
            {'fill': {'color': COLOR['chart_pass']}},
            {'fill': {'color': COLOR['chart_fail']}},
        ] + ([{'fill': {'color': COLOR['chart_na']}}] if na_cnt > 0 else []),
        'data_labels': {'percentage': True, 'font': {'name': '맑은 고딕', 'size': 10}},
    })
    chart_donut.set_title({'name': '전체 진단 결과 비율', 'name_font': {'name': '맑은 고딕', 'size': 11, 'bold': True}})
    chart_donut.set_size({'width': 380, 'height': 280})
    chart_donut.set_legend({'position': 'bottom', 'font': {'name': '맑은 고딕', 'size': 9}})
    ws_dash.insert_chart(chart_data_row, 4, chart_donut)
    row += 1

    # 중요도별 통계 + 막대 차트
    sev_data_row = row + 7
    ws_dash.merge_range(sev_data_row - 1, 1, sev_data_row - 1, 5, '중요도별 진단 결과', fmt['dash_section'])
    ws_dash.write(sev_data_row, 1, '중요도', fmt['header'])
    ws_dash.write(sev_data_row, 2, '양호', fmt['header'])
    ws_dash.write(sev_data_row, 3, '취약', fmt['header'])
    ws_dash.write(sev_data_row, 4, 'N/A', fmt['header'])
    ws_dash.write(sev_data_row, 5, '양호율', fmt['header'])

    sev_r = sev_data_row + 1
    for sev_label in ['상', '중', '하']:
        s = per_sev[sev_label]
        t = s['pass'] + s['fail']
        rate = s['pass'] / t if t > 0 else 0
        ws_dash.write(sev_r, 1, sev_label, fmt['cell'])
        ws_dash.write(sev_r, 2, s['pass'], fmt['cell'])
        ws_dash.write(sev_r, 3, s['fail'], fmt['cell'])
        ws_dash.write(sev_r, 4, s['na'], fmt['cell'])
        ws_dash.write(sev_r, 5, rate, fmt['pct'])
        sev_r += 1

    chart_bar = wb.add_chart({'type': 'column'})
    chart_bar.add_series({
        'name': '양호',
        'categories': [SHEET_DASH, sev_data_row + 1, 1, sev_data_row + 3, 1],
        'values':     [SHEET_DASH, sev_data_row + 1, 2, sev_data_row + 3, 2],
        'fill': {'color': COLOR['chart_pass']},
    })
    chart_bar.add_series({
        'name': '취약',
        'categories': [SHEET_DASH, sev_data_row + 1, 1, sev_data_row + 3, 1],
        'values':     [SHEET_DASH, sev_data_row + 1, 3, sev_data_row + 3, 3],
        'fill': {'color': COLOR['chart_fail']},
    })
    chart_bar.set_title({'name': '중요도별 양호/취약 분포', 'name_font': {'name': '맑은 고딕', 'size': 11, 'bold': True}})
    chart_bar.set_size({'width': 380, 'height': 280})
    chart_bar.set_legend({'position': 'bottom', 'font': {'name': '맑은 고딕', 'size': 9}})
    chart_bar.set_y_axis({'name': '건수', 'name_font': {'name': '맑은 고딕'}})
    ws_dash.insert_chart(sev_data_row - 1, 7, chart_bar)

    # 카테고리별 통계 + 카테고리 막대 그래프 (OS/DB 구분)
    cat_start = sev_r + 2
    ws_dash.merge_range(cat_start, 1, cat_start, 6, '점검 결과 (OS/DB 구분)', fmt['dash_section'])
    cat_start += 1
    ws_dash.write(cat_start, 1, '점검 영역', fmt['header'])
    ws_dash.write(cat_start, 2, '구분', fmt['header'])
    ws_dash.write(cat_start, 3, '양호', fmt['header'])
    ws_dash.write(cat_start, 4, '취약', fmt['header'])
    ws_dash.write(cat_start, 5, 'N/A', fmt['header'])
    ws_dash.write(cat_start, 6, '양호율', fmt['header'])

    cat_data_start = cat_start  # 차트 데이터 시작 행 기억
    cr = cat_start + 1
    # OS/DB 구분된 카테고리 순서 생성 (OS 먼저, DB 나중)
    os_cats = []
    db_cats = []
    for base_cat in CATEGORY_ORDER:
        os_key = f"{base_cat}(OS)"
        db_key = f"{base_cat}(DB)"
        if os_key in per_cat:
            os_cats.append(os_key)
        if db_key in per_cat:
            db_cats.append(db_key)
    active_cats = os_cats + db_cats

    for cat_name in active_cats:
        c = per_cat[cat_name]
        rate = c['pass_weight'] / c['total_weight'] if c['total_weight'] > 0 else 0
        # "계정 관리(OS)" → base="계정 관리", tag="OS"
        base_name = cat_name.rsplit('(', 1)[0]
        tag = cat_name.rsplit('(', 1)[1].rstrip(')')
        row_fmt = fmt['os_row_left'] if tag == 'OS' else fmt['db_row_left']
        row_c = fmt['os_row'] if tag == 'OS' else fmt['db_row']
        ws_dash.write(cr, 1, f"{base_name} ({tag})", row_fmt)
        ws_dash.write(cr, 2, tag, row_c)
        ws_dash.write(cr, 3, c['pass'], row_c)
        ws_dash.write(cr, 4, c['fail'], row_c)
        ws_dash.write(cr, 5, c['na'], row_c)
        ws_dash.write(cr, 6, rate, fmt['pct'])
        cr += 1

    # ── 카테고리별 막대 그래프 (가로 bar, OS/DB 구분) ──
    n_cats = len(active_cats)
    chart_cat = wb.add_chart({'type': 'bar'})
    chart_cat.add_series({
        'name': '양호',
        'categories': [SHEET_DASH, cat_data_start + 1, 1, cat_data_start + n_cats, 1],
        'values':     [SHEET_DASH, cat_data_start + 1, 3, cat_data_start + n_cats, 3],
        'fill': {'color': COLOR['chart_pass']},
        'gap': 150,
        'overlap': 0,
    })
    chart_cat.add_series({
        'name': '취약',
        'categories': [SHEET_DASH, cat_data_start + 1, 1, cat_data_start + n_cats, 1],
        'values':     [SHEET_DASH, cat_data_start + 1, 4, cat_data_start + n_cats, 4],
        'fill': {'color': COLOR['chart_fail']},
    })
    chart_cat.set_title({'name': '취약점 카테고리별 분포 (OS/DB)', 'name_font': {'name': '맑은 고딕', 'size': 11, 'bold': True}})
    chart_cat.set_size({'width': 620, 'height': 60 + n_cats * 38})
    chart_cat.set_legend({'position': 'bottom', 'font': {'name': '맑은 고딕', 'size': 9}})
    chart_cat.set_x_axis({'name': '건수', 'name_font': {'name': '맑은 고딕', 'size': 9}})
    chart_cat.set_y_axis({'reverse': True, 'num_font': {'name': '맑은 고딕', 'size': 8}})
    ws_dash.insert_chart(cat_start - 1, 8, chart_cat)

    # 서버별 점수
    srv_start = cr + 2
    ws_dash.merge_range(srv_start, 1, srv_start, 7, '서버별 보안 점수', fmt['dash_section'])
    srv_start += 1
    srv_headers = ['서버 ID', 'Hostname', 'IP', 'OS/DB', '양호', '취약', '보안점수']
    for i, h in enumerate(srv_headers):
        ws_dash.write(srv_start, 1 + i, h, fmt['header'])

    sr = srv_start + 1
    for ss in server_scores:
        asset_type = ss['os_type']
        if ss['db_type'] and ss['db_type'] != '없음':
            asset_type += f" / {ss['db_type']}"
        ws_dash.write(sr, 1, ss['server_id'], fmt['cell'])
        ws_dash.write(sr, 2, ss['hostname'], fmt['cell'])
        ws_dash.write(sr, 3, ss['ip_address'], fmt['cell'])
        ws_dash.write(sr, 4, asset_type, fmt['cell'])
        ws_dash.write(sr, 5, ss['pass'], fmt['cell'])
        ws_dash.write(sr, 6, ss['fail'], fmt['cell'])
        ws_dash.write(sr, 7, f'{ss["score"]}점', fmt['cell'])
        sr += 1

    # 보안 점수 하위 Top 5
    top5_start = sr + 2
    ws_dash.merge_range(top5_start, 1, top5_start, 7, '보안 점수 하위 Top 5 서버', fmt['dash_section'])
    top5_start += 1
    top5_headers = ['순위', '서버 ID', 'Hostname', 'IP', '보안점수', '취약 항목', '총 항목']
    for i, h in enumerate(top5_headers):
        ws_dash.write(top5_start, 1 + i, h, fmt['header'])

    bottom5 = sorted(server_scores, key=lambda x: x['score'])[:5]
    t5r = top5_start + 1
    for rank, ss in enumerate(bottom5, 1):
        ws_dash.write(t5r, 1, rank, fmt['warn_cell'])
        ws_dash.write(t5r, 2, ss['server_id'], fmt['warn_cell'])
        ws_dash.write(t5r, 3, ss['hostname'], fmt['cell'])
        ws_dash.write(t5r, 4, ss['ip_address'], fmt['cell'])
        ws_dash.write(t5r, 5, f'{ss["score"]}점', fmt['fail'])
        ws_dash.write(t5r, 6, ss['fail'], fmt['fail'])
        ws_dash.write(t5r, 7, ss['total'], fmt['cell'])
        t5r += 1

    # ════════════════════════════════════════════
    # Sheet 3: 항목별 요약 (UNIX/DB 구분 강화)
    # ════════════════════════════════════════════
    ws_matrix = wb.add_worksheet(SHEET_MATRIX)
    ws_matrix.hide_gridlines(2)
    ws_matrix.set_landscape()
    ws_matrix.freeze_panes(2, 4)
    ws_matrix.write_url('A1', f"internal:'{SHEET_DASH}'!A1", fmt['link'], '<< 대시보드')

    matrix_cols = [
        ('No.', 4), ('구분', 5), ('점검 영역', 12), ('코드', 7), ('항목명', 28),
        ('중요도', 5), ('전체', 5), ('취약', 5), ('양호율', 7), ('취약 서버 ID', 45),
    ]
    header_row = 1
    for i, (name, width) in enumerate(matrix_cols):
        ws_matrix.set_column(i, i, width)
        h_fmt = fmt['header_left'] if name in ('항목명', '취약 서버 ID') else fmt['header']
        ws_matrix.write(header_row, i, name, h_fmt)

    # UNIX/DB 분리 정렬
    item_codes_in_results = sorted(set(r['item_code'] for r in results))
    unix_items = [ic for ic in item_codes_in_results if ic.startswith('U-')]
    db_items = [ic for ic in item_codes_in_results if not ic.startswith('U-')]

    mr = header_row + 1
    num = 1

    # ── UNIX 섹션 ──
    if unix_items:
        ws_matrix.merge_range(mr, 0, mr, len(matrix_cols) - 1,
                              f'  UNIX 점검항목 ({len(unix_items)}개)', fmt['section_unix'])
        mr += 1

        for ic in unix_items:
            item_info = kisa_map.get(ic, {})
            cat_kr = CATEGORY_KR.get(item_info.get('category', ''), item_info.get('category', ''))
            sev = item_info.get('severity', '')
            st = item_stats[ic]
            total_cnt = st['total']
            vuln_cnt = st['vuln']
            assessable = total_cnt - st['na']
            pass_rate = (assessable - vuln_cnt) / assessable if assessable > 0 else 0

            base = fmt['os_row']
            base_left = fmt['os_row_left']

            ws_matrix.write(mr, 0, num, base)
            ws_matrix.write(mr, 1, 'UNIX', base)
            ws_matrix.write(mr, 2, cat_kr, base)
            ws_matrix.write(mr, 3, ic, base)
            ws_matrix.write(mr, 4, item_info.get('title', ''), base_left)

            if sev == '상':
                ws_matrix.write(mr, 5, sev, fmt['sev_h'])
            elif sev == '중':
                ws_matrix.write(mr, 5, sev, fmt['sev_m'])
            else:
                ws_matrix.write(mr, 5, sev, fmt['sev_l'])

            ws_matrix.write(mr, 6, total_cnt, base)
            ws_matrix.write(mr, 7, vuln_cnt, fmt['fail'] if vuln_cnt > 0 else fmt['pass'])
            ws_matrix.write(mr, 8, pass_rate, fmt['pct8'])

            vuln_server_list = ', '.join(sorted(set(st['vuln_servers'])))
            if vuln_server_list:
                ws_matrix.write(mr, 9, vuln_server_list, fmt['vuln_list'])
            else:
                ws_matrix.write(mr, 9, '-', base)

            num += 1
            mr += 1

    # ── DB 섹션 ──
    if db_items:
        ws_matrix.merge_range(mr, 0, mr, len(matrix_cols) - 1,
                              f'  DB 점검항목 ({len(db_items)}개)', fmt['section_db'])
        mr += 1

        for ic in db_items:
            item_info = kisa_map.get(ic, {})
            cat_kr = CATEGORY_KR.get(item_info.get('category', ''), item_info.get('category', ''))
            sev = item_info.get('severity', '')
            st = item_stats[ic]
            total_cnt = st['total']
            vuln_cnt = st['vuln']
            assessable = total_cnt - st['na']
            pass_rate = (assessable - vuln_cnt) / assessable if assessable > 0 else 0

            base = fmt['db_row']
            base_left = fmt['db_row_left']

            ws_matrix.write(mr, 0, num, base)
            ws_matrix.write(mr, 1, 'DB', base)
            ws_matrix.write(mr, 2, cat_kr, base)
            ws_matrix.write(mr, 3, ic, base)
            ws_matrix.write(mr, 4, item_info.get('title', ''), base_left)

            if sev == '상':
                ws_matrix.write(mr, 5, sev, fmt['sev_h'])
            elif sev == '중':
                ws_matrix.write(mr, 5, sev, fmt['sev_m'])
            else:
                ws_matrix.write(mr, 5, sev, fmt['sev_l'])

            ws_matrix.write(mr, 6, total_cnt, base)
            ws_matrix.write(mr, 7, vuln_cnt, fmt['fail'] if vuln_cnt > 0 else fmt['pass'])
            ws_matrix.write(mr, 8, pass_rate, fmt['pct8'])

            vuln_server_list = ', '.join(sorted(set(st['vuln_servers'])))
            if vuln_server_list:
                ws_matrix.write(mr, 9, vuln_server_list, fmt['vuln_list'])
            else:
                ws_matrix.write(mr, 9, '-', base)

            num += 1
            mr += 1

    ws_matrix.autofilter(header_row, 0, mr - 1, len(matrix_cols) - 1)

    # ════════════════════════════════════════════
    # Sheet 4: 자산 목록 (서버 시트 하이퍼링크)
    # ════════════════════════════════════════════
    ws_asset = wb.add_worksheet(SHEET_ASSET)
    ws_asset.hide_gridlines(2)
    ws_asset.set_landscape()
    ws_asset.write_url('A1', f"internal:'{SHEET_DASH}'!A1", fmt['link'], '<< 대시보드')

    asset_cols = [
        ('No.', 4), ('서버 ID', 18), ('Hostname', 14), ('IP 주소', 13),
        ('OS 유형', 12), ('DB 유형', 12), ('포트', 5),
        ('담당자', 10), ('부서', 10), ('점수', 7), ('상태', 6),
    ]
    header_row = 1
    for i, (name, width) in enumerate(asset_cols):
        ws_asset.set_column(i, i, width)
        ws_asset.write(header_row, i, name, fmt['header'])

    for idx, srv in enumerate(servers):
        r = idx + header_row + 1
        sid = srv['server_id']
        st = per_server[sid]
        s_score = round(st['pass_weight'] / st['total_weight'] * 100, 1) if st['total_weight'] > 0 else 0
        sheet_name = server_sheet_map[sid]

        ws_asset.write(r, 0, idx + 1, fmt['cell'])
        ws_asset.write(r, 1, sid, fmt['cell'])
        ws_asset.write_url(r, 2, f"internal:'{sheet_name}'!A1", fmt['link_cell'], srv['hostname'])
        ws_asset.write(r, 3, srv['ip_address'], fmt['cell'])
        ws_asset.write(r, 4, srv.get('os_type', ''), fmt['cell'])
        ws_asset.write(r, 5, srv.get('db_type', '없음'), fmt['cell'])
        ws_asset.write(r, 6, srv.get('ssh_port', '22'), fmt['cell'])
        ws_asset.write(r, 7, srv.get('manager', ''), fmt['cell'])
        ws_asset.write(r, 8, srv.get('department', ''), fmt['cell'])
        ws_asset.write(r, 9, f'{s_score}점', fmt['cell'])
        ws_asset.write(r, 10, '활성' if srv.get('is_active') else '비활성', fmt['cell'])

    ws_asset.autofilter(header_row, 0, header_row + len(servers), len(asset_cols) - 1)

    # ════════════════════════════════════════════
    # Sheet 5~N: 서버별 상세 결과 (샘플4 형식)
    # ════════════════════════════════════════════
    for srv in servers:
        sid = srv['server_id']
        sheet_name = server_sheet_map[sid]
        srv_results = sorted(results_by_server.get(sid, []),
                             key=lambda x: (0 if x['item_code'].startswith('U-') else 1, x['item_code']))

        if not srv_results:
            continue

        ws = wb.add_worksheet(sheet_name)
        ws.hide_gridlines(2)
        ws.set_landscape()

        # ── 열 너비 설정 (컴팩트, 9열) ──
        col_widths = [
            ('A:A', 11),   # 점검영역
            ('B:B', 7),    # CODE
            ('C:C', 24),   # 점검항목
            ('D:D', 5),    # 위험도
            ('E:E', 6),    # 진단결과
            ('F:F', 6),    # 조치결과
            ('G:G', 30),   # 취약(현재설정)
            ('H:H', 30),   # 양호(조치 내용 및 미조치시 사유)
            ('I:I', 4),    # 점수
        ]
        for col_range, w in col_widths:
            ws.set_column(col_range, w)

        # 통계 영역 열 너비 (J열~)
        ws.set_column('J:J', 1)    # 구분선
        ws.set_column('K:K', 6)    # 평균
        for c in range(11, 19):    # L~R: 카테고리 양호율
            ws.set_column(c, c, 7)
        ws.set_column('S:S', 1)    # 구분선
        for c in range(19, 28):    # T~AB: 중요도별 건수
            ws.set_column(c, c, 5)

        # A1: 자산 목록으로 돌아가기
        ws.write_url('A1', f"internal:'{SHEET_ASSET}'!A1", fmt['link'], '<< 자산 목록')

        st = per_server[sid]
        s_score = round(st['pass_weight'] / st['total_weight'] * 100, 1) if st['total_weight'] > 0 else 0

        # ── 서버 정보 헤더 (Row 1~2) ──
        info_row = 1
        ws.write(info_row, 0, '대상정보', fmt['srv_info_label'])
        ws.write(info_row, 1, 'Hostname', fmt['srv_info_label'])
        ws.merge_range(info_row, 2, info_row, 3, srv['hostname'], fmt['srv_info_value'])
        ws.write(info_row, 4, 'OS/DB', fmt['srv_info_label'])
        asset_type = srv.get('os_type', '')
        if srv.get('db_type') and srv['db_type'] != '없음':
            asset_type += f" / {srv['db_type']}"
        ws.merge_range(info_row, 5, info_row, 6, asset_type, fmt['srv_info_value'])
        ws.write(info_row, 7, '보안점수', fmt['srv_info_label'])
        score_display = f'{s_score}점'
        if s_score >= 80:
            ws.write(info_row, 8, score_display, fmt['pass'])
        elif s_score >= 60:
            ws.write(info_row, 8, score_display, fmt['warn_cell'])
        else:
            ws.write(info_row, 8, score_display, fmt['fail'])

        info_row += 1
        ws.write(info_row, 0, '', fmt['srv_info_label'])
        ws.write(info_row, 1, 'IP', fmt['srv_info_label'])
        ws.merge_range(info_row, 2, info_row, 3, srv['ip_address'], fmt['srv_info_value'])
        ws.write(info_row, 4, '담당자', fmt['srv_info_label'])
        ws.write(info_row, 5, srv.get('manager', ''), fmt['srv_info_value'])
        ws.write(info_row, 6, '양호/취약', fmt['srv_info_label'])
        ws.merge_range(info_row, 7, info_row, 8, f'{st["pass"]}/{st["fail"]}건', fmt['srv_info_value'])

        info_row += 1
        ws.write(info_row, 0, '', fmt['srv_info_label'])
        ws.write(info_row, 1, 'Server ID', fmt['srv_info_label'])
        ws.merge_range(info_row, 2, info_row, 3, sid, fmt['srv_info_value'])
        ws.write(info_row, 4, '부서', fmt['srv_info_label'])
        ws.merge_range(info_row, 5, info_row, 8, srv.get('department', ''), fmt['srv_info_value'])

        # ── 카테고리별 양호율 + 중요도별 건수 (오른쪽 영역) ──
        stat_row = 1  # info_row와 같은 줄에서 시작

        # 카테고리 양호율 헤더 (K열~)
        ws.write(stat_row, 10, '평균', fmt['stat_header'])
        srv_active_cats = [c for c in CATEGORY_ORDER if c in srv_cat_stats.get(sid, {})]
        for ci, cat_name in enumerate(srv_active_cats):
            short_name = cat_name.replace('파일 및 디렉터리 관리', '파일관리').replace('관리', '').strip()
            ws.write(stat_row, 11 + ci, short_name, fmt['stat_header'])

        # 카테고리 양호율 값
        stat_row += 1
        ws.write(stat_row, 10, s_score / 100.0, fmt['stat_value'])
        for ci, cat_name in enumerate(srv_active_cats):
            cs = srv_cat_stats[sid][cat_name]
            assessable = cs['total'] - cs['na']
            rate = (assessable - cs['fail']) / assessable if assessable > 0 else 1.0
            ws.write(stat_row, 11 + ci, rate, fmt['stat_value'])

        # 중요도별 건수 헤더 (T열~)
        sev_col_start = 19
        sev_headers = ['H-양호', 'H-취약', 'H-NA', 'M-양호', 'M-취약', 'M-NA', 'L-양호', 'L-취약', 'L-NA']
        for si, sh in enumerate(sev_headers):
            ws.write(1, sev_col_start + si, sh, fmt['stat_header'])

        # 중요도별 건수 값
        sev_vals = []
        for sev_key in ['상', '중', '하']:
            ss_data = srv_sev_stats[sid][sev_key]
            sev_vals.extend([ss_data['pass'], ss_data['fail'], ss_data['na']])
        for si, sv in enumerate(sev_vals):
            ws.write(2, sev_col_start + si, sv, fmt['stat_count'])

        # ── 상세 결과 테이블 (샘플4 형식) ──
        detail_start = info_row + 2
        detail_cols_names = ['점검영역', 'CODE', '점검항목', '위험도', '진단결과',
                             '조치결과', '취약(현재설정)', '양호(조치 내용 및 미조치시 사유)', '점수']
        for i, name in enumerate(detail_cols_names):
            h_fmt = fmt['header_left'] if name in ('점검항목', '취약(현재설정)', '양호(조치 내용 및 미조치시 사유)') else fmt['header']
            ws.write(detail_start, i, name, h_fmt)

        ws.freeze_panes(detail_start + 1, 2)

        # 카테고리 그룹핑
        prev_cat = None
        for idx, r in enumerate(srv_results):
            row = detail_start + 1 + idx
            itype = item_type(r['item_code'])
            base = fmt['os_row'] if itype == 'UNIX' else fmt['db_row']
            base_left = fmt['os_row_left'] if itype == 'UNIX' else fmt['db_row_left']

            # 점검영역 (카테고리 그룹핑: 첫 행에만 표시)
            cat_kr = CATEGORY_KR.get(r['category'], r['category'])
            if cat_kr != prev_cat:
                ws.write(row, 0, cat_kr, base)
                prev_cat = cat_kr
            else:
                ws.write(row, 0, '', base)

            ws.write(row, 1, r['item_code'], base)
            ws.write(row, 2, r['title'], base_left)

            # 위험도
            sev = r['severity']
            if sev == '상':
                ws.write(row, 3, sev, fmt['sev_h'])
            elif sev == '중':
                ws.write(row, 3, sev, fmt['sev_m'])
            else:
                ws.write(row, 3, sev, fmt['sev_l'])

            # 진단결과
            status = r['status']
            if '양호' in status:
                ws.write(row, 4, status, fmt['pass'])
            elif status == '취약':
                ws.write(row, 4, status, fmt['fail'])
            else:
                ws.write(row, 4, status, fmt['na'])

            # 조치결과 (현재 데이터 없음 → 빈칸)
            ws.write(row, 5, '', base)

            # 현황 요약 (JSON 정제)
            detail_text, cmd_text = parse_evidence(r.get('raw_evidence', ''))

            # 취약(현재설정) / 양호(조치 내용) 분리
            if status == '취약':
                ws.write(row, 6, detail_text, fmt['cell_wrap'])
                ws.write(row, 7, '', base_left)
            elif '양호' in status:
                ws.write(row, 6, '', base_left)
                ws.write(row, 7, detail_text, fmt['cell_wrap'])
            else:
                ws.write(row, 6, '', base_left)
                ws.write(row, 7, detail_text if detail_text else '', fmt['cell_wrap'])

            if cmd_text:
                # 코멘트는 내용이 있는 셀에 붙이기
                comment_col = 6 if status == '취약' else 7
                ws.write_comment(row, comment_col, f'[점검 명령어]\n{cmd_text}', {
                    'width': 400, 'height': 200, 'font_size': 9,
                })

            # 점수 (샘플4 형식: 중요도별 배점)
            item_score = ITEM_SCORE.get(sev, 6)
            if '양호' in status:
                ws.write(row, 8, item_score, fmt['score_pass'])
            elif status == '취약':
                ws.write(row, 8, 0, fmt['score_fail'])
            else:
                ws.write(row, 8, '-', fmt['na'])

            # 행 높이 (컴팩트)
            max_len = len(detail_text)
            if max_len > 120:
                ws.set_row(row, 65)
            elif max_len > 80:
                ws.set_row(row, 50)
            elif max_len > 40:
                ws.set_row(row, 35)
            else:
                ws.set_row(row, 22)

        ws.autofilter(detail_start, 0, detail_start + len(srv_results), len(detail_cols_names) - 1)

        print(f"  [Sheet] {sheet_name}: {len(srv_results)}건 (양호 {st['pass']}, 취약 {st['fail']}, 점수 {s_score}점)")

    # ── 닫기 ──
    wb.close()
    print(f"\n[SUCCESS] 보고서 생성 완료: {output_path}")
    print(f"  - 서버: {len(servers)}대 ({len(servers)}개 시트)")
    except_info = f', 예외 {except_cnt}' if except_cnt > 0 else ''
    print(f"  - 점검 결과: {total}건 (양호 {pass_cnt} / 취약 {fail_cnt} / N/A {na_cnt}{except_info})")
    print(f"  - 보안 점수: {score}점 (가중치: 상=3, 중=2, 하=1)")
    return output_path


def main():
    parser = argparse.ArgumentParser(description='취약점 진단 결과 엑셀 보고서 생성')
    parser.add_argument('--company', type=str, default=None, help='특정 회사만 (예: AUTOEVER)')
    parser.add_argument('--output', type=str, default=None, help='출력 파일 경로')
    args = parser.parse_args()

    servers, kisa_items, kisa_map, results = fetch_report_data(args.company)

    if not results:
        print("[ERROR] 점검 결과가 없습니다. 먼저 전수 점검을 실행해주세요.")
        sys.exit(1)

    company_name = args.company or servers[0].get('company', 'REPORT')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M')

    if args.output:
        output_path = args.output
    else:
        report_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'excel_report')
        os.makedirs(report_dir, exist_ok=True)
        output_path = os.path.join(report_dir, f'{company_name}_취약점진단결과_{timestamp}.xlsx')

    generate_report(servers, kisa_items, kisa_map, results, output_path, company_name)


if __name__ == '__main__':
    main()
