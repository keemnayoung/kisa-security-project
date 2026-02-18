/**
 * 점검 및 조치 이력 페이지
 * 좌: 점검 이력 / 우: 조치 이력
 */

import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { TopNav } from '../components/TopNav';
import { getHistory } from '../api/analysis';
import type { ScanHistoryItem, RemediationHistoryItem } from '../api/analysis';
import './History.css';

type SortDir = 'asc' | 'desc';

type ScanSortKey = keyof ScanHistoryItem;
type RemSortKey = 'action_date' | 'server_id' | 'item_code' | 'title' | 'is_success';

function comparePrimitive(a: string | boolean, b: string | boolean, dir: SortDir): number {
  if (a === b) return 0;
  const result = a < b ? -1 : 1;
  return dir === 'asc' ? result : -result;
}

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  return (
    <span className={`sort-icon ${active ? 'active' : ''}`}>
      {active ? (dir === 'asc' ? '▲' : '▼') : '⇅'}
    </span>
  );
}

/** "2026-02-17 16:58" → "2026-02-17" */
function extractDate(datetime: string): string {
  return datetime.split(' ')[0] || datetime;
}

export function History() {
  const navigate = useNavigate();
  const [user] = useState(() => {
    const raw = localStorage.getItem('user');
    return raw ? JSON.parse(raw) : { role: 'VIEWER' };
  });

  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [remediations, setRemediations] = useState<RemediationHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  // 날짜 필터
  const [scanDateFilter, setScanDateFilter] = useState('');
  const [remDateFilter, setRemDateFilter] = useState('');

  // 점검 이력 정렬
  const [scanSortKey, setScanSortKey] = useState<ScanSortKey>('scan_date');
  const [scanSortDir, setScanSortDir] = useState<SortDir>('desc');

  // 조치 이력 정렬
  const [remSortKey, setRemSortKey] = useState<RemSortKey>('action_date');
  const [remSortDir, setRemSortDir] = useState<SortDir>('desc');

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    navigate('/');
  };

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const data = await getHistory();
        setScans(data.scans);
        setRemediations(data.remediations);
      } catch (error) {
        console.error('Failed to fetch history:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  const toggleScanSort = (key: ScanSortKey) => {
    if (scanSortKey === key) {
      setScanSortDir(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setScanSortKey(key);
      setScanSortDir('asc');
    }
  };

  const toggleRemSort = (key: RemSortKey) => {
    if (remSortKey === key) {
      setRemSortDir(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setRemSortKey(key);
      setRemSortDir('asc');
    }
  };

  // 날짜 필터 → 정렬
  const sortedScans = useMemo(() => {
    let filtered = scans;
    if (scanDateFilter) {
      filtered = scans.filter(s => extractDate(s.scan_date) === scanDateFilter);
    }
    return [...filtered].sort((a, b) =>
      comparePrimitive(String(a[scanSortKey]), String(b[scanSortKey]), scanSortDir)
    );
  }, [scans, scanDateFilter, scanSortKey, scanSortDir]);

  const sortedRemediations = useMemo(() => {
    let filtered = remediations;
    if (remDateFilter) {
      filtered = remediations.filter(r => extractDate(r.action_date) === remDateFilter);
    }
    return [...filtered].sort((a, b) => {
      const av = remSortKey === 'is_success' ? String(a.is_success) : String(a[remSortKey]);
      const bv = remSortKey === 'is_success' ? String(b.is_success) : String(b[remSortKey]);
      return comparePrimitive(av, bv, remSortDir);
    });
  }, [remediations, remDateFilter, remSortKey, remSortDir]);

  // 점검 날짜 목록 (달력 제한용)
  const scanDates = useMemo(() => {
    const set = new Set(scans.map(s => extractDate(s.scan_date)));
    return Array.from(set).sort();
  }, [scans]);

  const remDates = useMemo(() => {
    const set = new Set(remediations.map(r => extractDate(r.action_date)));
    return Array.from(set).sort();
  }, [remediations]);

  if (loading) {
    return (
      <>
        <TopNav currentUser={user} onLogout={handleLogout} />
        <div className="history-page">
          <div className="history-loading">데이터를 불러오는 중...</div>
        </div>
      </>
    );
  }

  return (
    <>
      <TopNav currentUser={user} onLogout={handleLogout} />
      <div className="history-page">
        <div className="history-header">
          <h1 className="history-page-title">점검 및 조치 이력</h1>
          <p className="history-page-subtitle">서버별 보안 점검 결과와 자동조치 이력을 확인할 수 있습니다</p>
        </div>

        <div className="history-grid">
          {/* 좌측: 점검 이력 */}
          <div className="history-panel">
            <div className="panel-header">
              <div className="panel-title-row">
                <h2 className="panel-title">점검 이력</h2>
              </div>
              <div className="panel-header-right">
                <div className="date-filter">
                  <input
                    type="date"
                    className="date-input"
                    value={scanDateFilter}
                    min={scanDates[0] || ''}
                    max={scanDates[scanDates.length - 1] || ''}
                    onChange={e => setScanDateFilter(e.target.value)}
                  />
                  {scanDateFilter && (
                    <button className="date-clear" onClick={() => setScanDateFilter('')}>
                      ✕
                    </button>
                  )}
                </div>
                <span className="panel-count">{sortedScans.length}건</span>
              </div>
            </div>

            <div className="panel-table-wrap">
              <table className="history-table">
                <thead>
                  <tr>
                    <th className="sortable" onClick={() => toggleScanSort('scan_date')}>
                      점검 일시 <SortIcon active={scanSortKey === 'scan_date'} dir={scanSortDir} />
                    </th>
                    <th className="sortable" onClick={() => toggleScanSort('server_id')}>
                      서버 ID <SortIcon active={scanSortKey === 'server_id'} dir={scanSortDir} />
                    </th>
                    <th className="sortable" onClick={() => toggleScanSort('item_code')}>
                      번호 <SortIcon active={scanSortKey === 'item_code'} dir={scanSortDir} />
                    </th>
                    <th className="sortable" onClick={() => toggleScanSort('title')}>
                      점검 항목 <SortIcon active={scanSortKey === 'title'} dir={scanSortDir} />
                    </th>
                    <th className="sortable" onClick={() => toggleScanSort('status')}>
                      결과 <SortIcon active={scanSortKey === 'status'} dir={scanSortDir} />
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sortedScans.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="empty-row">
                        {scanDateFilter ? '해당 날짜의 점검 이력이 없습니다' : '점검 이력이 없습니다'}
                      </td>
                    </tr>
                  ) : (
                    sortedScans.map((s, i) => (
                      <tr key={`${s.server_id}-${s.item_code}-${i}`}>
                        <td className="col-date">{s.scan_date}</td>
                        <td className="col-server">{s.server_id}</td>
                        <td className="col-code">{s.item_code}</td>
                        <td className="col-title">{s.title}</td>
                        <td className="col-result">
                          <span className={`result-badge ${s.status === '양호' ? 'secure' : 'vulnerable'}`}>
                            {s.status}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* 우측: 조치 이력 */}
          <div className="history-panel">
            <div className="panel-header">
              <div className="panel-title-row">
                <h2 className="panel-title">조치 이력</h2>
              </div>
              <div className="panel-header-right">
                <div className="date-filter">
                  <input
                    type="date"
                    className="date-input"
                    value={remDateFilter}
                    min={remDates[0] || ''}
                    max={remDates[remDates.length - 1] || ''}
                    onChange={e => setRemDateFilter(e.target.value)}
                  />
                  {remDateFilter && (
                    <button className="date-clear" onClick={() => setRemDateFilter('')}>
                      ✕
                    </button>
                  )}
                </div>
                <span className="panel-count">{sortedRemediations.length}건</span>
              </div>
            </div>

            <div className="panel-table-wrap">
              <table className="history-table">
                <thead>
                  <tr>
                    <th className="sortable" onClick={() => toggleRemSort('action_date')}>
                      조치 일시 <SortIcon active={remSortKey === 'action_date'} dir={remSortDir} />
                    </th>
                    <th className="sortable" onClick={() => toggleRemSort('server_id')}>
                      서버 ID <SortIcon active={remSortKey === 'server_id'} dir={remSortDir} />
                    </th>
                    <th className="sortable" onClick={() => toggleRemSort('item_code')}>
                      번호 <SortIcon active={remSortKey === 'item_code'} dir={remSortDir} />
                    </th>
                    <th className="sortable" onClick={() => toggleRemSort('title')}>
                      조치 항목 <SortIcon active={remSortKey === 'title'} dir={remSortDir} />
                    </th>
                    <th className="sortable" onClick={() => toggleRemSort('is_success')}>
                      결과 <SortIcon active={remSortKey === 'is_success'} dir={remSortDir} />
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sortedRemediations.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="empty-row">
                        {remDateFilter ? '해당 날짜의 조치 이력이 없습니다' : '조치 이력이 없습니다'}
                      </td>
                    </tr>
                  ) : (
                    sortedRemediations.map((r, i) => (
                      <tr key={`${r.server_id}-${r.item_code}-${i}`}>
                        <td className="col-date">{r.action_date}</td>
                        <td className="col-server">{r.server_id}</td>
                        <td className="col-code">{r.item_code}</td>
                        <td className="col-title">{r.title}</td>
                        <td className="col-result">
                          <span className={`result-badge ${r.is_success ? 'success' : 'fail'}`}>
                            {r.is_success ? '성공' : '실패'}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
