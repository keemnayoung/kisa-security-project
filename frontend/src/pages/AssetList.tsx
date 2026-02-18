/**
 * 자산 목록 페이지
 * - 등록된 서버 목록 표시
 * - 통합 전수 점검 / OS 전수 점검 / DB 전수 점검 버튼
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { TopNav } from '../components/TopNav';
import { ScanProgressModal } from '../components/ScanProgressModal';
import { startFullScan } from '../api/scan';
import type { ScanResult, ScanType } from '../api/scan';
import './AssetList.css';

const API_BASE = `http://${window.location.hostname}:8000`;

export function AssetList() {
  const navigate = useNavigate();
  const [servers, setServers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedServers, setSelectedServers] = useState<Set<string>>(new Set());
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');

  // 스캔 모달 상태
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [scanTotalServers, setScanTotalServers] = useState(0);

  let user: any = {};
  try {
    const userStr = localStorage.getItem('user');
    if (userStr) user = JSON.parse(userStr);
  } catch (e) {
    console.error('Failed to parse user:', e);
  }

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) { navigate('/'); return; }
    fetchServers();
  }, [navigate]);

  const fetchServers = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/assets`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        setServers(await response.json());
      }
    } catch (error) {
      console.error('Failed to fetch servers:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    navigate('/');
  };

  // 전체 선택
  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedServers(new Set(servers.map(s => s.server_id)));
    } else {
      setSelectedServers(new Set());
    }
  };

  const handleSelectServer = (serverId: string, checked: boolean) => {
    const next = new Set(selectedServers);
    if (checked) next.add(serverId); else next.delete(serverId);
    setSelectedServers(next);
  };

  // 정렬
  const handleSort = (column: string) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const getSortedServers = () => {
    if (!sortColumn) return servers;
    return [...servers].sort((a, b) => {
      const aVal = a[sortColumn] || '';
      const bVal = b[sortColumn] || '';
      return sortDirection === 'asc'
        ? aVal.toString().localeCompare(bVal.toString(), 'ko', { numeric: true })
        : bVal.toString().localeCompare(aVal.toString(), 'ko', { numeric: true });
    });
  };

  const getSortIcon = (column: string) => {
    if (sortColumn !== column) return '';
    return sortDirection === 'asc' ? ' ↑' : ' ↓';
  };

  // 선택된 서버 삭제
  const handleDeleteSelected = async () => {
    if (selectedServers.size === 0) {
      alert('삭제할 서버를 선택하세요');
      return;
    }

    if (!confirm(`선택한 ${selectedServers.size}개의 서버를 삭제하시겠습니까?`)) return;

    try {
      const token = localStorage.getItem('access_token');
      let successCount = 0;
      const errors: string[] = [];

      for (const sid of selectedServers) {
        const response = await fetch(`${API_BASE}/api/assets/${sid}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
          successCount++;
        } else {
          try {
            const err = await response.json();
            errors.push(`${sid}: ${err.detail || 'error'}`);
          } catch {
            errors.push(`${sid}: HTTP ${response.status}`);
          }
        }
      }

      if (errors.length > 0) {
        alert(`${successCount}개 삭제 완료, ${errors.length}개 실패\n\n${errors.join('\n')}`);
      } else {
        alert(`${successCount}개 서버 삭제 완료`);
      }

      setSelectedServers(new Set());
      await fetchServers();
    } catch (error) {
      console.error('Delete error:', error);
      alert('삭제 중 오류가 발생했습니다');
    }
  };

  // 점검 시작
  const handleStartScan = async (scanType: ScanType) => {
    if (selectedServers.size === 0) {
      alert('서버를 선택해주세요');
      return;
    }

    const targetIds = Array.from(selectedServers);

    const typeLabels: Record<ScanType, string> = {
      'scan-all': '통합 전수 점검 (OS+DB)',
      'scan': 'OS 전수 점검',
      'scan-db': 'DB 전수 점검'
    };

    const targetLabel = `선택한 ${targetIds.length}개 서버`;

    if (!confirm(`${targetLabel}에 대해 ${typeLabels[scanType]}을 시작하시겠습니까?`)) return;

    try {
      const response = await startFullScan(targetIds, scanType);
      setScanJobId(response.job_id);
      setScanTotalServers(response.total_servers);
      setShowScanModal(true);
    } catch (error: any) {
      console.error('Failed to start scan:', error);
      if (error.response?.status === 401) {
        alert('로그인이 만료되었습니다.');
        navigate('/');
      } else {
        alert('점검을 시작하는데 실패했습니다.');
      }
    }
  };

  const handleScanComplete = (_result: ScanResult) => {
    fetchServers();
    setShowScanModal(false);
    setScanJobId(null);
    navigate('/analysis');
  };

  const handleCloseScanModal = () => {
    setShowScanModal(false);
    setScanJobId(null);
  };

  if (loading) {
    return (
      <>
        <TopNav currentUser={user} onLogout={handleLogout} />
        <div className="asset-list-page">
          <div className="asset-list-loading">데이터를 불러오는 중...</div>
        </div>
      </>
    );
  }

  return (
    <>
      <TopNav currentUser={user} onLogout={handleLogout} />
      <div className="asset-list-page">
        <div className="asset-list-container">
          {/* 헤더 */}
          <div className="asset-list-header">
            <div>
              <h1 className="asset-list-title">자산 목록</h1>
              <p className="asset-list-subtitle">
                등록된 서버를 관리하고 보안 점검을 실행할 수 있습니다
              </p>
            </div>
            {user.role === 'ADMIN' && (
              <button
                className="scan-btn scan-btn-register"
                onClick={() => navigate('/dashboard')}
              >
                + 자산 등록
              </button>
            )}
          </div>

          {/* 점검 버튼 영역 */}
          <div className="scan-actions">
            <div className="scan-actions-left">
              <span className="server-count-label">
                총 {servers.length}대 등록
                {selectedServers.size > 0 && ` · ${selectedServers.size}개 선택`}
              </span>
            </div>
            {user.role === 'ADMIN' && (
              <div className="scan-actions-right">
                {selectedServers.size > 0 && (
                  <button
                    className="scan-btn scan-btn-delete"
                    onClick={handleDeleteSelected}
                  >
                    삭제 ({selectedServers.size})
                  </button>
                )}
                <button
                  className="scan-btn scan-btn-all"
                  onClick={() => handleStartScan('scan-all')}
                >
                  <img src="/search.png" alt="" className="scan-btn-icon" />
                  통합 전수 점검
                </button>
                <button
                  className="scan-btn scan-btn-os"
                  onClick={() => handleStartScan('scan')}
                >
                  <img src="/linux.png" alt="" className="scan-btn-icon" />
                  OS 점검
                </button>
                <button
                  className="scan-btn scan-btn-db"
                  onClick={() => handleStartScan('scan-db')}
                >
                  <img src="/database.png" alt="" className="scan-btn-icon" />
                  DB 점검
                </button>
              </div>
            )}
          </div>

          {/* 서버 테이블 */}
          <div className="asset-table-card">
            <div className="asset-table-wrapper">
              <table className="asset-table">
                <thead>
                  <tr>
                    {user.role === 'ADMIN' && (
                      <th className="col-check">
                        <input
                          type="checkbox"
                          checked={servers.length > 0 && selectedServers.size === servers.length}
                          onChange={handleSelectAll}
                        />
                      </th>
                    )}
                    {[
                      { key: 'server_id', label: '서버명' },
                      { key: 'ip_address', label: 'IP 주소' },
                      { key: 'company', label: '회사' },
                      { key: 'os_type', label: 'OS' },
                      { key: 'db_type', label: 'DB' },
                      { key: 'manager', label: '담당자' },
                      { key: 'department', label: '부서' },
                    ].map(col => (
                      <th key={col.key} className="sortable-th" onClick={() => handleSort(col.key)}>
                        {col.label}{getSortIcon(col.key)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {getSortedServers().map(server => (
                    <tr key={server.server_id} className={selectedServers.has(server.server_id) ? 'row-selected' : ''}>
                      {user.role === 'ADMIN' && (
                        <td className="col-check">
                          <input
                            type="checkbox"
                            checked={selectedServers.has(server.server_id)}
                            onChange={e => handleSelectServer(server.server_id, e.target.checked)}
                          />
                        </td>
                      )}
                      <td className="col-server-id">{server.server_id}</td>
                      <td>{server.ip_address}</td>
                      <td>{server.company}</td>
                      <td>{server.os_type}</td>
                      <td>{server.db_type || '-'}</td>
                      <td>{server.manager}</td>
                      <td>{server.department}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {servers.length === 0 && (
              <div className="empty-state">
                <p>등록된 서버가 없습니다</p>
                {user.role === 'ADMIN' && (
                  <button className="go-register-btn" onClick={() => navigate('/dashboard')}>
                    서버 등록하러 가기
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 전수 점검 모달 */}
      {showScanModal && scanJobId && (
        <ScanProgressModal
          jobId={scanJobId}
          totalServers={scanTotalServers}
          onComplete={handleScanComplete}
          onClose={handleCloseScanModal}
        />
      )}
    </>
  );
}
