/**
 * 예외 처리 관리 페이지
 */

import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { TopNav } from '../components/TopNav';
import { ExceptionModal } from '../components/ExceptionModal';
import { getExceptions, deleteException } from '../api/exceptions';
import type { ExceptionItem } from '../api/exceptions';
import './ExceptionManagement.css';

type StatusFilter = 'all' | 'active' | 'expired';

export function ExceptionManagement() {
  const navigate = useNavigate();
  const [user] = useState(() => {
    const raw = localStorage.getItem('user');
    return raw ? JSON.parse(raw) : { role: 'VIEWER' };
  });

  const [exceptions, setExceptions] = useState<ExceptionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState({ total: 0, active_count: 0, expired_count: 0 });

  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showModal, setShowModal] = useState(false);

  const loadExceptions = async () => {
    try {
      setLoading(true);
      const data = await getExceptions();
      setExceptions(data.items);
      setSummary({ total: data.total, active_count: data.active_count, expired_count: data.expired_count });
    } catch (error) {
      console.error('Failed to load exceptions:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadExceptions();
  }, []);

  const filteredExceptions = useMemo(() => {
    const q = searchQuery.toLowerCase();
    return exceptions
      .filter(e => {
        if (statusFilter === 'active') return e.is_active;
        if (statusFilter === 'expired') return !e.is_active;
        return true;
      })
      .filter(e =>
        !q ||
        e.server_id.toLowerCase().includes(q) ||
        e.item_code.toLowerCase().includes(q) ||
        e.item_title.toLowerCase().includes(q) ||
        e.reason.toLowerCase().includes(q)
      );
  }, [exceptions, statusFilter, searchQuery]);

  const handleDelete = async (exceptionId: number) => {
    if (!confirm('이 예외를 삭제하시겠습니까?')) return;
    try {
      await deleteException(exceptionId);
      loadExceptions();
    } catch (error: any) {
      const detail = error.response?.data?.detail || '삭제에 실패했습니다';
      alert(detail);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    navigate('/');
  };

  return (
    <>
      <TopNav currentUser={user} onLogout={handleLogout} />
      <div className="exception-page">
        {/* 헤더 */}
        <div className="exception-header">
          <div>
            <h1 className="exception-page-title">예외 처리 관리</h1>
            <p className="exception-page-subtitle">업무상 조치가 불가능한 취약 항목의 예외 사유와 유효 기한을 관리합니다</p>
          </div>
          {user.role === 'ADMIN' && (
            <button className="exception-register-btn" onClick={() => setShowModal(true)}>
              + 예외 등록
            </button>
          )}
        </div>

        {/* 요약 카드 */}
        <div className="exception-summary-cards">
          <div className="summary-card">
            <span className="summary-card-label">전체 예외</span>
            <span className="summary-card-value">{summary.total}건</span>
          </div>
          <div className="summary-card active">
            <span className="summary-card-label">활성 예외</span>
            <span className="summary-card-value">{summary.active_count}건</span>
          </div>
          <div className="summary-card expired">
            <span className="summary-card-label">만료 예외</span>
            <span className="summary-card-value">{summary.expired_count}건</span>
          </div>
        </div>

        {/* 필터 바 */}
        <div className="exception-filter-bar">
          <div className="filter-tabs">
            {(['all', 'active', 'expired'] as StatusFilter[]).map(f => (
              <button
                key={f}
                className={`filter-tab ${statusFilter === f ? 'active' : ''}`}
                onClick={() => setStatusFilter(f)}
              >
                {f === 'all' ? '전체' : f === 'active' ? '활성' : '만료'}
              </button>
            ))}
          </div>
          <div className="exception-search-box">
            <input
              type="text"
              placeholder="서버, 항목, 사유 검색..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>
        </div>

        {/* 테이블 */}
        <div className="exception-table-card">
          {loading ? (
            <div className="exception-empty">불러오는 중...</div>
          ) : filteredExceptions.length === 0 ? (
            <div className="exception-empty">
              {exceptions.length === 0 ? '등록된 예외가 없습니다' : '검색 결과가 없습니다'}
            </div>
          ) : (
            <table className="exception-table">
              <thead>
                <tr>
                  <th>서버 ID</th>
                  <th>IP</th>
                  <th>번호</th>
                  <th>점검 항목</th>
                  <th>위험도</th>
                  <th>사유</th>
                  <th>유효 기한</th>
                  <th>상태</th>
                  {user.role === 'ADMIN' && <th>관리</th>}
                </tr>
              </thead>
              <tbody>
                {filteredExceptions.map(e => (
                  <tr key={e.exception_id} className={e.is_active ? '' : 'row-expired'}>
                    <td className="col-server">{e.server_id}</td>
                    <td className="col-ip">{e.ip_address}</td>
                    <td className="col-code">{e.item_code}</td>
                    <td className="col-item-title">{e.item_title}</td>
                    <td className="col-severity">
                      <span className="severity-badge" data-severity={e.severity}>
                        {e.severity}
                      </span>
                    </td>
                    <td className="col-reason">{e.reason}</td>
                    <td className="col-date">{e.valid_date}</td>
                    <td className="col-status">
                      <span className={`ex-status-badge ${e.is_active ? 'active' : 'expired'}`}>
                        {e.is_active ? '활성' : '만료'}
                      </span>
                    </td>
                    {user.role === 'ADMIN' && (
                      <td className="col-manage">
                        <button
                          className="delete-btn"
                          onClick={() => handleDelete(e.exception_id)}
                        >
                          삭제
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {showModal && (
        <ExceptionModal
          onClose={() => setShowModal(false)}
          onSuccess={() => { setShowModal(false); loadExceptions(); }}
        />
      )}
    </>
  );
}
