/**
 * 자산 분석 페이지
 * - 점검 결과 / 조치 이력 서브탭
 * - 자동조치 버튼 + RemediationModal
 */

import { useNavigate, useSearchParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import {
  getAnalysisServers, getServerResults, getRemediationHistory,
  type AnalysisServer, type ServerResults, type CategoryResult,
  type RemediationResults, type RemediationCategoryResult
} from '../api/analysis';
import { RemediationModal, type FixableItemWithCategory } from '../components/RemediationModal';
import { ExceptionModal } from '../components/ExceptionModal';
import { TopNav } from '../components/TopNav';
import './AssetAnalysis.css';

const OS_CATEGORY_LABELS: { [key: string]: { label: string; icon: string } } = {
  account: { label: '계정 관리', icon: '/account.png' },
  directory: { label: '파일 및 디렉토리 관리', icon: '/folder.png' },
  service: { label: '서비스 관리', icon: '/service.png' },
  patch: { label: '패치 관리', icon: '/patch.png' },
  log: { label: '로그 관리', icon: '/record.png' },
};

const DB_CATEGORY_LABELS: { [key: string]: { label: string; icon: string } } = {
  account: { label: '계정 관리', icon: '/account.png' },
  access: { label: '접근 관리', icon: '/access.png' },
  option: { label: '옵션 관리', icon: '/service.png' },
  patch: { label: '패치 관리', icon: '/patch.png' },
};

interface ParsedEvidence {
  reasonLine: string;
  detail: string;
}

function parseEvidence(raw: string): ParsedEvidence {
  if (!raw) return { reasonLine: '', detail: '' };

  let detailFull = '';

  // 1차: 직접 JSON 파싱
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed === 'object' && parsed !== null) {
      detailFull = parsed.detail || '';
    } else if (typeof parsed === 'string') {
      try {
        const inner = JSON.parse(parsed);
        if (typeof inner === 'object' && inner !== null) {
          detailFull = inner.detail || '';
        }
      } catch {}
    }
    // JSON parse 후 리터럴 \\n, \n, \\t, \t 를 실제 줄바꿈/탭으로 변환 (이중 이스케이프 우선 처리)
    detailFull = detailFull.replace(/\\\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\\\t/g, '\t').replace(/\\t/g, '\t');
  } catch {
    // 2차: 이스케이프된 JSON에서 추출
    const escapedDetailMatch = raw.match(/\\"detail\\"\s*:\s*\\"([\s\S]*?)\\"/);
    if (escapedDetailMatch) {
      detailFull = escapedDetailMatch[1].replace(/\\\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\\\t/g, '\t').replace(/\\t/g, '\t');
    }

    // 3차: 일반 JSON에서 추출
    if (!detailFull) {
      const normalDetailMatch = raw.match(/"detail"\s*:\s*"((?:[^"\\]|\\.)*)"/);
      if (normalDetailMatch) {
        detailFull = normalDetailMatch[1].replace(/\\\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\\\t/g, '\t').replace(/\\t/g, '\t').replace(/\\"/g, '"');
      }
    }
  }

  // detail에서 reason_line(첫 줄)과 DETAIL_CONTENT(나머지) 분리
  const nlIdx = detailFull.indexOf('\n');
  const reasonLine = nlIdx > 0 ? detailFull.slice(0, nlIdx) : detailFull;
  const detail = nlIdx > 0 ? detailFull.slice(nlIdx + 1).trim() : '';

  return { reasonLine, detail };
}

function EvidenceCell({ raw, overrideText, mode = 'scan', guide, autoFix }: {
  raw: string;
  overrideText?: string;
  mode?: 'scan' | 'remediation';
  guide?: string;
  autoFix?: boolean;
}) {
  const [showDetail, setShowDetail] = useState(false);
  const [showGuide, setShowGuide] = useState(false);

  const detailLabel = mode === 'scan' ? '점검 근거' : '조치 근거';
  const guideLabel = autoFix ? '자동조치 가이드' : '수동조치 가이드';
  const guideClass = autoFix ? 'guide-auto' : 'guide-manual';

  // overrideText가 있으면 그것만 표시 (조치 실패 사유 등)
  if (overrideText) {
    return (
      <td className="col-evidence">
        <div className="evidence-summary">{overrideText}</div>
      </td>
    );
  }

  const { reasonLine, detail } = parseEvidence(raw);

  if (!reasonLine && !detail) return <td className="col-evidence">-</td>;

  return (
    <td className="col-evidence">
      <div className="evidence-summary">{reasonLine}</div>
      <div className="evidence-toggles">
        {detail && (
          <button className="evidence-toggle" onClick={() => setShowDetail(!showDetail)}>
            {showDetail ? `${detailLabel} \u25B2` : `${detailLabel} \u25BC`}
          </button>
        )}
        {mode === 'scan' && guide && (
          <button className={`evidence-toggle guide-toggle ${guideClass} ${showGuide ? 'active' : ''}`} onClick={() => setShowGuide(!showGuide)}>
            {showGuide ? `${guideLabel} \u25B2` : `${guideLabel} \u25BC`}
          </button>
        )}
      </div>
      {showDetail && detail && <div className="evidence-detail">{detail}</div>}
      {showGuide && guide && <div className={`evidence-detail guide-detail ${guideClass}`}>{guide}</div>}
    </td>
  );
}

export function AssetAnalysis() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [servers, setServers] = useState<AnalysisServer[]>([]);
  const [selectedServerId, setSelectedServerId] = useState<string | null>(null);
  const [serverResults, setServerResults] = useState<ServerResults | null>(null);
  const [remediationResults, setRemediationResults] = useState<RemediationResults | null>(null);
  const [activeTab, setActiveTab] = useState<'linux' | 'database'>('linux');
  const [initialApplied, setInitialApplied] = useState(false);
  const [subTab, setSubTab] = useState<'scan' | 'remediation'>('scan');
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'name' | 'vuln'>('name');
  const [loading, setLoading] = useState(true);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [showRemediation, setShowRemediation] = useState(false);
  const [showExceptionModal, setShowExceptionModal] = useState(false);
  const [exceptionPrefill, setExceptionPrefill] = useState<{
    serverId: string; itemCode: string; itemTitle: string;
  } | null>(null);
  const [selectedFixItems, setSelectedFixItems] = useState<Set<string>>(new Set());

  let user: any = {};
  try {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      user = JSON.parse(userStr);
    }
  } catch (e) {
    console.error('Failed to parse user:', e);
  }

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      navigate('/');
      return;
    }
    loadServers();
  }, [navigate]);

  const loadServers = async () => {
    try {
      setLoading(true);
      const data = await getAnalysisServers();
      setServers(data);
    } catch (error: any) {
      console.error('Failed to load servers:', error);
      if (error.response?.status === 401) {
        localStorage.removeItem('access_token');
        navigate('/');
      }
    } finally {
      setLoading(false);
    }
  };

  const loadServerResults = async (serverId: string) => {
    try {
      setResultsLoading(true);
      const data = await getServerResults(serverId);
      setServerResults(data);
      setExpandedCategories(new Set());
    } catch (error: any) {
      console.error('Failed to load server results:', error);
      if (error.response?.status === 401) {
        localStorage.removeItem('access_token');
        navigate('/');
      }
    } finally {
      setResultsLoading(false);
    }
  };

  const loadRemediationHistory = async (serverId: string) => {
    try {
      const data = await getRemediationHistory(serverId);
      setRemediationResults(data);
    } catch (error: any) {
      console.error('Failed to load remediation history:', error);
    }
  };

  // URL 파라미터로 서버+탭 자동 선택 (?server=xxx&tab=linux|database)
  useEffect(() => {
    if (initialApplied || servers.length === 0) return;
    const paramServer = searchParams.get('server');
    const paramTab = searchParams.get('tab');
    if (paramServer && servers.some(s => s.server_id === paramServer)) {
      setSelectedServerId(paramServer);
      if (paramTab === 'linux' || paramTab === 'database') {
        setActiveTab(paramTab);
      }
      setSubTab('scan');
      loadServerResults(paramServer);
      loadRemediationHistory(paramServer);
    }
    setInitialApplied(true);
  }, [servers]);

  const handleServerSelect = (serverId: string) => {
    setSelectedServerId(serverId);
    setActiveTab('linux');
    setSubTab('scan');
    setSelectedFixItems(new Set());
    loadServerResults(serverId);
    loadRemediationHistory(serverId);
  };

  const toggleCategory = (category: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    navigate('/');
  };

  const handleSubTabChange = (tab: 'scan' | 'remediation') => {
    setSubTab(tab);
    setExpandedCategories(new Set());
  };

  // 체크박스 토글
  const toggleFixItem = (itemCode: string) => {
    setSelectedFixItems(prev => {
      const next = new Set(prev);
      if (next.has(itemCode)) next.delete(itemCode); else next.add(itemCode);
      return next;
    });
  };

  // 전체 선택/해제 (현재 보이는 카테고리 기준)
  const toggleAllFixItems = () => {
    const allFixable = getFixableItems();
    const allCodes = allFixable.map(i => i.item_code);
    const allSelected = allCodes.length > 0 && allCodes.every(c => selectedFixItems.has(c));
    if (allSelected) {
      setSelectedFixItems(new Set());
    } else {
      setSelectedFixItems(new Set(allCodes));
    }
  };

  // 카테고리별 전체 선택/해제
  const toggleCategoryFixItems = (catItems: { item_code: string; auto_fix: boolean; status: string }[]) => {
    const fixable = catItems.filter(i => i.auto_fix && i.status === '취약');
    const codes = fixable.map(i => i.item_code);
    const allSelected = codes.length > 0 && codes.every(c => selectedFixItems.has(c));
    setSelectedFixItems(prev => {
      const next = new Set(prev);
      if (allSelected) {
        codes.forEach(c => next.delete(c));
      } else {
        codes.forEach(c => next.add(c));
      }
      return next;
    });
  };

  // 자동조치 버튼 클릭
  const handleAutoFix = () => {
    if (!serverResults) return;

    // 선택된 항목이 있으면 그것만, 없으면 전체 자동조치 가능 항목
    const allFixable = getFixableItems();
    const itemsToFix = selectedFixItems.size > 0
      ? allFixable.filter(i => selectedFixItems.has(i.item_code))
      : allFixable;

    if (itemsToFix.length === 0) {
      alert('자동조치 가능한 취약 항목이 없습니다');
      return;
    }

    setShowRemediation(true);
  };

  const handleRemediationComplete = () => {
    setSelectedFixItems(new Set());
    if (selectedServerId) {
      loadServerResults(selectedServerId);
      loadRemediationHistory(selectedServerId);
    }
    loadServers();
    setSubTab('remediation');
  };

  const handleRegisterException = (itemCode: string, itemTitle: string) => {
    if (!selectedServerId) return;
    setExceptionPrefill({ serverId: selectedServerId, itemCode, itemTitle });
    setShowExceptionModal(true);
  };

  const handleExceptionSuccess = () => {
    setShowExceptionModal(false);
    setExceptionPrefill(null);
    if (selectedServerId) {
      loadServerResults(selectedServerId);
    }
    loadServers();
  };

  // 검색 + 정렬
  const filteredServers = servers
    .filter(s =>
      s.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.ip_address.includes(searchQuery)
    )
    .sort((a, b) => {
      if (sortBy === 'name') return a.hostname.localeCompare(b.hostname);
      return b.vulnerable_count - a.vulnerable_count;
    });

  const categoryLabels = activeTab === 'linux'
    ? OS_CATEGORY_LABELS
    : DB_CATEGORY_LABELS;

  const categoryOrder = activeTab === 'linux'
    ? ['account', 'directory', 'service', 'patch', 'log']
    : ['account', 'access', 'option', 'patch'];

  const currentScanCategories = activeTab === 'linux'
    ? serverResults?.os_results
    : serverResults?.db_results;

  const currentRemediationCategories = activeTab === 'linux'
    ? remediationResults?.os_results
    : remediationResults?.db_results;

  // 자동조치 가능 취약 항목 수집
  const getFixableItems = (): FixableItemWithCategory[] => {
    if (!serverResults) return [];
    const fixableItems: FixableItemWithCategory[] = [];

    const collectFixable = (results: { [key: string]: CategoryResult }, catKeys: string[]) => {
      for (const catKey of catKeys) {
        const catData = results[catKey];
        if (!catData) continue;
        for (const item of catData.items) {
          if (item.auto_fix && item.status === '취약') {
            fixableItems.push({ ...item, category: catKey });
          }
        }
      }
    };

    collectFixable(serverResults.os_results, ['account', 'directory', 'service', 'patch', 'log']);
    collectFixable(serverResults.db_results, ['account', 'access', 'option', 'patch']);

    return fixableItems;
  };


  if (loading) {
    return (
      <>
        <TopNav currentUser={user} onLogout={handleLogout} />
        <div className="analysis-page">
          <div className="analysis-loading">데이터를 불러오는 중...</div>
        </div>
      </>
    );
  }

  return (
    <>
      <TopNav currentUser={user} onLogout={handleLogout} />
      <div className="analysis-page">
        {/* 좌측 사이드바 */}
        <aside className="server-sidebar">
          <div className="sidebar-header">
            <div className="search-box">
              <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
              <input
                type="text"
                placeholder="검색..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="search-input"
              />
            </div>
            <div className="sort-buttons">
              <button
                className={`sort-btn ${sortBy === 'name' ? 'active' : ''}`}
                onClick={() => setSortBy('name')}
              >
                이름순
              </button>
              <button
                className={`sort-btn ${sortBy === 'vuln' ? 'active' : ''}`}
                onClick={() => setSortBy('vuln')}
              >
                취약순
              </button>
            </div>
          </div>
          <div className="server-list">
            {filteredServers.map(server => (
              <div
                key={server.server_id}
                className={`server-item ${selectedServerId === server.server_id ? 'selected' : ''}`}
                onClick={() => handleServerSelect(server.server_id)}
              >
                <div className="server-item-main">
                  <div className="server-item-info">
                    <span className="server-hostname">{server.server_id}</span>
                    <span className="server-ip">{server.ip_address}</span>
                    <div className="server-counts">
                      <span className="count-secure">양호 {server.secure_count}</span>
                      <span className="count-divider">/</span>
                      <span className="count-vuln">취약 {server.vulnerable_count}</span>
                      {server.exception_count > 0 && (
                        <>
                          <span className="count-divider">/</span>
                          <span className="count-exception">예외 {server.exception_count}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <span className={`status-dot ${server.is_active ? 'active' : 'inactive'}`} />
                </div>
              </div>
            ))}
          </div>
        </aside>

        {/* 우측 컨텐츠 */}
        <main className="analysis-content">
          {!selectedServerId ? (
            <div className="no-selection">
              <div className="no-selection-icon">&#128202;</div>
              <p>좌측 목록에서 서버를 선택해주세요</p>
            </div>
          ) : resultsLoading ? (
            <div className="analysis-loading">점검 결과를 불러오는 중...</div>
          ) : serverResults ? (
            <>
              {/* 서버 헤더 */}
              <div className="server-header">
                <div className="server-header-left">
                  <div className="server-header-icon">&#128421;&#65039;</div>
                  <div>
                    <h2 className="server-header-name">
                      {serverResults.server_info.server_id} &bull; {serverResults.server_info.ip_address}
                    </h2>
                    <p className="server-header-meta">
                      {serverResults.server_info.os_type}
                      {serverResults.server_info.db_type && ` \u2022 ${serverResults.server_info.db_type}`}
                    </p>
                  </div>
                </div>
                {user.role === 'ADMIN' && (
                  <button className="auto-fix-btn" onClick={handleAutoFix}>
                    &#128295; 자동조치
                  </button>
                )}
              </div>

              {/* 메인 탭 */}
              <div className="tab-container">
                <button
                  className={`tab-btn ${activeTab === 'linux' ? 'active' : ''}`}
                  onClick={() => { setActiveTab('linux'); setExpandedCategories(new Set()); }}
                >
                  <img src="/linux.png" alt="Linux" className="tab-icon-img" /> LINUX
                </button>
                <button
                  className={`tab-btn ${activeTab === 'database' ? 'active' : ''}`}
                  onClick={() => { setActiveTab('database'); setSubTab('scan'); setExpandedCategories(new Set()); }}
                >
                  <img src="/database.png" alt="Database" className="tab-icon-img" /> DATABASE
                </button>
              </div>

              {/* 서브탭 (LINUX만) */}
              {activeTab === 'linux' && (
                <div className="sub-tab-container">
                  <button
                    className={`sub-tab-btn ${subTab === 'scan' ? 'active' : ''}`}
                    onClick={() => handleSubTabChange('scan')}
                  >
                    점검 결과
                  </button>
                  <button
                    className={`sub-tab-btn ${subTab === 'remediation' ? 'active' : ''}`}
                    onClick={() => handleSubTabChange('remediation')}
                  >
                    조치 결과
                  </button>
                </div>
              )}

              {/* 기준 표시 */}
              {activeTab === 'linux' && serverResults.server_info.os_type && (
                <div className="standard-label">
                  {serverResults.server_info.os_type} 기준
                </div>
              )}
              {activeTab === 'database' && serverResults.server_info.db_type && (
                <div className="standard-label">
                  {serverResults.server_info.db_type} 기준
                </div>
              )}

              {/* 점검 결과 */}
              {(subTab === 'scan' || activeTab === 'database') && (
                <div className="categories-container">
                  {categoryOrder.map(catKey => {
                    const catData = currentScanCategories?.[catKey];
                    const catLabel = categoryLabels[catKey];
                    if (!catData || !catLabel) return null;
                    const isExpanded = expandedCategories.has(catKey);

                    return (
                      <div key={catKey} className="category-section">
                        <div
                          className="category-header"
                          onClick={() => toggleCategory(catKey)}
                        >
                          <div className="category-header-left">
                            <img src={catLabel.icon} alt={catLabel.label} className="category-icon-img" />
                            <span className="category-name">{catLabel.label}</span>
                          </div>
                          <div className="category-header-right">
                            <span className="cat-count-secure">양호 {catData.secure_count}</span>
                            <span className="cat-count-vuln">취약 {catData.vulnerable_count}</span>
                            {catData.exception_count > 0 && (
                              <span className="cat-count-exception">예외 {catData.exception_count}</span>
                            )}
                            <span className={`expand-arrow ${isExpanded ? 'expanded' : ''}`}>
                              &#8250;
                            </span>
                          </div>
                        </div>

                        {isExpanded && (
                          <div className="category-body">
                            <table className="results-table">
                              <thead>
                                <tr>
                                  {user.role === 'ADMIN' && (
                                    <th className="col-check">
                                      <input
                                        type="checkbox"
                                        className="fix-checkbox"
                                        checked={(() => {
                                          const fixable = catData.items.filter(i => i.auto_fix && i.status === '취약');
                                          return fixable.length > 0 && fixable.every(i => selectedFixItems.has(i.item_code));
                                        })()}
                                        onChange={() => toggleCategoryFixItems(catData.items)}
                                        disabled={!catData.items.some(i => i.auto_fix && i.status === '취약')}
                                      />
                                    </th>
                                  )}
                                  <th className="col-date">점검 일시</th>
                                  <th className="col-code">번호</th>
                                  <th className="col-title">점검 항목</th>
                                  <th className="col-status">결과</th>
                                  <th className="col-action">조치유형</th>
                                  <th className="col-evidence">점검 상세 결과</th>
                                  <th className="col-manage">관리</th>
                                </tr>
                              </thead>
                              <tbody>
                                {catData.items.map(item => {
                                  const isFixable = item.auto_fix && item.status === '취약';
                                  return (
                                  <tr key={item.item_code} className={selectedFixItems.has(item.item_code) ? 'row-selected' : ''}>
                                    {user.role === 'ADMIN' && (
                                      <td className="col-check">
                                        {isFixable ? (
                                          <input
                                            type="checkbox"
                                            className="fix-checkbox"
                                            checked={selectedFixItems.has(item.item_code)}
                                            onChange={() => toggleFixItem(item.item_code)}
                                          />
                                        ) : null}
                                      </td>
                                    )}
                                    <td className="col-date">{item.scan_date || '-'}</td>
                                    <td className="col-code">{item.item_code}</td>
                                    <td className="col-title">{item.title}</td>
                                    <td className="col-status">
                                      <span className={`status-badge ${
                                        item.status === '양호' ? 'secure'
                                          : item.status === '예외' ? 'exception'
                                          : 'vulnerable'
                                      }`}>
                                        {item.status}
                                      </span>
                                    </td>
                                    <td className="col-action">
                                      <span className={`action-type ${item.auto_fix ? 'auto' : 'manual'}`}>
                                        {item.auto_fix ? '\u25B6 자동' : '\u2299 수동'}
                                      </span>
                                    </td>
                                    <EvidenceCell
                                      raw={item.raw_evidence}
                                      mode="scan"
                                      guide={item.status !== '양호' ? item.guide : undefined}
                                      autoFix={item.auto_fix}
                                    />
                                    <td className="col-manage">
                                      {item.status === '취약' && user.role === 'ADMIN' && (
                                        <button
                                          className="exception-manage-btn"
                                          onClick={(e) => { e.stopPropagation(); handleRegisterException(item.item_code, item.title); }}
                                        >
                                          예외 등록
                                        </button>
                                      )}
                                    </td>
                                  </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* 조치 결과 (LINUX만) */}
              {subTab === 'remediation' && activeTab === 'linux' && (
                <div className="categories-container">
                  {categoryOrder.map(catKey => {
                    const catData = currentRemediationCategories?.[catKey] as RemediationCategoryResult | undefined;
                    const catLabel = categoryLabels[catKey];
                    if (!catData || !catLabel) return null;
                    if (catData.items.length === 0) return null;
                    const isExpanded = expandedCategories.has(catKey);

                    return (
                      <div key={catKey} className="category-section">
                        <div
                          className="category-header"
                          onClick={() => toggleCategory(catKey)}
                        >
                          <div className="category-header-left">
                            <img src={catLabel.icon} alt={catLabel.label} className="category-icon-img" />
                            <span className="category-name">{catLabel.label}</span>
                          </div>
                          <div className="category-header-right">
                            <span className="cat-count-secure">성공 {catData.success_count}</span>
                            <span className="cat-count-vuln">실패 {catData.fail_count}</span>
                            <span className={`expand-arrow ${isExpanded ? 'expanded' : ''}`}>
                              &#8250;
                            </span>
                          </div>
                        </div>

                        {isExpanded && (
                          <div className="category-body">
                            <table className="results-table">
                              <thead>
                                <tr>
                                  <th className="col-date">조치 일시</th>
                                  <th className="col-code">번호</th>
                                  <th className="col-title">점검 항목</th>
                                  <th className="col-status">결과</th>
                                  <th className="col-evidence">실패 사유 / 조치 근거</th>
                                </tr>
                              </thead>
                              <tbody>
                                {catData.items.map(item => (
                                  <tr key={item.item_code}>
                                    <td className="col-date">{item.action_date || '-'}</td>
                                    <td className="col-code">{item.item_code}</td>
                                    <td className="col-title">{item.title}</td>
                                    <td className="col-status">
                                      <span className={`status-badge ${item.is_success ? 'secure' : 'vulnerable'}`}>
                                        {item.is_success ? '성공' : '실패'}
                                      </span>
                                    </td>
                                    <EvidenceCell
                                      raw={item.raw_evidence}
                                      overrideText={!item.is_success && item.failure_reason ? item.failure_reason : undefined}
                                      mode="remediation"
                                    />
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    );
                  })}

                  {(!currentRemediationCategories ||
                    categoryOrder.every(k => {
                      const cat = currentRemediationCategories?.[k] as RemediationCategoryResult | undefined;
                      return !cat || cat.items.length === 0;
                    })) && (
                    <div className="empty-remediation">
                      <p>조치 결과가 없습니다</p>
                    </div>
                  )}
                </div>
              )}
            </>
          ) : null}
        </main>

        {/* 선택 항목 플로팅 액션바 */}
        {selectedFixItems.size > 0 && user.role === 'ADMIN' && (
          <div className="fix-action-bar">
            <div className="fix-action-bar-left">
              <input
                type="checkbox"
                className="fix-checkbox"
                checked={(() => {
                  const all = getFixableItems();
                  return all.length > 0 && all.every(i => selectedFixItems.has(i.item_code));
                })()}
                onChange={toggleAllFixItems}
              />
              <span className="fix-action-count">
                <strong>{selectedFixItems.size}</strong>개 항목 선택됨
              </span>
            </div>
            <div className="fix-action-bar-right">
              <button className="fix-action-clear" onClick={() => setSelectedFixItems(new Set())}>
                선택 해제
              </button>
              <button className="fix-action-execute" onClick={handleAutoFix}>
                &#128295; 선택 항목 조치 ({selectedFixItems.size}건)
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 자동조치 모달 */}
      {showRemediation && selectedServerId && (
        <RemediationModal
          serverId={selectedServerId}
          servers={servers}
          items={selectedFixItems.size > 0
            ? getFixableItems().filter(i => selectedFixItems.has(i.item_code))
            : getFixableItems()}
          onClose={() => setShowRemediation(false)}
          onComplete={handleRemediationComplete}
        />
      )}

      {/* 예외 등록 모달 */}
      {showExceptionModal && exceptionPrefill && (
        <ExceptionModal
          onClose={() => { setShowExceptionModal(false); setExceptionPrefill(null); }}
          onSuccess={handleExceptionSuccess}
          prefillServerId={exceptionPrefill.serverId}
          prefillItemCode={exceptionPrefill.itemCode}
          prefillItemTitle={exceptionPrefill.itemTitle}
        />
      )}
    </>
  );
}
