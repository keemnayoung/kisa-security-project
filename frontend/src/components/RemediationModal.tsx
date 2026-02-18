/**
 * 자동조치 모달 (3단계 Phase)
 * Phase 1: confirm (확인) → Phase 2: progress (진행) → Phase 3: result (결과)
 *
 * 서버 선택 모드: 검색 + 전체 선택 지원
 */

import { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  startFix, startBatchFix,
  getFixProgress, getFixResult, getAffectedServers
} from '../api/fix';
import type { FixResult, AffectedServerInfo } from '../api/fix';
import type { CheckItem, AnalysisServer } from '../api/analysis';
import './RemediationModal.css';

// 카테고리 라벨
const CATEGORY_MAP: { [key: string]: string } = {
  account: '계정 관리',
  directory: '파일 및 디렉토리 관리',
  service: '서비스 관리',
  patch: '패치 관리',
  log: '로그 관리',
  access: '접근 관리',
  option: '옵션 관리',
};

// raw_evidence에서 reason_line(첫 줄)만 추출
function extractReasonLine(raw: string): string {
  if (!raw) return '';
  let detailFull = '';
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed === 'object' && parsed !== null) {
      detailFull = parsed.detail || '';
    } else if (typeof parsed === 'string') {
      try {
        const inner = JSON.parse(parsed);
        if (typeof inner === 'object' && inner !== null) detailFull = inner.detail || '';
      } catch {}
    }
    detailFull = detailFull.replace(/\\\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\\\t/g, '\t').replace(/\\t/g, '\t');
  } catch {
    const escapedMatch = raw.match(/\\"detail\\"\s*:\s*\\"([\s\S]*?)\\"/);
    if (escapedMatch) {
      detailFull = escapedMatch[1].replace(/\\\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\\\t/g, '\t').replace(/\\t/g, '\t');
    }
    if (!detailFull) {
      const normalMatch = raw.match(/"detail"\s*:\s*"((?:[^"\\]|\\.)*)"/);
      if (normalMatch) detailFull = normalMatch[1].replace(/\\\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\\\t/g, '\t').replace(/\\t/g, '\t').replace(/\\"/g, '"');
    }
  }
  const nlIdx = detailFull.indexOf('\n');
  return nlIdx > 0 ? detailFull.slice(0, nlIdx) : detailFull;
}

export interface FixableItemWithCategory extends CheckItem {
  category: string;
}

interface RemediationModalProps {
  serverId: string;
  servers: AnalysisServer[];
  items: FixableItemWithCategory[];
  onClose: () => void;
  onComplete: () => void;
}

export function RemediationModal({ serverId, servers, items, onClose, onComplete }: RemediationModalProps) {
  const navigate = useNavigate();
  const [phase, setPhase] = useState<'confirm' | 'progress' | 'result'>('confirm');
  const [excludedItems, setExcludedItems] = useState<Set<string>>(new Set());
  const [jobId, setJobId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [progressMessage, setProgressMessage] = useState('');
  const [fixResult, setFixResult] = useState<FixResult | null>(null);

  // 서버 선택 관련
  const [affectedServers, setAffectedServers] = useState<AffectedServerInfo[] | null>(null);
  const [loadingAffected, setLoadingAffected] = useState(false);
  const [selectedServerIds, setSelectedServerIds] = useState<Set<string>>(new Set([serverId]));
  const [serverSearch, setServerSearch] = useState('');

  // 서버별 확장/축소
  const [expandedServers, setExpandedServers] = useState<Set<string>>(new Set([serverId]));
  const [expandedResultServers, setExpandedResultServers] = useState<Set<string>>(new Set());

  const activeItems = items.filter(item => !excludedItems.has(item.item_code));

  // 모달 열리면 자동으로 영향 서버 로드
  const loadAffectedServers = useCallback(async () => {
    if (activeItems.length === 0) return;
    setLoadingAffected(true);
    try {
      const itemCodes = activeItems.map(i => i.item_code);
      const result = await getAffectedServers(itemCodes);
      setAffectedServers(result.servers);
      // 현재 서버가 목록에 있으면 선택 상태 유지
      const currentInList = result.servers.some(s => s.server_id === serverId);
      if (currentInList) {
        setSelectedServerIds(new Set([serverId]));
      }
    } catch (err) {
      console.error('Failed to load affected servers:', err);
      setAffectedServers([]);
    } finally {
      setLoadingAffected(false);
    }
  }, [activeItems.map(i => i.item_code).join(',')]);

  // 모달 진입 시 자동 로드
  useEffect(() => {
    if (servers.length > 1) {
      loadAffectedServers();
    }
  }, []);

  // 서버 검색 필터링
  const filteredServers = useMemo(() => {
    if (!affectedServers) return [];
    if (!serverSearch.trim()) return affectedServers;
    const q = serverSearch.toLowerCase().trim();
    return affectedServers.filter(s =>
      s.server_id.toLowerCase().includes(q) ||
      s.hostname.toLowerCase().includes(q) ||
      s.ip_address.includes(q) ||
      s.os_type.toLowerCase().includes(q)
    );
  }, [affectedServers, serverSearch]);

  // 전체 선택 / 해제
  const isAllSelected = filteredServers.length > 0 && filteredServers.every(s => selectedServerIds.has(s.server_id));

  const handleSelectAll = () => {
    setSelectedServerIds(prev => {
      const next = new Set(prev);
      if (isAllSelected) {
        // 현재 필터된 서버 전부 해제
        filteredServers.forEach(s => next.delete(s.server_id));
      } else {
        // 현재 필터된 서버 전부 선택
        filteredServers.forEach(s => next.add(s.server_id));
      }
      return next;
    });
  };

  const toggleServerSelection = (sid: string) => {
    setSelectedServerIds(prev => {
      const next = new Set(prev);
      if (next.has(sid)) next.delete(sid); else next.add(sid);
      return next;
    });
  };

  const handleExclude = (itemCode: string) => {
    setExcludedItems(prev => new Set(prev).add(itemCode));
  };

  const toggleServerExpand = (sid: string) => {
    setExpandedServers(prev => {
      const next = new Set(prev);
      if (next.has(sid)) next.delete(sid); else next.add(sid);
      return next;
    });
  };

  const toggleResultServerExpand = (sid: string) => {
    setExpandedResultServers(prev => {
      const next = new Set(prev);
      if (next.has(sid)) next.delete(sid); else next.add(sid);
      return next;
    });
  };

  // 조치 실행
  const handleExecute = async () => {
    const selectedCodes = activeItems.map(i => i.item_code);
    if (selectedCodes.length === 0) {
      alert('조치할 항목이 없습니다');
      return;
    }

    const serverIds = Array.from(selectedServerIds);
    if (serverIds.length === 0) {
      alert('조치할 서버를 선택해주세요');
      return;
    }

    try {
      let response;
      if (serverIds.length === 1) {
        response = await startFix(serverIds[0], selectedCodes);
      } else {
        response = await startBatchFix(serverIds, selectedCodes);
      }
      setJobId(response.job_id);
      setPhase('progress');
    } catch (error: any) {
      console.error('Failed to start fix:', error);
      const detail = error?.response?.data?.detail || '조치 실행에 실패했습니다';
      alert(detail);
    }
  };

  // 진행 상황 폴링
  useEffect(() => {
    if (phase !== 'progress' || !jobId) return;

    const interval = setInterval(async () => {
      try {
        const progressData = await getFixProgress(jobId);
        setProgress(progressData.progress);
        setProgressMessage(progressData.message);

        if (progressData.status === 'completed') {
          clearInterval(interval);
          setTimeout(async () => {
            try {
              const result = await getFixResult(jobId);
              setFixResult(result);
              if (result.servers && result.servers.length > 0) {
                setExpandedResultServers(new Set([result.servers[0].server_id]));
              }
              setPhase('result');
            } catch (error) {
              console.error('Failed to fetch fix result:', error);
              setPhase('result');
            }
          }, 1000);
        }

        if (progressData.status === 'failed') {
          clearInterval(interval);
          alert('조치 중 오류가 발생했습니다');
          onClose();
        }
      } catch (error) {
        console.error('Failed to fetch fix progress:', error);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [phase, jobId, onClose]);

  // 멀티 서버 여부
  const isMultiServer = servers.length > 1;

  // 조치 대상 서버/항목 수 계산
  const getTargetSummary = () => {
    if (!isMultiServer) {
      return { serverCount: 1, itemCount: activeItems.length, totalCount: activeItems.length };
    }
    if (!affectedServers) return { serverCount: 0, itemCount: activeItems.length, totalCount: 0 };
    const selected = affectedServers.filter(s => selectedServerIds.has(s.server_id));
    const totalCount = selected.reduce((sum, s) => sum + s.vulnerable_count, 0);
    return { serverCount: selected.length, itemCount: activeItems.length, totalCount };
  };

  // Phase 1: 확인
  if (phase === 'confirm') {
    const summary = getTargetSummary();

    return (
      <div className="remediation-overlay">
        <div className="remediation-modal confirm-phase">
          {/* 헤더 */}
          <div className="remediation-header">
            <div className="remediation-header-left">
              <h2 className="remediation-title">보안 조치 설정 확인</h2>
              <span className="remediation-count-badge">
                선택된 항목 <strong>{activeItems.length}건</strong>
              </span>
            </div>
            <button className="remediation-close" onClick={onClose}>&times;</button>
          </div>
          <p className="remediation-subtitle">Security Remediation Confirmation</p>

          {/* 경고문 (간결화) */}
          <div className="remediation-warning">
            <div className="warning-icon">&#9888;</div>
            <div className="warning-content">
              <h4 className="warning-title">주의사항</h4>
              <ul className="warning-list">
                <li>선택된 항목에 대한 보안 변경이 즉시 서버에 적용됩니다.</li>
                <li>관련 서비스(SSH, DB, Web 등)의 재시작이 발생할 수 있습니다.</li>
                <li>롤백이 불가한 항목이 포함될 수 있습니다. 사전 백업을 권장합니다.</li>
              </ul>
            </div>
          </div>

          {/* 서버 선택 (멀티 서버일 때) */}
          {isMultiServer && (
            <div className="server-selector-section">
              <h3 className="section-title">
                조치 대상 서버 선택
                {affectedServers && (
                  <span className="section-title-sub"> ({selectedServerIds.size}/{affectedServers.length}대 선택)</span>
                )}
              </h3>

              {/* 검색 + 전체선택 바 */}
              <div className="server-toolbar">
                <div className="server-search-wrap">
                  <span className="server-search-icon">&#128269;</span>
                  <input
                    type="text"
                    className="server-search-input"
                    placeholder="서버 검색 (이름, IP, OS)"
                    value={serverSearch}
                    onChange={e => setServerSearch(e.target.value)}
                  />
                  {serverSearch && (
                    <button className="server-search-clear" onClick={() => setServerSearch('')}>&times;</button>
                  )}
                </div>
                <label className="server-select-all">
                  <input
                    type="checkbox"
                    checked={isAllSelected}
                    onChange={handleSelectAll}
                    disabled={filteredServers.length === 0}
                  />
                  <span>전체 선택</span>
                </label>
              </div>

              {/* 서버 목록 */}
              <div className="server-select-panel">
                {loadingAffected ? (
                  <div className="scope-loading">서버 목록을 불러오는 중...</div>
                ) : filteredServers.length > 0 ? (
                  filteredServers.map(server => (
                    <label key={server.server_id} className={`server-select-item ${selectedServerIds.has(server.server_id) ? 'selected' : ''}`}>
                      <input
                        type="checkbox"
                        checked={selectedServerIds.has(server.server_id)}
                        onChange={() => toggleServerSelection(server.server_id)}
                      />
                      <span className="server-select-name">{server.server_id}</span>
                      <span className="server-select-ip">{server.ip_address}</span>
                      <span className="server-select-os">{server.os_type}</span>
                      <span className="server-select-count">{server.vulnerable_count}건</span>
                    </label>
                  ))
                ) : affectedServers && affectedServers.length > 0 && serverSearch ? (
                  <div className="scope-loading">검색 결과가 없습니다</div>
                ) : (
                  <div className="scope-loading">영향받는 서버가 없습니다</div>
                )}
              </div>
            </div>
          )}

          {/* 조치 대상 상세 내역 */}
          <h3 className="section-title">
            조치 대상 상세 내역
            {isMultiServer && summary.serverCount > 0 && (
              <span className="section-title-sub"> ({summary.serverCount}대 서버)</span>
            )}
          </h3>

          {/* 단일 서버 모드: 기존 카테고리 뷰 */}
          {!isMultiServer && (
            <SingleServerItemList
              items={activeItems}
              onExclude={handleExclude}
            />
          )}

          {/* 멀티 서버 모드: 서버별 아코디언 */}
          {isMultiServer && affectedServers && !loadingAffected && (
            <div className="fix-server-list">
              {affectedServers
                .filter(s => selectedServerIds.has(s.server_id))
                .map(server => (
                  <div key={server.server_id} className="fix-server-section">
                    <div
                      className="fix-server-header"
                      onClick={() => toggleServerExpand(server.server_id)}
                    >
                      <span className={`fix-expand-arrow ${expandedServers.has(server.server_id) ? 'expanded' : ''}`}>&#8250;</span>
                      <span className="fix-server-name">{server.server_id}</span>
                      <span className="fix-server-ip">{server.ip_address} &middot; {server.os_type}</span>
                      <span className="fix-server-count">{server.vulnerable_count}개 항목</span>
                    </div>
                    {expandedServers.has(server.server_id) && (
                      <div className="fix-server-body">
                        {server.vulnerable_items
                          .map(code => activeItems.find(i => i.item_code === code))
                          .filter((item): item is FixableItemWithCategory => item !== undefined)
                          .map(item => (
                            <FixItemCard
                              key={item.item_code}
                              item={item}
                              onExclude={handleExclude}
                              compact={true}
                            />
                          ))
                        }
                      </div>
                    )}
                  </div>
                ))
              }
            </div>
          )}

          {/* 요약 */}
          <div className="fix-summary">
            {isMultiServer ? (
              <span className="fix-summary-text">
                총 <strong>{summary.serverCount}</strong>대 서버 &middot;{' '}
                <strong>{summary.totalCount}</strong>건 조치
              </span>
            ) : (
              <span className="fix-summary-text">
                총 <strong>{activeItems.length}</strong>건 조치
              </span>
            )}
          </div>

          {/* 하단 버튼 */}
          <div className="remediation-actions">
            <button className="btn-cancel" onClick={onClose}>취소</button>
            <button
              className="btn-execute"
              onClick={handleExecute}
              disabled={activeItems.length === 0 || selectedServerIds.size === 0}
            >
              &#9654; 조치 실행{isMultiServer ? ` (${summary.totalCount}건)` : ` (${activeItems.length}건)`}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Phase 2: 진행 중
  if (phase === 'progress') {
    return (
      <div className="remediation-overlay">
        <div className="remediation-modal progress-phase">
          <div className="fix-animation">
            <div className="fix-spinner" />
            <img src="/fix.png" alt="조치 중" className="fix-icon-img" />
          </div>

          <div className="fix-progress-bar-container">
            <div
              className="fix-progress-bar-fill"
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="fix-progress-text">{progress}%</div>

          <h2 className="fix-headline">
            {progress < 50
              ? '보안 조치를 적용하고 있어요'
              : progress < 100
              ? '거의 다 완료됐어요!'
              : '조치가 완료됐어요!'}
          </h2>
          <p className="fix-body">
            {selectedServerIds.size > 1
              ? `${selectedServerIds.size}대 서버에서 조치를 진행하고 있습니다`
              : progressMessage || '잠시만 기다려 주세요'}
          </p>

          <div className="fix-step-indicator">
            {[1, 2, 3, 4].map(step => (
              <div
                key={step}
                className={`fix-step-dot ${step <= Math.ceil(progress / 25) ? 'active' : ''}`}
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Phase 3: 결과 요약
  if (phase === 'result') {
    const result = fixResult;
    const hasMultipleServers = result?.servers && result.servers.length > 1;

    return (
      <div className="remediation-overlay">
        <div className={`remediation-modal ${hasMultipleServers ? 'result-phase-batch' : 'result-phase'}`}>
          <img src="/fix.png" alt="조치 완료" className="fix-result-img" />

          <h2 className="fix-headline">
            보안 조치가 완료되었어요!
          </h2>

          <div className="fix-result-stats">
            {hasMultipleServers && (
              <div className="fix-stat-item">
                <span className="fix-stat-label">전체 서버</span>
                <span className="fix-stat-value info">{result?.servers?.length || 1}대</span>
              </div>
            )}
            <div className="fix-stat-item">
              <span className="fix-stat-label">조치 완료</span>
              <span className="fix-stat-value success">{result?.success_count || 0}건</span>
            </div>
            <div className="fix-stat-item">
              <span className="fix-stat-label">조치 실패</span>
              <span className="fix-stat-value danger">{result?.fail_count || 0}건</span>
            </div>
          </div>

          {/* 항목별 결과 (단일 서버) */}
          {!hasMultipleServers && result?.items && result.items.length > 0 && (
            <div className="fix-result-servers">
              <div className="fix-result-server-items">
                {result.items.map(item => (
                  <div key={item.item_code} className={`fix-result-item ${item.is_success ? 'success' : 'fail'}`}>
                    <div className="fix-result-item-header">
                      <span className="fix-result-item-status" dangerouslySetInnerHTML={{
                        __html: item.is_success ? '&#10003;' : '&#10007;'
                      }} />
                      <span className="fix-result-item-code">{item.item_code}</span>
                      <span className="fix-result-item-title">{item.title}</span>
                    </div>
                    {!item.is_success && item.failure_reason && (
                      <div className="fix-result-item-reason">{item.failure_reason}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 서버별 결과 (멀티 서버) */}
          {hasMultipleServers && result?.servers && (
            <div className="fix-result-servers">
              {result.servers.map(srv => (
                <div key={srv.server_id} className="fix-result-server-row">
                  <div
                    className="fix-result-server-header"
                    onClick={() => toggleResultServerExpand(srv.server_id)}
                  >
                    <span className={`fix-expand-arrow ${expandedResultServers.has(srv.server_id) ? 'expanded' : ''}`}>&#8250;</span>
                    <span className="fix-result-server-name">{srv.server_id}</span>
                    <span className="fix-result-server-hostname">{srv.hostname}</span>
                    <div className="fix-result-server-counts">
                      {srv.success_count > 0 && (
                        <span className="result-count-success">&#10003; {srv.success_count}</span>
                      )}
                      {srv.fail_count > 0 && (
                        <span className="result-count-fail">&#10007; {srv.fail_count}</span>
                      )}
                    </div>
                  </div>
                  {expandedResultServers.has(srv.server_id) && (
                    <div className="fix-result-server-items">
                      {srv.items.map(item => (
                        <div key={item.item_code} className={`fix-result-item ${item.is_success ? 'success' : 'fail'}`}>
                          <div className="fix-result-item-header">
                            <span className="fix-result-item-status" dangerouslySetInnerHTML={{
                              __html: item.is_success ? '&#10003;' : '&#10007;'
                            }} />
                            <span className="fix-result-item-code">{item.item_code}</span>
                            <span className="fix-result-item-title">{item.title}</span>
                          </div>
                          {!item.is_success && item.failure_reason && (
                            <div className="fix-result-item-reason">{item.failure_reason}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          <button
            className="btn-view-result"
            onClick={() => {
              onComplete();
              onClose();
              navigate('/main');
            }}
          >
            결과 보러가기
          </button>
        </div>
      </div>
    );
  }

  return null;
}


/**
 * 단일 서버 항목 목록 (카테고리별 그룹)
 */
function SingleServerItemList({
  items,
  onExclude,
}: {
  items: FixableItemWithCategory[];
  onExclude: (itemCode: string) => void;
}) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

  const groupedItems: { [category: string]: FixableItemWithCategory[] } = {};
  for (const item of items) {
    const cat = item.category;
    if (!groupedItems[cat]) groupedItems[cat] = [];
    groupedItems[cat].push(item);
  }

  const toggleCategory = (cat: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat); else next.add(cat);
      return next;
    });
  };

  return (
    <div className="fix-categories">
      {Object.entries(groupedItems).map(([catKey, catItems]) => {
        const autoCount = catItems.filter(i => i.auto_fix).length;
        const isExpanded = expandedCategories.has(catKey);
        const catLabel = CATEGORY_MAP[catKey] || catKey;

        return (
          <div key={catKey} className="fix-category">
            <div className="fix-category-header" onClick={() => toggleCategory(catKey)}>
              <span className="fix-category-name">{catLabel}</span>
              <span className="fix-category-counts">
                {autoCount}건
              </span>
              <span className={`fix-expand-arrow ${isExpanded ? 'expanded' : ''}`}>&#8250;</span>
            </div>

            {isExpanded && (
              <div className="fix-category-body">
                {catItems.filter(i => i.auto_fix).map(item => (
                  <FixItemCard
                    key={item.item_code}
                    item={item}
                    onExclude={onExclude}
                    compact={false}
                  />
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}


/**
 * 개별 조치 항목 카드
 */
function FixItemCard({
  item,
  onExclude,
  compact = false,
}: {
  item: FixableItemWithCategory;
  onExclude: (itemCode: string) => void;
  compact?: boolean;
}) {
  const detail = extractReasonLine(item.raw_evidence);
  const guide = item.guide;
  const caution = item.auto_fix_description;

  return (
    <div className={`fix-item-card ${compact ? 'compact' : ''}`}>
      <div className="fix-item-header">
        <span className="fix-item-code">{item.item_code}</span>
        <span className="fix-item-title">{item.title}</span>
        <span className="fix-item-severity" data-severity={item.severity}>
          {item.severity}
        </span>
        <button className="fix-item-remove" onClick={() => onExclude(item.item_code)}>
          &times;
        </button>
      </div>

      <div className="fix-item-states">
        <div className="fix-state-box current">
          <div className="fix-state-label">현재 상태:</div>
          <div className="fix-state-content">{detail || '상태 정보 없음'}</div>
        </div>
        <div className="fix-state-arrow">&#8594;</div>
        <div className="fix-state-box after">
          <div className="fix-state-label">조치 후:</div>
          <div className="fix-state-content">
            {guide || '조치 후 상태 정보가 아직 없습니다'}
          </div>
        </div>
      </div>

      {caution && !compact && (
        <div className="fix-item-caution">
          <span className="caution-icon">&#9888;</span>
          <div className="caution-content">
            <div className="caution-title">주의사항</div>
            <div className="caution-text">{caution}</div>
          </div>
        </div>
      )}
    </div>
  );
}
