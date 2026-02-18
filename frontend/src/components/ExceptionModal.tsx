/**
 * 예외 등록 모달 (분석 페이지 / 예외 관리 페이지 공유)
 */

import { useEffect, useMemo, useState } from 'react';
import { getAnalysisServers } from '../api/analysis';
import type { AnalysisServer } from '../api/analysis';
import { createException, createBulkException } from '../api/exceptions';
import './ExceptionModal.css';

interface Props {
  onClose: () => void;
  onSuccess: () => void;
  prefillServerId?: string;
  prefillItemCode?: string;
  prefillItemTitle?: string;
}

export function ExceptionModal({
  onClose, onSuccess,
  prefillServerId, prefillItemCode, prefillItemTitle
}: Props) {
  const [servers, setServers] = useState<AnalysisServer[]>([]);
  const [selectedServerIds, setSelectedServerIds] = useState<Set<string>>(
    () => prefillServerId ? new Set([prefillServerId]) : new Set()
  );
  const [serverSearch, setServerSearch] = useState('');
  const [itemCode, setItemCode] = useState(prefillItemCode || '');
  const [reason, setReason] = useState('');
  const [validDate, setValidDate] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    getAnalysisServers().then(list => {
      setServers(list);
      // prefill이 없으면 전체 선택
      if (!prefillServerId && list.length > 0) {
        setSelectedServerIds(new Set(list.map(s => s.server_id)));
      }
    }).catch(() => {});
  }, []);

  const today = new Date().toISOString().split('T')[0];

  /* 서버 검색 필터 */
  const filteredServers = useMemo(() => {
    if (!serverSearch.trim()) return servers;
    const q = serverSearch.toLowerCase().trim();
    return servers.filter(s =>
      s.server_id.toLowerCase().includes(q) ||
      s.hostname.toLowerCase().includes(q) ||
      s.ip_address.includes(q)
    );
  }, [servers, serverSearch]);

  /* 전체 선택 */
  const isAllSelected = filteredServers.length > 0 &&
    filteredServers.every(s => selectedServerIds.has(s.server_id));

  const handleSelectAll = () => {
    setSelectedServerIds(prev => {
      const next = new Set(prev);
      if (isAllSelected) {
        filteredServers.forEach(s => next.delete(s.server_id));
      } else {
        filteredServers.forEach(s => next.add(s.server_id));
      }
      return next;
    });
  };

  const handleToggleServer = (serverId: string) => {
    setSelectedServerIds(prev => {
      const next = new Set(prev);
      if (next.has(serverId)) {
        next.delete(serverId);
      } else {
        next.add(serverId);
      }
      return next;
    });
  };

  const handleSubmit = async () => {
    if (!itemCode || !reason || !validDate) {
      alert('모든 필드를 입력해주세요');
      return;
    }
    if (selectedServerIds.size === 0) {
      alert('서버를 선택해주세요');
      return;
    }

    const validDateStr = `${validDate} 23:59:59`;
    setSubmitting(true);

    try {
      if (selectedServerIds.size === 1) {
        const serverId = Array.from(selectedServerIds)[0];
        await createException({ server_id: serverId, item_code: itemCode, reason, valid_date: validDateStr });
      } else if (selectedServerIds.size === servers.length) {
        // 전체 서버 → server_ids 없이 호출
        const result = await createBulkException({ item_code: itemCode, reason, valid_date: validDateStr });
        alert(result.message);
      } else {
        // 선택한 서버들
        const result = await createBulkException({
          item_code: itemCode,
          reason,
          valid_date: validDateStr,
          server_ids: Array.from(selectedServerIds),
        });
        alert(result.message);
      }
      onSuccess();
    } catch (error: any) {
      const detail = error.response?.data?.detail || '예외 등록에 실패했습니다';
      alert(detail);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="exception-modal-overlay" onClick={onClose}>
      <div className="exception-modal" onClick={e => e.stopPropagation()}>
        <div className="exception-modal-header">
          <h2 className="exception-modal-title">예외 등록</h2>
          <button className="exception-modal-close" onClick={onClose}>&times;</button>
        </div>

        {/* 서버 선택 섹션 */}
        <div className="exception-modal-field">
          <label>서버 선택 <span className="field-selected-count">{selectedServerIds.size}대 선택</span></label>

          <div className="ex-server-toolbar">
            <div className="ex-server-search-wrap">
              <span className="ex-server-search-icon">&#128269;</span>
              <input
                className="ex-server-search-input"
                type="text"
                placeholder="서버 검색..."
                value={serverSearch}
                onChange={e => setServerSearch(e.target.value)}
              />
              {serverSearch && (
                <button className="ex-server-search-clear" onClick={() => setServerSearch('')}>&times;</button>
              )}
            </div>
            <label className="ex-server-select-all">
              <input
                type="checkbox"
                checked={isAllSelected}
                onChange={handleSelectAll}
              />
              전체
            </label>
          </div>

          <div className="ex-server-panel">
            {filteredServers.length === 0 ? (
              <div className="ex-server-empty">검색 결과 없음</div>
            ) : (
              filteredServers.map(s => (
                <label
                  key={s.server_id}
                  className={`ex-server-item ${selectedServerIds.has(s.server_id) ? 'selected' : ''}`}
                >
                  <input
                    type="checkbox"
                    checked={selectedServerIds.has(s.server_id)}
                    onChange={() => handleToggleServer(s.server_id)}
                  />
                  <span className="ex-server-name">{s.server_id}</span>
                  <span className="ex-server-ip">{s.ip_address}</span>
                </label>
              ))
            )}
          </div>
        </div>

        <div className="exception-modal-field">
          <label>점검 항목 코드</label>
          <input
            type="text"
            value={itemCode}
            onChange={e => setItemCode(e.target.value)}
            placeholder="예: U-01, D-05"
            disabled={!!prefillItemCode}
          />
          {prefillItemTitle && (
            <span className="field-hint">{prefillItemTitle}</span>
          )}
        </div>

        <div className="exception-modal-field">
          <label>예외 사유</label>
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="예외 처리 사유를 입력하세요 (예: 레거시 시스템 연동 문제)"
            maxLength={500}
            rows={3}
          />
          <span className="char-count">{reason.length}/500</span>
        </div>

        <div className="exception-modal-field">
          <label>유효 기한</label>
          <input
            type="date"
            value={validDate}
            onChange={e => setValidDate(e.target.value)}
            min={today}
          />
        </div>

        <div className="exception-modal-actions">
          <button className="btn-cancel" onClick={onClose}>취소</button>
          <button
            className="btn-submit"
            onClick={handleSubmit}
            disabled={submitting || !itemCode || !reason || !validDate || selectedServerIds.size === 0}
          >
            {submitting ? '등록 중...' : `예외 등록 (${selectedServerIds.size}대)`}
          </button>
        </div>
      </div>
    </div>
  );
}
