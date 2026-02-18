/**
 * 전수 점검 진행 모달 (토스 스타일 4단계 페이지)
 */

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScanProgress, getScanResult } from '../api/scan';
import type { ScanProgress, ScanResult } from '../api/scan';
import './ScanProgressModal.css';

interface Props {
  jobId: string;
  totalServers: number;
  onComplete: (result: ScanResult) => void;
  onClose: () => void;
}

export function ScanProgressModal({ jobId, totalServers, onComplete, onClose }: Props) {
  const navigate = useNavigate();
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [currentPage, setCurrentPage] = useState<1 | 2 | 3 | 4>(1); // 4단계 페이지
  const [isCompleted, setIsCompleted] = useState(false);

  // 점검 진행 상황 폴링
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const progressData = await getScanProgress(jobId);
        setProgress(progressData);

        // 점검 완료 시
        if (progressData.status === 'completed' && !isCompleted) {
          clearInterval(interval);
          setIsCompleted(true);

          // 결과 조회
          setTimeout(async () => {
            try {
              const resultData = await getScanResult(jobId);
              setResult(resultData);
              setCurrentPage(2); // 첫 번째 결과 페이지로 이동
            } catch (error) {
              console.error('Failed to fetch scan result:', error);
            }
          }, 1000);
        }

        // 점검 실패 시
        if (progressData.status === 'failed') {
          clearInterval(interval);
          alert('점검 중 오류가 발생했습니다. 다시 시도해주세요.');
          onClose();
        }

      } catch (error) {
        console.error('Failed to fetch scan progress:', error);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [jobId, isCompleted, onClose]);

  // 다음 단계로
  const handleNext = () => {
    if (currentPage < 4) {
      setCurrentPage((currentPage + 1) as 1 | 2 | 3 | 4);
    } else {
      // 마지막 단계에서 "결과 보기" 클릭 → 메인 화면으로 이동
      if (result) {
        onComplete(result);
      }
      onClose();
      navigate('/');
    }
  };

  // 점검 진행 중 (Page 1)
  if (!isCompleted || currentPage === 1) {
    return (
      <div className="scan-modal-overlay">
        <div className="scan-modal">
          <div className="scan-animation">
            <div className="scan-spinner" />
            <img src="/search.png" alt="검색 중" className="scan-icon" />
          </div>

          <div className="progress-bar-container">
            <div
              className="progress-bar-fill"
              style={{ width: `${progress?.progress || 0}%` }}
            />
          </div>
          <div className="progress-text">{progress?.progress || 0}%</div>

          <h2 className="scan-headline">
            {getProgressHeadline(progress, totalServers)}
          </h2>
          <p className="scan-body">
            {getProgressBody(progress)}
          </p>

          <div className="step-indicator">
            {[1, 2, 3, 4].map(step => (
              <div
                key={step}
                className={`step-dot ${step <= (progress?.current_step || 1) ? 'active' : ''}`}
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  // 점검 완료 후 4단계 결과 페이지
  if (!result) return null;

  // Page 2: 점검 완료 알림
  if (currentPage === 2) {
    return (
      <div className="scan-modal-overlay">
        <div className="scan-modal result-page">
          <div className="scan-result-icon">🎯</div>

          <h2 className="scan-headline">
            {result.company}님,<br />
            {result.total_servers}개의 노드를<br />
            꼼꼼하게 살펴봤어요
          </h2>

          <p className="scan-body">
            {result.scan_duration} 동안<br />
            정밀 점검을 마쳤습니다.
          </p>

          <div className="scan-stats">
            <div className="stat-item">
              <span className="stat-label">점검 완료</span>
              <span className="stat-value primary">{result.total_servers}대</span>
            </div>
          </div>

          <button className="btn-next" onClick={handleNext}>
            다음
          </button>

          <div className="page-indicator">
            <div className="page-dot active" />
            <div className="page-dot" />
            <div className="page-dot" />
          </div>
        </div>
      </div>
    );
  }

  // Page 3: 가장 주의가 필요한 서버
  if (currentPage === 3) {
    return (
      <div className="scan-modal-overlay">
        <div className="scan-modal result-page">
          <div className="scan-result-icon">⚠️</div>

          <h2 className="scan-headline">
            가장 주의가 필요한<br />
            서버를 찾았어요
          </h2>

          <p className="scan-body">
            <strong>{result.top_vulnerable_server?.server_id || '없음'}</strong> 서버에서<br />
            <span className="highlight-red">{result.top_vulnerable_server?.count || 0}건</span>의 보안 취약점이<br />
            발견됐네요.
          </p>

          <div className="scan-stats">
            <div className="stat-item">
              <span className="stat-label">서버 전체 취약한 항목</span>
              <span className="stat-value danger">{result.vulnerable_count}건</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">서버 전체 양호한 항목</span>
              <span className="stat-value safe">{result.secure_count}건</span>
            </div>
          </div>

          <button className="btn-next" onClick={handleNext}>
            다음
          </button>

          <div className="page-indicator">
            <div className="page-dot active" />
            <div className="page-dot active" />
            <div className="page-dot" />
          </div>
        </div>
      </div>
    );
  }

  // Page 4: 위험도 분석 + 최종 결과
  if (currentPage === 4) {
    return (
      <div className="scan-modal-overlay">
        <div className="scan-modal result-page">
          <img src="/statistics.png" alt="통계" className="scan-result-icon" />

          <h2 className="scan-headline">
            {result.risk_distribution.high >= 50
              ? <>고위험 리스크가<br /><span className="highlight-red">{result.risk_distribution.high}%</span>로 높아요</>
              : result.risk_distribution.high >= 30
                ? <>고위험 리스크가<br />{result.risk_distribution.high}% 수준이에요</>
                : <>다행히 고위험 리스크는<br />{result.risk_distribution.high}% 수준이에요</>
            }
          </h2>

          <p className="scan-body">
            {result.risk_distribution.high >= 50
              ? <>전체의 <span className="highlight-red">{result.risk_percentage}%</span>가<br />취약 상태입니다. 즉시 조치가 필요해요.</>
              : result.risk_percentage > 0
                ? <>하지만 전체의 <span className="highlight-orange">{result.risk_percentage}%</span>가<br />취약 상태라 관리가 필요해 보여요.</>
                : <>모든 항목이 양호 상태입니다!</>
            }
          </p>

          <div className="risk-distribution">
            <div className="risk-item">
              <span className="risk-label">저위험</span>
              <div className="risk-bar-container">
                <div className="risk-bar low" style={{ width: `${result.risk_distribution.low}%` }} />
              </div>
              <span className="risk-value">{result.risk_distribution.low}%</span>
            </div>
            <div className="risk-item">
              <span className="risk-label">중위험</span>
              <div className="risk-bar-container">
                <div className="risk-bar medium" style={{ width: `${result.risk_distribution.medium}%` }} />
              </div>
              <span className="risk-value">{result.risk_distribution.medium}%</span>
            </div>
            <div className="risk-item">
              <span className="risk-label">고위험</span>
              <div className="risk-bar-container">
                <div className="risk-bar high" style={{ width: `${result.risk_distribution.high}%` }} />
              </div>
              <span className="risk-value">{result.risk_distribution.high}%</span>
            </div>
          </div>

          <p className="scan-body" style={{ marginTop: '24px' }}>
            방금 분석한 상세 리포트를<br />
            자산 분석 페이지에 정리해 두었습니다.<br />
            지금 바로 확인해 보시겠어요?
          </p>

          <button className="btn-view-result" onClick={handleNext}>
            결과 보러갈까요?
          </button>

          <div className="page-indicator">
            <div className="page-dot active" />
            <div className="page-dot active" />
            <div className="page-dot active" />
          </div>
        </div>
      </div>
    );
  }

  return null;
}

/**
 * 진행 중 헤드라인 (진행률 퍼센트 기반)
 */
function getProgressHeadline(progress: ScanProgress | null, totalServers: number): string {
  if (!progress) return `지금부터 ${totalServers}개 서버를\n하나하나 점검해 볼게요 👀`;

  const percentage = progress.progress || 0;

  if (percentage < 50) {
    return `지금부터 ${totalServers}개 서버를\n하나하나 점검해 볼게요 👀`;
  } else if (percentage < 80) {
    return `벌써 절반을 확인했어요!\n점검이 순조롭게 진행 중이에요 ✨`;
  } else if (percentage < 100) {
    return `거의 다 왔어요!\n마지막 서버들을 점검하고 있어요 🚀`;
  } else {
    return '점검이 완료됐어요! 🎉';
  }
}

/**
 * 진행 중 본문
 */
function getProgressBody(progress: ScanProgress | null): string {
  if (!progress) {
    return 'OS 설정부터 DB 보안까지\n꼼꼼하게 확인하는 중이에요.\n조금만 기다려 주세요!';
  }

  return progress.message || '점검을 진행하고 있습니다...';
}
