/**
 * 메인 대시보드 (토스 스타일)
 */

import { useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { getDashboardData, type DashboardData } from '../api/dashboard';
import { downloadReport } from '../api/report';
import { ScanProgressModal } from '../components/ScanProgressModal';
import { TopNav } from '../components/TopNav';
import { getAllServerIds, startFullScan } from '../api/scan';
import type { ScanResult } from '../api/scan';
import './MainDashboard.css';

export function MainDashboard() {
  const navigate = useNavigate();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [scanTotalServers, setScanTotalServers] = useState(0);
  const [reportLoading, setReportLoading] = useState(false);

  let user: any = {};
  try {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      user = JSON.parse(userStr);
    }
  } catch (e) {
    console.error('Failed to parse user:', e);
  }

  // 데이터 로드
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      navigate('/');
      return;
    }

    loadDashboardData();
  }, [navigate]);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const dashboardData = await getDashboardData();
      setData(dashboardData);
    } catch (error: any) {
      console.error('Failed to load dashboard data:', error);
      if (error.response?.status === 401) {
        alert('로그인이 만료되었습니다. 다시 로그인해주세요.');
        navigate('/');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleStartScan = async () => {
    if (user.role !== 'ADMIN') {
      alert('점검 실행은 관리자만 가능합니다');
      return;
    }

    try {
      const serverIds = await getAllServerIds();

      if (serverIds.length === 0) {
        alert('점검할 서버가 없습니다. 먼저 서버를 등록해주세요.');
        navigate('/register');
        return;
      }

      const response = await startFullScan(serverIds);
      setScanJobId(response.job_id);
      setScanTotalServers(response.total_servers);
      setShowScanModal(true);

    } catch (error: any) {
      console.error('Failed to start scan:', error);
      if (error.response?.status === 401) {
        alert('로그인이 만료되었습니다. 다시 로그인해주세요.');
        navigate('/');
      } else {
        alert('전수 점검을 시작하는데 실패했습니다. 다시 시도해주세요.');
      }
    }
  };

  const handleScanComplete = (result: ScanResult) => {
    console.log('Scan completed:', result);
    loadDashboardData(); // 데이터 새로고침
  };

  const handleCloseScanModal = () => {
    setShowScanModal(false);
    setScanJobId(null);
  };

  const handleDownloadReport = async () => {
    try {
      setReportLoading(true);
      await downloadReport();
    } catch (error: any) {
      console.error('Failed to download report:', error);
      if (error.response?.status === 401) {
        alert('로그인이 만료되었습니다. 다시 로그인해주세요.');
        navigate('/');
      } else if (error.response?.status === 404) {
        alert('점검 결과가 없습니다. 먼저 전수 점검을 실행해주세요.');
      } else {
        alert('보고서 생성에 실패했습니다. 다시 시도해주세요.');
      }
    } finally {
      setReportLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    navigate('/');
  };

  if (loading || !data) {
    return (
      <div className="main-dashboard loading">
        <div className="loading-spinner" />
        <p>대시보드 데이터를 불러오는 중...</p>
      </div>
    );
  }

  const { summary, os_categories, db_categories, unresolved_count, os_top_servers, db_top_servers, risk_distribution, vulnerability_ratio } = data;

  return (
    <>
      <TopNav currentUser={user} onLogout={handleLogout} />

      <div className="main-dashboard">
        {/* 상단 정보 카드 */}
      <div className="company-info-card">
        <div className="company-info-left">
          <div className="info-section">
            <div className="info-label">조직</div>
            <div className="company-name">{summary.company}</div>
          </div>
          <div className="info-section">
            <div className="info-label">최근 점검</div>
            <div className={`last-scan ${summary.last_scan_date === 'N/A' ? 'empty' : ''}`}>
              {summary.last_scan_date === 'N/A' ? '미실시' : summary.last_scan_date}
            </div>
          </div>
          <div className="info-section">
            <div className="info-label">운용 자산</div>
            <div className="nodes-count">{summary.total_servers}대</div>
            <div className="version-info">
              {summary.os_info.split(' • ').map((os, idx) => (
                <span key={`os-${idx}`} className="version-badge">{os}</span>
              ))}
              {summary.db_info.split(' • ').map((db, idx) => (
                <span key={`db-${idx}`} className="version-badge">{db}</span>
              ))}
            </div>
          </div>
        </div>
        <div className="company-info-right">
          <button
            onClick={handleDownloadReport}
            className="report-btn"
            disabled={reportLoading}
          >
            {reportLoading ? '생성 중...' : '보고서'}
          </button>
          {user.role === 'ADMIN' && (
            <button
              onClick={() => navigate('/assets')}
              className="scan-btn"
            >
              점검
            </button>
          )}
        </div>
      </div>

      {/* 메인 컨텐츠 (2열 레이아웃) */}
      <div className="main-content">
        {/* 왼쪽 열: TOP 5 리스트 */}
        <div className="left-column">
          {/* Linux 보안 취약 서버 TOP 5 */}
          <div className="top5-card">
            <h3 className="card-title">
              <img src="/rising.png" alt="상승" className="title-icon" />
              Linux 보안 취약점 수가 높은 서버 TOP 5
            </h3>
            <div className="server-list">
              {os_top_servers.map((server) => (
                <div
                  key={server.rank}
                  className="server-item clickable"
                  onClick={() => navigate(`/analysis?server=${server.server_id}&tab=linux`)}
                >
                  <div className="server-rank" data-rank={server.rank}>{server.rank}</div>
                  <div className="server-info">
                    <div className="server-name">{server.server_id}</div>
                    <div className="server-ip">{server.ip_address}</div>
                  </div>
                  <div className="server-stats">
                    <span className="vuln-count">취약 {server.vuln_count}건</span>
                  </div>
                </div>
              ))}
              {os_top_servers.length === 0 && (
                <div className="empty-state">취약점이 발견된 서버가 없습니다 ✨</div>
              )}
            </div>
          </div>

          {/* DB 보안 취약 서버 TOP 5 */}
          <div className="top5-card">
            <h3 className="card-title">
              <img src="/rising.png" alt="상승" className="title-icon" />
              DB 보안 취약점 수가 높은 서버 TOP 5
            </h3>
            <div className="server-list">
              {db_top_servers.map((server) => (
                <div
                  key={server.rank}
                  className="server-item clickable"
                  onClick={() => navigate(`/analysis?server=${server.server_id}&tab=database`)}
                >
                  <div className="server-rank" data-rank={server.rank}>{server.rank}</div>
                  <div className="server-info">
                    <div className="server-name">{server.server_id}</div>
                    <div className="server-ip">{server.ip_address}</div>
                  </div>
                  <div className="server-stats">
                    <span className="vuln-count">취약 {server.vuln_count}건</span>
                  </div>
                </div>
              ))}
              {db_top_servers.length === 0 && (
                <div className="empty-state">취약점이 발견된 서버가 없습니다 ✨</div>
              )}
            </div>
          </div>
        </div>

        {/* 오른쪽 열: 차트 */}
        <div className="right-column">
          {/* OS + DB 보안 취약점 막대 그래프 (나란히) */}
          <div className="chart-row">
            {/* Linux 보안 취약점 */}
            <div className="chart-card">
              <div className="chart-header">
                <img src="/linux.png" alt="Linux" className="chart-icon" />
                <h3 className="chart-title">Linux 보안 취약점</h3>
              </div>
              <BarChart
                data={[
                  { label: '계정 관리', value: os_categories.account },
                  { label: '파일 및\n디렉토리 관리', value: os_categories.directory },
                  { label: '서비스 관리', value: os_categories.service },
                  { label: '패치 관리', value: os_categories.patch },
                  { label: '로그 관리', value: os_categories.log },
                ]}
                color="#3182F7"
              />
            </div>

            {/* DB 보안 취약점 */}
            <div className="chart-card">
              <div className="chart-header">
                <img src="/db_risk2.png" alt="DB" className="chart-icon" />
                <h3 className="chart-title">DB 보안 취약점</h3>
              </div>
              <BarChart
                data={[
                  { label: '계정 관리', value: db_categories.account },
                  { label: '로그 관리', value: db_categories.access },
                  { label: '옵션 관리', value: db_categories.option },
                  { label: '패치 관리', value: db_categories.patch },
                ]}
                color="#00A0E9"
              />
            </div>
          </div>

          {/* 리스크 분포 + 양호/위험 비율 (나란히) */}
          <div className="donut-row">
            {/* 리스크 분포 */}
            <div className="chart-card">
              <div className="chart-header">
                <img src="/statistics.png" alt="통계" className="chart-icon" />
                <h3 className="chart-title">리스크 분포</h3>
              </div>
              <div className="donut-content">
                <DonutChart
                  data={[
                    { label: '저위험', value: risk_distribution.low, color: '#FFBB00' },
                    { label: '중위험', value: risk_distribution.medium, color: '#FF6B00' },
                    { label: '고위험', value: risk_distribution.high, color: '#F04452' },
                  ]}
                  total={risk_distribution.total}
                  centerText={`${risk_distribution.total}건`}
                />
                <div className="chart-legend">
                  <div className="legend-item">
                    <span className="legend-dot" style={{ background: '#FFBB00' }} />
                    <span className="legend-label">저위험</span>
                    <span className="legend-percent">{risk_distribution.low_percent}%</span>
                  </div>
                  <div className="legend-item">
                    <span className="legend-dot" style={{ background: '#FF6B00' }} />
                    <span className="legend-label">중위험</span>
                    <span className="legend-percent">{risk_distribution.medium_percent}%</span>
                  </div>
                  <div className="legend-item">
                    <span className="legend-dot" style={{ background: '#F04452' }} />
                    <span className="legend-label">고위험</span>
                    <span className="legend-percent">{risk_distribution.high_percent}%</span>
                  </div>
                </div>
              </div>
            </div>

            {/* 양호/위험 비율 */}
            <div className="chart-card">
              <div className="chart-header">
                <img src="/statistics.png" alt="통계" className="chart-icon" />
                <h3 className="chart-title">양호/위험 비율</h3>
              </div>
              <div className="donut-content">
                <DonutChart
                  data={[
                    { label: '양호', value: vulnerability_ratio.secure, color: '#15B886' },
                    { label: '취약', value: vulnerability_ratio.vulnerable, color: '#F04452' },
                  ]}
                  total={vulnerability_ratio.total}
                  centerText={`${vulnerability_ratio.vulnerable_percent}%`}
                  centerLabel="취약"
                />
                <div className="chart-legend">
                  <div className="legend-item">
                    <span className="legend-dot" style={{ background: '#15B886' }} />
                    <span className="legend-label">양호</span>
                    <span className="legend-count">{vulnerability_ratio.secure}건</span>
                  </div>
                  <div className="legend-item">
                    <span className="legend-dot" style={{ background: '#F04452' }} />
                    <span className="legend-label">취약</span>
                    <span className="legend-count">{vulnerability_ratio.vulnerable}건</span>
                  </div>
                </div>
              </div>
            </div>
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
      </div>
    </>
  );
}

/**
 * 막대 그래프 컴포넌트
 */
interface BarChartProps {
  data: Array<{ label: string; value: number }>;
  color: string;
}

function BarChart({ data, color }: BarChartProps) {
  const maxValue = Math.max(...data.map(d => d.value), 1);

  return (
    <div className="bar-chart">
      {data.map((item, index) => (
        <div key={index} className="bar-item">
          <div className="bar-wrapper">
            <div
              className="bar"
              style={{
                height: `${(item.value / maxValue) * 100}%`,
                background: color,
              }}
            >
              <span className="bar-value">{item.value}</span>
            </div>
          </div>
          <div className="bar-label">{item.label}</div>
        </div>
      ))}
    </div>
  );
}

/**
 * 도넛 차트 컴포넌트 (SVG 애니메이션)
 */
interface DonutChartProps {
  data: Array<{ label: string; value: number; color: string }>;
  total: number;
  centerText?: string;
  centerLabel?: string;
}

function DonutChart({ data, total, centerText, centerLabel }: DonutChartProps) {
  if (total === 0) {
    return (
      <div className="donut-chart empty">
        <svg viewBox="0 0 200 200">
          <circle cx="100" cy="100" r="80" fill="none" stroke="#E5E8EB" strokeWidth="40" />
        </svg>
        <div className="chart-center">
          <div className="chart-percentage">0</div>
          <div className="chart-label">데이터 없음</div>
        </div>
      </div>
    );
  }

  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  let currentOffset = 0;

  return (
    <div className="donut-chart">
      <svg viewBox="0 0 200 200">
        {data.map((item, index) => {
          const percentage = item.value / total;
          const dashLength = percentage * circumference;
          const dashOffset = -currentOffset;

          const segment = (
            <circle
              key={index}
              cx="100"
              cy="100"
              r={radius}
              fill="none"
              stroke={item.color}
              strokeWidth="40"
              strokeDasharray={`${dashLength} ${circumference}`}
              strokeDashoffset={dashOffset}
              transform="rotate(-90 100 100)"
              className="donut-segment"
              style={{
                animation: `donutFill 1s ease-out ${index * 0.1}s both`
              }}
            />
          );

          currentOffset += dashLength;
          return segment;
        })}
      </svg>
      <div className="chart-center">
        <div className="chart-percentage">{centerText || total}</div>
        {centerLabel && <div className="chart-label">{centerLabel}</div>}
      </div>
    </div>
  );
}
