import { useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import { TopNav } from '../components/TopNav';
import { OnboardingCard } from '../components/cards/OnboardingCard';
import './Dashboard.css';

export function Dashboard() {
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      navigate('/');
      return;
    }

    try {
      const userStr = localStorage.getItem('user');
      if (userStr) {
        const user = JSON.parse(userStr);
        if (user.role !== 'ADMIN') {
          navigate('/main');
        }
      }
    } catch (e) {
      console.error('Failed to parse user:', e);
    }
  }, [navigate]);

  const handleSingleServer = () => {
    navigate('/register?type=single');
  };

  const handleBulkUpload = () => {
    navigate('/register?type=bulk');
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    navigate('/');
  };

  let user: any = {};
  try {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      user = JSON.parse(userStr);
    }
  } catch (e) {
    console.error('Failed to parse user:', e);
  }

  return (
    <>
      <TopNav currentUser={user} onLogout={handleLogout} />
      <div className="dashboard">
        <div className="dashboard-container">
          <div className="dashboard-header">
            <h1 className="dashboard-title">자산 등록</h1>
            <p className="dashboard-subtitle">
              보안 점검을 시작하려면 먼저 서버를 등록해주세요
            </p>
          </div>

          <div className="onboarding-cards">
            <OnboardingCard
              icon="🖥️"
              title="단일 서버 등록"
              description="서버 정보를 직접 입력하여<br/>한 대씩 등록합니다"
              badge="추천: 1~5대"
              onClick={handleSingleServer}
            />
            <OnboardingCard
              icon="📊"
              title="CSV 대량 등록"
              description="엑셀 파일을 업로드하여<br/>여러 대를 한번에 등록합니다"
              badge="추천: 6대 이상"
              onClick={handleBulkUpload}
            />
          </div>
        </div>
      </div>
    </>
  );
}
