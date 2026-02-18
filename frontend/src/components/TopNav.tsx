/**
 * 상단 네비게이션 바 (Toss 스타일)
 */

import { useNavigate } from 'react-router-dom';
import './TopNav.css';

interface TopNavProps {
  currentUser: {
    role: string;
    user_name?: string;
  };
  onLogout: () => void;
}

export function TopNav({ currentUser, onLogout }: TopNavProps) {
  const navigate = useNavigate();

  const menuItems = [
    { label: '자산 목록', path: '/assets' },
    { label: '자산 분석', path: '/analysis' },
    { label: '점검 및 조치 이력', path: '/history' },
    { label: '예외 처리', path: '/exceptions' },
  ];

  return (
    <nav className="topnav">
      <div className="topnav-container">
        {/* 왼쪽: 로고 */}
        <div className="topnav-logo" onClick={() => navigate('/main')}>
          <img src="/secu.png" alt="KISA Security" />
        </div>

        {/* 중앙: 메뉴 */}
        <div className="topnav-menu">
          {menuItems.map((item) => (
            <button
              key={item.path}
              className={`topnav-menu-item ${window.location.pathname === item.path ? 'active' : ''}`}
              onClick={() => navigate(item.path)}
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* 오른쪽: 사용자 정보 + 로그아웃 */}
        <div className="topnav-actions">
          <span className={`user-badge ${currentUser.role === 'ADMIN' ? 'admin' : 'viewer'}`}>
            {currentUser.role === 'ADMIN' ? '관리자' : '뷰어'}
          </span>
          <button onClick={onLogout} className="logout-btn">
            로그아웃
          </button>
        </div>
      </div>
    </nav>
  );
}
