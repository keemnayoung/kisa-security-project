import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css';

type LoginStep = 'checking' | 'blocked' | 'login';

export function Login() {
  const navigate = useNavigate();
  const [step, setStep] = useState<LoginStep>('checking');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [clientIp, setClientIp] = useState('');

  // API 베이스 URL (동적 설정)
  const API_BASE = `http://${window.location.hostname}:8000`;

  useEffect(() => {
    // 이미 로그인되어 있으면 대시보드로 리다이렉트
    const token = localStorage.getItem('access_token');
    if (token) {
      navigate('/main');
      return;
    }

    // 내부망 체크 (백엔드 API 호출)
    checkNetworkAccess();
  }, []);

  const checkNetworkAccess = async () => {
    try {
      // 타임아웃 설정 (2초로 단축)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      // 백엔드 /health 호출 (IP 필터링 체크)
      const response = await fetch(`${API_BASE}/health`, {
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.status === 403) {
        // IP 필터링으로 차단됨
        const data = await response.json();
        setClientIp(data.client_ip || '확인 불가');
        setStep('blocked');
      } else if (response.ok) {
        // 내부망 접속 확인
        setTimeout(() => setStep('login'), 1500);
      } else {
        // 기타 에러 (서버 연결 실패 등)
        setError('내부망 연결 실패');
        setStep('blocked');
      }
    } catch (err) {
      // 네트워크 에러 또는 타임아웃 (VPN 켜진 경우)
      console.error('Network check error:', err);
      if (err instanceof Error && err.name === 'AbortError') {
        setError('내부망에 연결할 수 없습니다');
      } else {
        setError('내부망에 연결할 수 없습니다');
      }
      setStep('blocked');
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const data = await response.json();
        setError(data.detail || '로그인 실패');
        return;
      }

      const data = await response.json();

      // 토큰 저장
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('user', JSON.stringify(data.user));

      // must_change_password 체크
      if (data.user.must_change_password) {
        alert('최초 로그인입니다. 비밀번호를 변경해주세요.');
        navigate('/change-password');
      } else {
        // 역할에 따라 다른 페이지로 이동
        if (data.user.role === 'ADMIN') {
          navigate('/main'); // 관리자: 메인 대시보드
        } else {
          navigate('/main'); // 뷰어: 메인 대시보드 (읽기 전용)
        }
      }
    } catch (err) {
      console.error('Login error:', err);
      setError('로그인 중 오류가 발생했습니다');
    }
  };

  // Step 1: 내부망 확인 중
  if (step === 'checking') {
    return (
      <div className="login-page">
        <div className="intro-container">
          <img src="/login.png" alt="Fiber Joint Security" className="intro-logo" />
          <div className="intro-title">내부망 보안 점검 시스템</div>
          <div className="intro-subtitle">SECURITYCORE v2.0</div>
          <div className="check-animation">
            <div className="spinner"></div>
            <div className="check-text">네트워크 환경 확인 중...</div>
          </div>
        </div>
      </div>
    );
  }

  // Step 2: 외부망 차단
  if (step === 'blocked') {
    return (
      <div className="login-page">
        <div className="intro-container">
          <img src="/risk2.png" alt="접근 차단" className="intro-logo" />
          <div className="intro-title">내부망 접근 제한</div>
          <div className="intro-subtitle">이 시스템은 내부망에서만 접속할 수 있습니다</div>

          {clientIp && (
            <div className="blocked-detail">
              <div className="detail-item">
                <span className="detail-label">현재 IP:</span>
                <span className="detail-value">{clientIp}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">허용 대역:</span>
                <span className="detail-value">192.168.0.0/16, 10.0.0.0/8</span>
              </div>
            </div>
          )}

          {error && (
            <div className="blocked-message">⚠️ {error}</div>
          )}

          <div className="blocked-hint">
            외부망에서 접속 중이라면 VPN 접속 후 다시 시도하세요
          </div>
        </div>
      </div>
    );
  }

  // Step 3: 로그인 페이지
  return (
    <div className="login-page">
      {/* 내부망 연결 확인 배지 */}
      <div className="success-badge-container">
        <div className="success-badge">
          ✓ 내부망 접속 확인
        </div>
      </div>

      <div className="login-container">
        <img src="/login.png" alt="Fiber Joint Security" className="login-logo" />
        <div className="login-title">로그인</div>
        <div className="login-subtitle">내부망 보안 점검 시스템</div>

        <form className="login-form" onSubmit={handleLogin}>
          <div className="form-field">
            <label>아이디</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="아이디를 입력하세요"
              required
            />
          </div>

          <div className="form-field">
            <label>비밀번호</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="비밀번호를 입력하세요"
              required
            />
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" className="login-btn">
            로그인
          </button>
        </form>
      </div>
    </div>
  );
}
