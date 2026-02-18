import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './ChangePassword.css';

export function ChangePassword() {
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // 비밀번호 표시/숨김 상태
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const API_BASE = `http://${window.location.hostname}:8000`;

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // 비밀번호 일치 확인
    if (newPassword !== confirmPassword) {
      setError('새 비밀번호가 일치하지 않습니다');
      return;
    }

    // 비밀번호 길이 확인
    if (newPassword.length < 8) {
      setError('비밀번호는 최소 8자 이상이어야 합니다');
      return;
    }

    setLoading(true);

    try {
      const token = localStorage.getItem('access_token');
      console.log('🔑 Token exists:', !!token);
      console.log('🔑 Token preview:', token?.substring(0, 50) + '...');

      if (!token) {
        console.error('❌ No token found in localStorage');
        navigate('/');
        return;
      }

      console.log('📡 Sending change password request...');
      const response = await fetch(`${API_BASE}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          old_password: currentPassword,
          new_password: newPassword,
        }),
      });

      console.log('📡 Response status:', response.status);

      if (!response.ok) {
        // 401 에러 (인증 실패) 시 로그인 페이지로 이동
        if (response.status === 401) {
          console.error('❌ 401 Unauthorized - Token validation failed');
          const errorData = await response.json();
          console.error('❌ Error detail:', errorData);

          localStorage.removeItem('access_token');
          localStorage.removeItem('user');
          alert('로그인 세션이 만료되었습니다. 다시 로그인해주세요.');
          navigate('/');
          return;
        }

        const data = await response.json();
        console.error('❌ Error:', data);
        setError(data.detail || '비밀번호 변경 실패');
        setLoading(false);
        return;
      }

      // 성공
      alert('비밀번호가 변경되었습니다. 자산 등록을 시작하세요!');
      // 토큰 유지하고 온보딩 선택 화면으로 이동
      navigate('/dashboard');
    } catch (err) {
      console.error('Password change error:', err);
      setError('비밀번호 변경 중 오류가 발생했습니다');
      setLoading(false);
    }
  };

  return (
    <div className="change-password-page">
      <div className="change-password-container">
        <img src="/login.png" alt="Fiber Joint Security" className="logo" />
        <div className="title">비밀번호 변경</div>
        <div className="subtitle">최초 로그인입니다. 비밀번호를 변경해주세요.</div>

        <form className="form" onSubmit={handleChangePassword}>
          <div className="form-field">
            <label>현재 비밀번호</label>
            <div className="password-input-wrapper">
              <input
                type={showCurrentPassword ? "text" : "password"}
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="현재 비밀번호를 입력하세요"
                required
                disabled={loading}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                disabled={loading}
              >
                <span className={showCurrentPassword ? 'eye-icon eye-open' : 'eye-icon eye-closed'}>
                  {showCurrentPassword ? (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                      <circle cx="12" cy="12" r="3"/>
                    </svg>
                  ) : (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                      <line x1="1" y1="1" x2="23" y2="23"/>
                    </svg>
                  )}
                </span>
              </button>
            </div>
          </div>

          <div className="form-field">
            <label>새 비밀번호</label>
            <div className="password-input-wrapper">
              <input
                type={showNewPassword ? "text" : "password"}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="새 비밀번호를 입력하세요 (최소 8자)"
                required
                disabled={loading}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => setShowNewPassword(!showNewPassword)}
                disabled={loading}
              >
                <span className={showNewPassword ? 'eye-icon eye-open' : 'eye-icon eye-closed'}>
                  {showNewPassword ? (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                      <circle cx="12" cy="12" r="3"/>
                    </svg>
                  ) : (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                      <line x1="1" y1="1" x2="23" y2="23"/>
                    </svg>
                  )}
                </span>
              </button>
            </div>
          </div>

          <div className="form-field">
            <label>새 비밀번호 확인</label>
            <div className="password-input-wrapper">
              <input
                type={showConfirmPassword ? "text" : "password"}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="새 비밀번호를 다시 입력하세요"
                required
                disabled={loading}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                disabled={loading}
              >
                <span className={showConfirmPassword ? 'eye-icon eye-open' : 'eye-icon eye-closed'}>
                  {showConfirmPassword ? (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                      <circle cx="12" cy="12" r="3"/>
                    </svg>
                  ) : (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                      <line x1="1" y1="1" x2="23" y2="23"/>
                    </svg>
                  )}
                </span>
              </button>
            </div>
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" className="submit-btn" disabled={loading}>
            {loading ? '변경 중...' : '비밀번호 변경'}
          </button>
        </form>

        <div className="help-text">
          💡 안전한 비밀번호를 위해 영문, 숫자, 특수문자를 조합하세요.
        </div>
      </div>
    </div>
  );
}
