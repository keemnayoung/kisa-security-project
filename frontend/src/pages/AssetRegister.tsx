import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CustomSelect } from '../components/common/CustomSelect';
import './AssetRegister.css';

// API 베이스 URL
const API_BASE = `http://${window.location.hostname}:8000`;

type StepType = 1 | 2 | 3;

export function AssetRegister() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const type = searchParams.get('type') || 'single';
  const [currentStep, setCurrentStep] = useState<StepType>(1);
  const [view, setView] = useState<'form' | 'list'>('form');
  const [servers, setServers] = useState<any[]>([]);
  const [selectedServers, setSelectedServers] = useState<Set<string>>(new Set());
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');

  useEffect(() => {
    // 로그인 확인 (토큰 없으면 로그인 페이지로)
    const token = localStorage.getItem('access_token');
    if (!token) {
      navigate('/');
      return;
    }

    // 뷰어는 서버 등록 불가 → 메인 대시보드로 리다이렉트
    try {
      const userStr = localStorage.getItem('user');
      if (userStr) {
        const user = JSON.parse(userStr);
        if (user.role !== 'ADMIN') {
          alert('서버 등록은 관리자만 가능합니다');
          navigate('/main-dashboard');
          return;
        }
      }
    } catch (e) {
      console.error('Failed to parse user:', e);
    }

    // 초기 서버 목록 로드
    const initServers = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/assets`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        if (response.ok) {
          const data = await response.json();
          setServers(data);
        }
      } catch (error) {
        console.error('Failed to load servers:', error);
      }
    };

    initServers();
  }, [navigate, type]);

  // 단일 등록 폼 상태
  const [serverId, setServerId] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [company, setCompany] = useState('');
  const [hostname, setHostname] = useState('');
  const [osType, setOsType] = useState('Rocky Linux 9.7');
  const [manager, setManager] = useState('');
  const [department, setDepartment] = useState('');

  const [dbType, setDbType] = useState('없음');
  const [dbPort, setDbPort] = useState('');
  const [dbUser, setDbUser] = useState('');
  const [dbPasswd, setDbPasswd] = useState('');
  const [dbName, setDbName] = useState('postgres');
  const [encryptPw, setEncryptPw] = useState(true);

  // 테스트 결과 상태
  const [sshTestResult, setSshTestResult] = useState<{ status: 'idle' | 'loading' | 'success' | 'error', message?: string }>({ status: 'idle' });
  const [dbPortResult, setDbPortResult] = useState<{ status: 'idle' | 'loading' | 'success' | 'error', message?: string }>({ status: 'idle' });
  const [dbLoginResult, setDbLoginResult] = useState<{ status: 'idle' | 'loading' | 'success' | 'error', message?: string }>({ status: 'idle' });

  // CSV 업로드 상태
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [csvData, setCsvData] = useState<any[]>([]);
  const [bulkRegistering, setBulkRegistering] = useState(false);
  const [bulkResults, setBulkResults] = useState<any[] | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const getDefaultDbPort = (type: string) => {
    if (type === 'MySQL 8.0.4') return '3306';
    if (type === 'PostgreSQL 16.11') return '5432';
    return '';
  };

  const handleDbTypeChange = (val: string) => {
    setDbType(val);
    setDbPort(getDefaultDbPort(val));
    setCurrentStep(2);
  };

  const fetchServers = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/assets`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setServers(data);
      }
    } catch (error) {
      console.error('Failed to fetch servers:', error);
    }
  };

  const resetForm = () => {
    setServerId('');
    setIpAddress('');
    setCompany('');
    setHostname('');
    setOsType('Rocky Linux 9.7');
    setManager('');
    setDepartment('');
    setDbType('없음');
    setDbPort('');
    setDbUser('');
    setDbPasswd('');
    setDbName('postgres');
    setEncryptPw(true);
    setSshTestResult({ status: 'idle' });
    setDbPortResult({ status: 'idle' });
    setDbLoginResult({ status: 'idle' });
    setCurrentStep(1);
  };

  const handleSshTest = async () => {
    if (!serverId || !ipAddress || !hostname) {
      setSshTestResult({ status: 'error', message: '기본 정보를 모두 입력하세요' });
      return;
    }

    setSshTestResult({ status: 'loading' });
    setCurrentStep(3);

    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/assets/test/ssh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          ip_address: ipAddress,
          hostname: hostname,
          ssh_port: '22'
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setSshTestResult({ status: 'success', message: data.message });
      } else {
        setSshTestResult({ status: 'error', message: data.message || 'SSH 연결 실패' });
      }
    } catch (error) {
      setSshTestResult({ status: 'error', message: 'SSH 연결 테스트 중 오류가 발생했습니다' });
    }
  };

  const handleDbPortTest = async () => {
    if (!dbPort) return;

    setDbPortResult({ status: 'loading' });

    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/assets/test/db-port`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          ip_address: ipAddress,
          db_port: parseInt(dbPort)
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setDbPortResult({ status: 'success', message: data.message });
      } else {
        setDbPortResult({ status: 'error', message: data.message || 'DB 포트 접근 불가' });
      }
    } catch (error) {
      setDbPortResult({ status: 'error', message: 'DB 포트 테스트 중 오류가 발생했습니다' });
    }
  };

  const handleDbLoginTest = async () => {
    if (!ipAddress || !dbPort || !dbUser || !dbPasswd) {
      setDbLoginResult({ status: 'error', message: 'DB 접속 정보를 입력하세요' });
      return;
    }

    setDbLoginResult({ status: 'loading' });

    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/assets/test/db-login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          ip_address: ipAddress,
          db_type: dbType,
          db_port: parseInt(dbPort),
          db_user: dbUser,
          db_passwd: dbPasswd
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setDbLoginResult({ status: 'success', message: data.message });
      } else {
        setDbLoginResult({ status: 'error', message: data.message || 'DB 로그인 실패' });
      }
    } catch (error) {
      setDbLoginResult({ status: 'error', message: 'DB 로그인 테스트 중 오류가 발생했습니다' });
    }
  };

  const handleRegister = async () => {
    if (!serverId || !ipAddress || !company || !hostname || !osType || !manager || !department) {
      alert('필수 항목을 모두 입력하세요');
      return;
    }

    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/assets`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          server_id: serverId,
          ip_address: ipAddress,
          company: company,
          hostname: hostname,
          ssh_port: '22',
          os_type: osType,
          db_type: dbType === '없음' ? null : dbType,
          db_port: dbPort || null,
          db_user: dbUser || null,
          db_passwd: dbPasswd || null,
          manager: manager,
          department: department,
          encrypt_pw: encryptPw
        })
      });

      if (!response.ok) {
        const data = await response.json();
        alert(`등록 실패: ${data.detail || '알 수 없는 오류'}`);
        // 실패해도 목록을 보여주기 (기존 서버 확인 가능)
        await fetchServers();
        setView('list');
        return;
      }

      alert(`✅ 자산 ${serverId} 등록 완료`);
      resetForm();
      await fetchServers();
      setView('list');
    } catch (error) {
      console.error('Server registration error:', error);
      alert('등록 중 오류가 발생했습니다');
      // 에러 발생해도 목록 보여주기
      await fetchServers();
      setView('list');
    }
  };

  const parseCsvFile = (file: File) => {
    setCsvFile(file);
    setBulkResults(null);

    const reader = new FileReader();
    reader.onload = (event) => {
      let text = event.target?.result as string;
      if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
      const lines = text.split('\n').filter(l => l.trim());
      const headers = lines[0].split(',').map(h => h.trim());
      const data = lines.slice(1).map(line => {
        const values = line.split(',');
        return headers.reduce((obj, header, i) => {
          obj[header] = values[i]?.trim() || '';
          return obj;
        }, {} as any);
      });
      setCsvData(data);
    };
    reader.readAsText(file, 'UTF-8');
  };

  const handleCsvUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) parseCsvFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith('.csv')) parseCsvFile(file);
  };

  const downloadTemplate = () => {
    const csv = `서버명,IP주소,회사명,계정,운영체제,DB종류,DB계정,DB비밀번호,담당자,부서명
web-01,192.168.10.10,AUTOEVER,manager,Rocky Linux 9.7,없음,,,김보안,보안팀
db-01,192.168.10.11,NAVER,manager,Rocky Linux 10.1,PostgreSQL,audit_user,CHANGE_ME,이DB,인프라팀`;

    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'asset_template.csv';
    link.click();
  };

  // CSV → API 필드 매핑
  const CSV_FIELD_MAP: Record<string, string> = {
    '서버명': 'server_id',
    'IP주소': 'ip_address',
    '회사명': 'company',
    '계정': 'hostname',
    '운영체제': 'os_type',
    'DB종류': 'db_type',
    'DB계정': 'db_user',
    'DB비밀번호': 'db_passwd',
    '담당자': 'manager',
    '부서명': 'department',
  };

  const handleBulkRegister = async () => {
    if (csvData.length === 0) return;

    // CSV 데이터를 API 형식으로 변환
    const servers = csvData.map(row => {
      const mapped: any = {};
      for (const [csvKey, apiKey] of Object.entries(CSV_FIELD_MAP)) {
        mapped[apiKey] = row[csvKey] || '';
      }
      // 기본값 설정
      mapped.ssh_port = '22';
      mapped.encrypt_pw = true;
      if (!mapped.db_type || mapped.db_type === '없음') {
        mapped.db_type = null;
        mapped.db_user = null;
        mapped.db_passwd = null;
      }
      return mapped;
    });

    // 필수 필드 검증
    const invalid = servers.filter(s => !s.server_id || !s.ip_address || !s.company || !s.hostname || !s.os_type || !s.manager || !s.department);
    if (invalid.length > 0) {
      alert(`필수 항목이 누락된 행이 ${invalid.length}건 있습니다.\n(서버명, IP주소, 회사명, 계정, 운영체제, 담당자, 부서명은 필수)`);
      return;
    }

    setBulkRegistering(true);
    setBulkResults(null);

    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/assets/bulk`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ servers })
      });

      const data = await response.json();

      if (response.ok) {
        setBulkResults(data.results);
        await fetchServers();
      } else {
        alert(`등록 실패: ${data.detail || '알 수 없는 오류'}`);
      }
    } catch (error) {
      alert('일괄 등록 중 오류가 발생했습니다');
    } finally {
      setBulkRegistering(false);
    }
  };

  const title = type === 'bulk' ? 'CSV 대량 등록' : '단일 서버 등록';
  const subtitle = type === 'bulk'
    ? '템플릿을 다운로드하여 여러 대의 서버를 한번에 등록하세요'
    : '보안 점검을 수행할 서버 정보를 입력해주세요';

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    navigate('/');
  };

  // 전체 선택/해제
  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedServers(new Set(servers.map(s => s.server_id)));
    } else {
      setSelectedServers(new Set());
    }
  };

  // 개별 선택/해제
  const handleSelectServer = (serverId: string, checked: boolean) => {
    const newSelected = new Set(selectedServers);
    if (checked) {
      newSelected.add(serverId);
    } else {
      newSelected.delete(serverId);
    }
    setSelectedServers(newSelected);
  };

  // 선택된 서버 삭제
  const handleDeleteSelected = async () => {
    if (selectedServers.size === 0) {
      alert('삭제할 서버를 선택하세요');
      return;
    }

    if (!confirm(`선택한 ${selectedServers.size}개의 서버를 삭제하시겠습니까?`)) {
      return;
    }

    try {
      const token = localStorage.getItem('access_token');
      let successCount = 0;
      let failCount = 0;
      const errors: string[] = [];

      for (const serverId of selectedServers) {
        const response = await fetch(`${API_BASE}/api/assets/${serverId}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (response.ok) {
          successCount++;
        } else {
          failCount++;
          try {
            const errorData = await response.json();
            errors.push(`${serverId}: ${errorData.detail || '알 수 없는 오류'}`);
          } catch {
            errors.push(`${serverId}: HTTP ${response.status}`);
          }
        }
      }

      if (errors.length > 0) {
        alert(`삭제 완료: ${successCount}개 성공, ${failCount}개 실패\n\n실패 원인:\n${errors.join('\n')}`);
      } else {
        alert(`삭제 완료: ${successCount}개 성공`);
      }

      setSelectedServers(new Set());
      await fetchServers();
    } catch (error) {
      console.error('Delete error:', error);
      alert(`삭제 중 오류가 발생했습니다: ${error}`);
    }
  };

  // 정렬 핸들러
  const handleSort = (column: string) => {
    if (sortColumn === column) {
      // 같은 컬럼 클릭 시 방향 토글
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      // 새로운 컬럼 클릭 시 오름차순으로 시작
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  // 정렬된 서버 목록
  const getSortedServers = () => {
    if (!sortColumn) return servers;

    const sorted = [...servers].sort((a, b) => {
      const aVal = a[sortColumn] || '';
      const bVal = b[sortColumn] || '';

      // 한글 및 숫자 정렬 지원
      if (sortDirection === 'asc') {
        return aVal.toString().localeCompare(bVal.toString(), 'ko', { numeric: true });
      } else {
        return bVal.toString().localeCompare(aVal.toString(), 'ko', { numeric: true });
      }
    });

    return sorted;
  };

  // 정렬 아이콘
  const getSortIcon = (column: string) => {
    if (sortColumn !== column) return '';
    return sortDirection === 'asc' ? ' ↑' : ' ↓';
  };

  // 컨테이너 너비 계산
  const getContainerWidth = () => {
    if (type === 'single' && view === 'list') return '900px';  // 목록: +50px
    if (type === 'single' && view === 'form') return '750px';  // 폼: -100px
    return '1200px';  // CSV 업로드: 넓게
  };

  let user: any = {};
  let userRole = '사용자';
  try {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      user = JSON.parse(userStr);
      userRole = user.role === 'ADMIN' ? '관리자' : '뷰어';
    }
  } catch (e) {
    console.error('Failed to parse user:', e);
  }

  return (
    <div className="asset-register">
      <div className="asset-register-container" style={{ maxWidth: getContainerWidth() }}>
        {/* 헤더 */}
        <div className="asset-register-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', width: '100%' }}>
            <div>
              <button onClick={() => navigate('/dashboard')} className="back-button">
                ← 돌아가기
              </button>
              <h1 className="asset-register-title">{title}</h1>
              <p className="asset-register-subtitle">
                {subtitle}
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', paddingTop: '8px' }}>
              <span style={{
                background: user.role === 'ADMIN' ? 'var(--color-blue-100)' : 'var(--color-gray-200)',
                color: user.role === 'ADMIN' ? 'var(--color-blue-700)' : 'var(--color-gray-700)',
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: 600
              }}>
                {userRole}
              </span>
              <button
                onClick={handleLogout}
                style={{
                  background: 'white',
                  border: '1px solid var(--color-gray-300)',
                  borderRadius: '6px',
                  padding: '6px 12px',
                  fontSize: '14px',
                  fontWeight: 500,
                  cursor: 'pointer',
                  color: 'var(--color-gray-700)'
                }}
              >
                로그아웃
              </button>
            </div>
          </div>
        </div>

        {/* 단일 등록 */}
        {type === 'single' && view === 'form' && (
          <div className="form-container">
            {/* 진행 단계 */}
            <div className="steps">
              <div className="step">
                <div className={`step-num ${currentStep >= 1 ? 'active' : ''}`}>1</div>
                <div className={`step-label ${currentStep >= 1 ? 'active' : ''}`}>기본정보</div>
              </div>
              <div className={`step-line ${currentStep >= 2 ? 'active' : ''}`}></div>
              <div className="step">
                <div className={`step-num ${currentStep >= 2 ? 'active' : ''}`}>2</div>
                <div className={`step-label ${currentStep >= 2 ? 'active' : ''}`}>DB설정</div>
              </div>
              <div className={`step-line ${currentStep >= 3 ? 'active' : ''}`}></div>
              <div className="step">
                <div className={`step-num ${currentStep >= 3 ? 'active' : ''}`}>3</div>
                <div className={`step-label ${currentStep >= 3 ? 'active' : ''}`}>검증</div>
              </div>
            </div>

            {/* 기본 정보 */}
            <div className="section-title">기본 정보</div>
            <div className="form-grid">
              <div className="form-field">
                <label>서버명</label>
                <input type="text" value={serverId} onChange={(e) => setServerId(e.target.value)} placeholder="web-01" />
              </div>
              <div className="form-field">
                <label>SSH 계정</label>
                <input type="text" value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="manager" />
              </div>
              <div className="form-field">
                <label>IP 주소</label>
                <input type="text" value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="192.168.10.10" />
              </div>
              <div className="form-field">
                <label>SSH 포트</label>
                <input type="text" value="22" disabled />
              </div>
              <div className="form-field">
                <label>회사명</label>
                <input type="text" value={company} onChange={(e) => setCompany(e.target.value)} placeholder="AUTOEVER" />
              </div>
              <div className="form-field">
                <label>운영체제</label>
                <CustomSelect
                  value={osType}
                  onChange={setOsType}
                  options={['Rocky Linux 9.7', 'Rocky Linux 10.1']}
                />
              </div>
              <div className="form-field">
                <label>담당자</label>
                <input type="text" value={manager} onChange={(e) => setManager(e.target.value)} placeholder="김보안" />
              </div>
              <div className="form-field">
                <label>부서</label>
                <input type="text" value={department} onChange={(e) => setDepartment(e.target.value)} placeholder="보안팀" />
              </div>
            </div>

            {/* DB 설정 */}
            <div className="section-title">데이터베이스 설정 (선택)</div>
            <div className="form-grid">
              <div className="form-field">
                <label>DB 종류</label>
                <CustomSelect
                  value={dbType}
                  onChange={handleDbTypeChange}
                  options={['없음', 'MySQL 8.0.4', 'PostgreSQL 16.11']}
                />
              </div>
              <div className="form-field">
                <label>DB 포트</label>
                <input type="text" value={dbPort} onChange={(e) => setDbPort(e.target.value)} placeholder="3306" />
              </div>
              {dbType !== '없음' && (
                <>
                  <div className="form-field">
                    <label>DB 계정</label>
                    <input type="text" value={dbUser} onChange={(e) => setDbUser(e.target.value)} placeholder="audit_user" />
                  </div>
                  <div className="form-field">
                    <label>DB 비밀번호</label>
                    <input type="password" value={dbPasswd} onChange={(e) => setDbPasswd(e.target.value)} placeholder="••••••••" />
                  </div>
                  {dbType === 'PostgreSQL 16.11' && (
                    <div className="form-field full-width">
                      <label>DB 이름 (테스트용)</label>
                      <input type="text" value={dbName} onChange={(e) => setDbName(e.target.value)} />
                    </div>
                  )}
                  <div className="form-field full-width">
                    <label className="checkbox-label">
                      <input type="checkbox" checked={encryptPw} onChange={(e) => setEncryptPw(e.target.checked)} />
                      비밀번호 암호화
                    </label>
                  </div>
                </>
              )}
            </div>

            {/* 연결 검증 */}
            <div className="section-title">연결 검증</div>
            <div className="test-buttons">
              <button
                className={`test-btn ${sshTestResult.status}`}
                onClick={handleSshTest}
                disabled={sshTestResult.status === 'loading'}
              >
                <span className="test-btn-content">
                  {sshTestResult.status === 'loading' && <span className="test-btn-spinner" />}
                  {sshTestResult.status === 'success' && <span className="test-btn-icon check">{'\u2714'}</span>}
                  {sshTestResult.status === 'error' && <span className="test-btn-icon fail">{'\u2718'}</span>}
                  {sshTestResult.status === 'loading' ? '테스트 중...' : 'SSH 연결 테스트'}
                </span>
              </button>
              {dbType !== '없음' && (
                <>
                  <button
                    className={`test-btn ${dbPortResult.status}`}
                    onClick={handleDbPortTest}
                    disabled={dbPortResult.status === 'loading'}
                  >
                    <span className="test-btn-content">
                      {dbPortResult.status === 'loading' && <span className="test-btn-spinner" />}
                      {dbPortResult.status === 'success' && <span className="test-btn-icon check">{'\u2714'}</span>}
                      {dbPortResult.status === 'error' && <span className="test-btn-icon fail">{'\u2718'}</span>}
                      {dbPortResult.status === 'loading' ? '확인 중...' : 'DB 포트 확인'}
                    </span>
                  </button>
                  <button
                    className={`test-btn ${dbLoginResult.status}`}
                    onClick={handleDbLoginTest}
                    disabled={dbLoginResult.status === 'loading'}
                  >
                    <span className="test-btn-content">
                      {dbLoginResult.status === 'loading' && <span className="test-btn-spinner" />}
                      {dbLoginResult.status === 'success' && <span className="test-btn-icon check">{'\u2714'}</span>}
                      {dbLoginResult.status === 'error' && <span className="test-btn-icon fail">{'\u2718'}</span>}
                      {dbLoginResult.status === 'loading' ? '테스트 중...' : 'DB 로그인 테스트'}
                    </span>
                  </button>
                </>
              )}
            </div>

            {/* 테스트 결과 */}
            {sshTestResult.status !== 'idle' && (
              <div key={`ssh-${sshTestResult.status}`} className={`alert test-alert alert-${sshTestResult.status === 'success' ? 'success' : sshTestResult.status === 'error' ? 'error' : 'info'}`}>
                <span className="test-alert-icon">
                  {sshTestResult.status === 'success' && '\u2714'}
                  {sshTestResult.status === 'error' && '\u2718'}
                  {sshTestResult.status === 'loading' && '\u25CF'}
                </span>
                {sshTestResult.message}
              </div>
            )}
            {dbPortResult.status !== 'idle' && (
              <div key={`dbport-${dbPortResult.status}`} className={`alert test-alert alert-${dbPortResult.status === 'success' ? 'success' : dbPortResult.status === 'error' ? 'error' : 'info'}`}>
                <span className="test-alert-icon">
                  {dbPortResult.status === 'success' && '\u2714'}
                  {dbPortResult.status === 'error' && '\u2718'}
                  {dbPortResult.status === 'loading' && '\u25CF'}
                </span>
                {dbPortResult.message}
              </div>
            )}
            {dbLoginResult.status !== 'idle' && (
              <div key={`dblogin-${dbLoginResult.status}`} className={`alert test-alert alert-${dbLoginResult.status === 'success' ? 'success' : dbLoginResult.status === 'error' ? 'error' : 'info'}`}>
                <span className="test-alert-icon">
                  {dbLoginResult.status === 'success' && '\u2714'}
                  {dbLoginResult.status === 'error' && '\u2718'}
                  {dbLoginResult.status === 'loading' && '\u25CF'}
                </span>
                {dbLoginResult.message}
              </div>
            )}

            {/* 등록 버튼 */}
            <button className="register-btn" onClick={handleRegister}>
              등록 완료
            </button>
          </div>
        )}

        {/* 서버 목록 */}
        {type === 'single' && view === 'list' && (
          <div className="form-container">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <h2 style={{ fontSize: '20px', fontWeight: 600, margin: 0 }}>등록된 서버 목록</h2>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={() => { resetForm(); setView('form'); }}
                  style={{
                    background: 'white',
                    color: 'var(--color-blue-600)',
                    border: '1px solid var(--color-blue-600)',
                    borderRadius: '8px',
                    padding: '10px 20px',
                    fontSize: '15px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <span style={{ fontSize: '18px' }}>+</span> 서버 추가
                </button>
                <button
                  onClick={() => navigate('/assets')}
                  style={{
                    background: 'var(--color-blue-600)',
                    color: 'white',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '10px 20px',
                    fontSize: '15px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  점검하러 가기 →
                </button>
              </div>
            </div>

            <div className="alert alert-info">
              총 {servers.length}대의 서버가 등록되어 있습니다
              {selectedServers.size > 0 && ` | ${selectedServers.size}개 선택됨`}
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '16px' }}>
                <thead>
                  <tr style={{ background: 'var(--color-gray-100)', borderBottom: '2px solid var(--color-gray-200)' }}>
                    <th
                      onClick={() => handleSort('server_id')}
                      style={{
                        padding: '12px',
                        textAlign: 'left',
                        fontSize: '14px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        userSelect: 'none',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--color-gray-200)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = ''}
                    >
                      서버명{getSortIcon('server_id')}
                    </th>
                    <th
                      onClick={() => handleSort('ip_address')}
                      style={{
                        padding: '12px',
                        textAlign: 'left',
                        fontSize: '14px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        userSelect: 'none',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--color-gray-200)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = ''}
                    >
                      IP 주소{getSortIcon('ip_address')}
                    </th>
                    <th
                      onClick={() => handleSort('company')}
                      style={{
                        padding: '12px',
                        textAlign: 'left',
                        fontSize: '14px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        userSelect: 'none',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--color-gray-200)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = ''}
                    >
                      회사{getSortIcon('company')}
                    </th>
                    <th
                      onClick={() => handleSort('os_type')}
                      style={{
                        padding: '12px',
                        textAlign: 'left',
                        fontSize: '14px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        userSelect: 'none',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--color-gray-200)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = ''}
                    >
                      OS{getSortIcon('os_type')}
                    </th>
                    <th
                      onClick={() => handleSort('db_type')}
                      style={{
                        padding: '12px',
                        textAlign: 'left',
                        fontSize: '14px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        userSelect: 'none',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--color-gray-200)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = ''}
                    >
                      DB{getSortIcon('db_type')}
                    </th>
                    <th
                      onClick={() => handleSort('manager')}
                      style={{
                        padding: '12px',
                        textAlign: 'left',
                        fontSize: '14px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        userSelect: 'none',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--color-gray-200)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = ''}
                    >
                      담당자{getSortIcon('manager')}
                    </th>
                    <th
                      onClick={() => handleSort('department')}
                      style={{
                        padding: '12px',
                        textAlign: 'left',
                        fontSize: '14px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        userSelect: 'none',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--color-gray-200)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = ''}
                    >
                      부서{getSortIcon('department')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {getSortedServers().map((server, index) => (
                    <tr key={server.id} style={{ borderBottom: '1px solid var(--color-gray-200)' }}>
                      <td style={{ padding: '12px', fontSize: '14px' }}>{server.server_id}</td>
                      <td style={{ padding: '12px', fontSize: '14px' }}>{server.ip_address}</td>
                      <td style={{ padding: '12px', fontSize: '14px' }}>{server.company}</td>
                      <td style={{ padding: '12px', fontSize: '14px' }}>{server.os_type}</td>
                      <td style={{ padding: '12px', fontSize: '14px' }}>{server.db_type || '없음'}</td>
                      <td style={{ padding: '12px', fontSize: '14px' }}>{server.manager}</td>
                      <td style={{ padding: '12px', fontSize: '14px' }}>{server.department}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {servers.length === 0 && (
              <div style={{ textAlign: 'center', padding: '40px', color: 'var(--color-gray-400)' }}>
                등록된 서버가 없습니다
              </div>
            )}
          </div>
        )}

        {/* CSV 대량 등록 */}
        {type === 'bulk' && (
          <div className="form-container">
            <div className="section-title">CSV 일괄 업로드</div>
            <div className="alert alert-info">
              📥 템플릿을 다운로드하여 자산 정보를 입력한 후 업로드하세요
            </div>

            <button className="download-btn" onClick={downloadTemplate}>
              📥 템플릿 다운로드
            </button>

            <div
              className={`upload-area ${isDragging ? 'dragging' : ''}`}
              onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
              onDragEnter={e => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
            >
              <input type="file" accept=".csv" onChange={handleCsvUpload} id="csv-upload" />
              <label htmlFor="csv-upload" className="upload-label">
                {isDragging ? '여기에 파일을 놓으세요' : csvFile ? `📄 ${csvFile.name}` : '📁 CSV 파일을 선택하거나 드래그하세요'}
              </label>
            </div>

            {csvData.length > 0 && !bulkResults && (
              <>
                <div className="alert alert-info">
                  총 {csvData.length}건의 자산이 업로드되었습니다
                </div>
                <div className="csv-preview">
                  <table>
                    <thead>
                      <tr>
                        {Object.keys(csvData[0] || {}).map(key => (
                          <th key={key}>{key}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {csvData.slice(0, 10).map((row, i) => (
                        <tr key={i}>
                          {Object.values(row).map((val: any, j) => (
                            <td key={j}>{val}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <button
                  className="register-btn"
                  onClick={handleBulkRegister}
                  disabled={bulkRegistering}
                >
                  {bulkRegistering ? '등록 중...' : `일괄 등록 실행 (${csvData.length}건)`}
                </button>
              </>
            )}

            {/* 일괄 등록 결과 */}
            {bulkResults && (
              <div style={{ marginTop: '20px' }}>
                <div className={`alert ${bulkResults.some(r => r.status === 'fail') ? 'alert-info' : 'alert-success'}`} style={{ marginBottom: '12px' }}>
                  결과: {bulkResults.filter(r => r.status === 'success').length}건 성공
                  {bulkResults.filter(r => r.status === 'fail').length > 0 &&
                    ` / ${bulkResults.filter(r => r.status === 'fail').length}건 실패`}
                </div>
                <div className="csv-preview">
                  <table>
                    <thead>
                      <tr>
                        <th>서버명</th>
                        <th>IP주소</th>
                        <th>SSH</th>
                        <th>상태</th>
                        <th>메시지</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bulkResults.map((r: any, i: number) => (
                        <tr key={i} style={{ background: r.status === 'fail' ? '#FFF5F5' : undefined }}>
                          <td>{r.server_id}</td>
                          <td>{r.ip_address}</td>
                          <td style={{ color: r.ssh_ok ? '#00C471' : '#F04452', fontWeight: 600 }}>
                            {r.ssh_ok ? '연결됨' : '실패'}
                          </td>
                          <td>
                            <span style={{
                              padding: '3px 10px',
                              borderRadius: '6px',
                              fontSize: '12px',
                              fontWeight: 600,
                              background: r.status === 'success' ? '#E8F5E8' : '#FFEAEA',
                              color: r.status === 'success' ? '#00C471' : '#F04452',
                            }}>
                              {r.status === 'success' ? '성공' : '실패'}
                            </span>
                          </td>
                          <td style={{ fontSize: '12px', color: r.status === 'fail' ? '#F04452' : '#6B7684' }}>
                            {r.message}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <button
                  className="register-btn"
                  onClick={() => navigate('/assets')}
                  style={{ marginTop: '16px' }}
                >
                  자산 목록으로 이동
                </button>
              </div>
            )}
          </div>
        )}
      </div>

    </div>
  );
}
