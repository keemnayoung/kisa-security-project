import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { MainDashboard } from './pages/MainDashboard';
import { AssetRegister } from './pages/AssetRegister';
import { AssetAnalysis } from './pages/AssetAnalysis';
import { ChangePassword } from './pages/ChangePassword';
import { AssetList } from './pages/AssetList';
import { History } from './pages/History';
import { ExceptionManagement } from './pages/ExceptionManagement';
import './styles/variables.css';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/change-password" element={<ChangePassword />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/main" element={<MainDashboard />} />
        <Route path="/register" element={<AssetRegister />} />
        <Route path="/analysis" element={<AssetAnalysis />} />
        <Route path="/assets" element={<AssetList />} />
        <Route path="/history" element={<History />} />
        <Route path="/exceptions" element={<ExceptionManagement />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
