import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, NavLink, Outlet } from 'react-router-dom';
import { 
  Shield, 
  Cloud, 
  Activity, 
  LogOut, 
  UserCheck, 
  Layers, 
  Radio, 
  ShieldAlert, 
  BookOpen
} from 'lucide-react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { Scans } from './pages/Scans';
import { Resources } from './pages/Resources';
import { Findings } from './pages/Findings';
import { Rules } from './pages/Rules';
import api from './services/api';

interface HealthData {
  status: string;
  service: string;
  version: string;
  mode: string;
  environment: string;
}

function AppLayout() {
  const { user, logout } = useAuth();
  const [health, setHealth] = useState<HealthData | null>(null);

  useEffect(() => {
    api.get<HealthData>('/health')
      .then((res) => setHealth(res.data))
      .catch(() => {});
  }, []);

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'ADMIN':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
      case 'SECURITY_ANALYST':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      default:
        return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col font-sans">
      {/* Top SOC Navigation Bar */}
      <header className="border-b border-gray-800 bg-[#111827]/90 backdrop-blur px-6 py-3 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 border border-blue-500/30 rounded-lg text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-2">
              Cloud Security Posture Management
              <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono font-normal">
                CSPM v1.0
              </span>
            </h1>
          </div>
        </div>

        {/* User & Status Badges */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full bg-gray-800/80 border border-gray-700 text-xs">
            <Cloud className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-gray-400">Target:</span>
            <span className="font-semibold text-white">AWS</span>
          </div>

          <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full bg-gray-800/80 border border-gray-700 text-xs">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-gray-400">Mode:</span>
            <span className="font-mono font-semibold text-emerald-400 uppercase">
              {health?.mode || 'MOCK'}
            </span>
          </div>

          {user && (
            <div className="flex items-center gap-2 pl-3 border-l border-gray-800">
              <div className="text-right hidden md:block">
                <div className="text-xs font-semibold text-white flex items-center gap-1">
                  <UserCheck className="w-3 h-3 text-emerald-400" />
                  {user.username}
                </div>
                <div className="text-[10px] text-gray-400">{user.email}</div>
              </div>

              {user.roles && user.roles.map((role) => (
                <span 
                  key={role}
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full border uppercase font-semibold ${getRoleBadgeColor(role)}`}
                >
                  {role}
                </span>
              ))}

              <button
                onClick={logout}
                title="Sign Out"
                className="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-red-400 border border-gray-700 transition"
                aria-label="Logout"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Navigation Sub-bar */}
      <nav className="border-b border-gray-800 bg-[#0E131F] px-6">
        <div className="max-w-7xl mx-auto flex items-center gap-1">
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-white bg-blue-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <Activity className="w-3.5 h-3.5" />
            Dashboard
          </NavLink>

          <NavLink
            to="/scans"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-white bg-blue-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <Radio className="w-3.5 h-3.5" />
            Cloud Scans
          </NavLink>

          <NavLink
            to="/resources"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-white bg-blue-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <Layers className="w-3.5 h-3.5" />
            Discovered Assets
          </NavLink>

          <NavLink
            to="/findings"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-white bg-blue-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Findings
          </NavLink>

          <NavLink
            to="/rules"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-white bg-blue-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <BookOpen className="w-3.5 h-3.5" />
            Security Rules
          </NavLink>
        </div>
      </nav>

      {/* Main Page Content */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/80 bg-[#0B0F19] px-6 py-4 text-center text-xs text-gray-400">
        Cloud Security Posture Management (CSPM) Platform &bull; Academic Cybersecurity Project &bull; Phase 6 Completed
      </footer>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/resources" element={<Resources />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/rules" element={<Rules />} />
          </Route>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
