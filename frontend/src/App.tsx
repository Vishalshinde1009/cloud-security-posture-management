import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, NavLink, Outlet } from 'react-router-dom';
import { 
  Shield, 
  Server, 
  CheckCircle, 
  AlertTriangle, 
  Cloud, 
  Activity, 
  Terminal, 
  LogOut, 
  UserCheck, 
  Lock,
  Eye,
  Sliders,
  Layers,
  Radio,
  ShieldAlert,
  BookOpen
} from 'lucide-react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
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
        Cloud Security Posture Management (CSPM) Platform &bull; Academic Cybersecurity Project &bull; Phase 4 Completed
      </footer>
    </div>
  );
}

function DashboardContent() {
  const { user, hasRole } = useAuth();
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get<HealthData>('/health')
      .then((res) => {
        setHealth(res.data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="rounded-xl border border-blue-900/40 bg-gradient-to-r from-blue-950/40 via-indigo-950/20 to-gray-900/60 p-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase font-semibold tracking-wider text-blue-400 font-mono">
                Final Year Cybersecurity Project
              </span>
              <span className="text-xs text-gray-400">&bull;</span>
              <span className="text-xs text-emerald-400 font-mono">Phase 4 Scanner Active</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              Enterprise Cloud Security Posture Engine
            </h2>
            <p className="text-sm text-gray-300 max-w-3xl">
              Authenticated session for <strong className="text-white">{user?.username}</strong> with roles{' '}
              <strong className="text-blue-400 font-mono">[{user?.roles?.join(', ')}]</strong>. 
              Safe Mock scanner pipeline ready for automated asset discovery.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-3 py-1.5 rounded-lg bg-emerald-950/50 border border-emerald-800/50 text-emerald-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              Session Authenticated
            </span>
          </div>
        </div>
      </div>

      {/* Role-Based Capabilities Matrix */}
      <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-2">
            <Sliders className="w-4 h-4 text-blue-400" />
            Role Permissions & Capabilities
          </span>
          <span className="text-xs font-mono text-gray-400">
            Active Persona: <span className="text-white font-semibold">{user?.roles?.[0] || 'VIEWER'}</span>
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className={`p-4 rounded-xl border ${hasRole('ADMIN') ? 'border-purple-500/40 bg-purple-950/20' : 'border-gray-800 bg-gray-900/40 opacity-50'}`}>
            <div className="font-semibold text-purple-400 mb-2 flex items-center justify-between">
              <span>ADMIN</span>
              {hasRole('ADMIN') && <span className="text-[10px] bg-purple-500/20 px-1.5 py-0.5 rounded">Active</span>}
            </div>
            <ul className="space-y-1 text-gray-300">
              <li>&bull; Full platform administration</li>
              <li>&bull; Manage users & system roles</li>
              <li>&bull; Manage cloud accounts & credentials</li>
              <li>&bull; Enable/disable security rules</li>
              <li>&bull; Run scans & view audit logs</li>
            </ul>
          </div>

          <div className={`p-4 rounded-xl border ${hasRole(['ADMIN', 'SECURITY_ANALYST']) ? 'border-blue-500/40 bg-blue-950/20' : 'border-gray-800 bg-gray-900/40 opacity-50'}`}>
            <div className="font-semibold text-blue-400 mb-2 flex items-center justify-between">
              <span>SECURITY_ANALYST</span>
              {hasRole('SECURITY_ANALYST') && <span className="text-[10px] bg-blue-500/20 px-1.5 py-0.5 rounded">Active</span>}
            </div>
            <ul className="space-y-1 text-gray-300">
              <li>&bull; Execute on-demand cloud scans</li>
              <li>&bull; Inspect findings & technical evidence</li>
              <li>&bull; Update finding status & remediation</li>
              <li>&bull; Generate security posture reports</li>
              <li>&bull; View CIS benchmark compliance</li>
            </ul>
          </div>

          <div className="p-4 rounded-xl border border-gray-700 bg-gray-900/60">
            <div className="font-semibold text-emerald-400 mb-2 flex items-center justify-between">
              <span>VIEWER</span>
              <span className="text-[10px] bg-emerald-500/20 px-1.5 py-0.5 rounded">Active</span>
            </div>
            <ul className="space-y-1 text-gray-300">
              <li>&bull; Access security dashboard</li>
              <li>&bull; View discovered cloud inventory</li>
              <li>&bull; View detection rules & findings</li>
              <li>&bull; View compliance summary</li>
              <li>&bull; Read-only access enforced</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">FastAPI Backend</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <Activity className="w-4 h-4 animate-spin text-blue-400" /> Checking API connectivity...
            </div>
          ) : error ? (
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-red-400 text-sm font-medium">
                <AlertTriangle className="w-4 h-4" /> API Offline
              </div>
              <p className="text-xs text-gray-400 font-mono">{error}</p>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium">
                <CheckCircle className="w-4 h-4" /> Connected & Healthy
              </div>
              <div className="text-xs space-y-1 font-mono text-gray-400">
                <div>Service: <span className="text-gray-200">{health?.service}</span></div>
                <div>Version: <span className="text-gray-200">{health?.version}</span></div>
                <div>Environment: <span className="text-gray-200">{health?.environment}</span></div>
              </div>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Cloud Target Scope</span>
            <Terminal className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="space-y-2">
            <div className="text-sm font-medium text-gray-200">6 AWS Services Supported</div>
            <div className="flex flex-wrap gap-1.5">
              {['S3 Storage', 'IAM Identity', 'EC2 Compute', 'VPC Network', 'CloudTrail Audit', 'RDS Database'].map((svc) => (
                <span key={svc} className="text-xs px-2 py-1 rounded bg-gray-800/80 border border-gray-700 text-gray-300 font-mono">
                  {svc}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Authentication Security</span>
            <Eye className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-xs space-y-2 text-gray-300">
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Bcrypt password hashing active</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>JWT tokens with 60-min expiration</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>SOC audit logging for auth & scan events</span>
            </div>
          </div>
        </div>
      </div>
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
            <Route path="/dashboard" element={<DashboardContent />} />
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
