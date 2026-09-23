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
  BookOpen,
  Bell,
  CheckCheck,
  ShieldCheck,
  FileText,
  History,
  Menu,
  X,
  Settings
} from 'lucide-react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { UserSettingsModal } from './components/UserSettingsModal';
import { Landing } from './pages/Landing';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Dashboard } from './pages/Dashboard';
import { Scans } from './pages/Scans';
import { Resources } from './pages/Resources';
import { Findings } from './pages/Findings';
import { Rules } from './pages/Rules';
import { CloudAccounts } from './pages/CloudAccounts';
import { Compliance } from './pages/Compliance';
import { Reports } from './pages/Reports';
import { AuditLogs } from './pages/AuditLogs';
import { Alerts } from './pages/Alerts';
import api from './services/api';
import {
  resolvePreferredAccountId,
  getStoredAccountId,
  getAccountModeLabel,
  getAccountModeStyle,
  onAccountChanged,
  type CloudAccountOption,
} from './utils/accountSelection';

interface HealthData {
  status: string;
  service: string;
  version: string;
  mode: string;
  environment: string;
}

interface NotificationItem {
  id: string;
  title: string;
  message: string;
  notification_type: string;
  severity: string;
  is_read: boolean;
  created_at: string;
}

function AppLayout() {
  const { user, logout } = useAuth();
  const [health, setHealth] = useState<HealthData | null>(null);
  const [selectedAccount, setSelectedAccount] = useState<CloudAccountOption | null>(null);
  const [unreadCount, setUnreadCount] = useState<number>(0);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [showNotifications, setShowNotifications] = useState<boolean>(false);
  const [showSettingsModal, setShowSettingsModal] = useState<boolean>(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  const fetchNotifications = () => {
    api.get('/notifications/unread-count')
      .then((res) => setUnreadCount(res.data.unread_count))
      .catch(() => {});
  };

  const refreshAccount = async () => {
    try {
      const res = await api.get('/cloud-accounts');
      const items: CloudAccountOption[] = Array.isArray(res.data) ? res.data : (res.data?.items || []);
      const storedId = getStoredAccountId();
      const preferredId = resolvePreferredAccountId(items, storedId);
      const acc = items.find((a) => a.id === preferredId) || null;
      setSelectedAccount(acc);
    } catch {
      // Ignore
    }
  };

  useEffect(() => {
    api.get<HealthData>('/health')
      .then((res) => setHealth(res.data))
      .catch(() => {});

    fetchNotifications();
    const interval = setInterval(fetchNotifications, 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (user) {
      refreshAccount();
    }
    const unsubscribe = onAccountChanged((_id, acc) => {
      if (acc) {
        setSelectedAccount(acc);
      } else {
        refreshAccount();
      }
    });
    return () => unsubscribe();
  }, [user]);

  const modeLabel = getAccountModeLabel(selectedAccount, health?.mode);
  const modeStyle = getAccountModeStyle(modeLabel);

  const openNotificationPanel = async () => {
    setShowNotifications(!showNotifications);
    if (!showNotifications) {
      try {
        const res = await api.get('/notifications?limit=10');
        setNotifications(res.data.items);
      } catch (err) {}
    }
  };

  const markAllRead = async () => {
    try {
      await api.post('/notifications/read-all');
      setUnreadCount(0);
      setNotifications(notifications.map((n) => ({ ...n, is_read: true })));
    } catch (err) {}
  };

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
            <span className="font-semibold text-white truncate max-w-[130px]" title={selectedAccount?.name || 'AWS'}>
              {selectedAccount ? selectedAccount.name : (health?.mode?.toLowerCase() === 'aws' ? 'AWS' : 'MOCK')}
            </span>
          </div>

          <div className={`hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs ${modeStyle.badge}`}>
            <span className="relative flex h-2 w-2">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${modeStyle.ping}`}></span>
              <span className={`relative inline-flex rounded-full h-2 w-2 ${modeStyle.dot}`}></span>
            </span>
            <span className="text-gray-400">Mode:</span>
            <span className={`font-mono font-semibold uppercase ${modeStyle.text}`}>
              {modeLabel}
            </span>
          </div>

          {/* Notification Bell Dropdown */}
          <div className="relative">
            <button
              onClick={openNotificationPanel}
              className="relative p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 transition"
              title="Notifications"
            >
              <Bell className="w-4 h-4" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>

            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 rounded-xl border border-gray-800 bg-gray-900 shadow-2xl p-3 z-50 space-y-2">
                <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                  <span className="text-xs font-semibold text-white">In-App Security Alerts</span>
                  {unreadCount > 0 && (
                    <button
                      onClick={markAllRead}
                      className="text-[10px] text-blue-400 hover:underline flex items-center gap-1"
                    >
                      <CheckCheck className="w-3 h-3" /> Mark all read
                    </button>
                  )}
                </div>

                <div className="max-h-72 overflow-y-auto space-y-1.5">
                  {notifications.length === 0 ? (
                    <div className="text-center py-6 text-xs text-gray-500">No recent alerts</div>
                  ) : (
                    notifications.map((n) => (
                      <div
                        key={n.id}
                        className={`p-2.5 rounded-lg border text-xs space-y-1 ${
                          n.is_read
                            ? 'bg-gray-800/40 border-gray-800 text-gray-400'
                            : 'bg-blue-950/30 border-blue-900/50 text-gray-200'
                        }`}
                      >
                        <div className="flex items-center justify-between font-semibold">
                          <span className="text-white text-[11px] truncate max-w-[180px]">{n.title}</span>
                          <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono ${
                            n.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                            n.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>
                            {n.severity}
                          </span>
                        </div>
                        <p className="text-[11px] text-gray-300 leading-snug">{n.message}</p>
                        <div className="text-[9px] text-gray-500 text-right">
                          {new Date(n.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

          {user && (
            <div className="flex items-center gap-2 pl-3 border-l border-gray-800">
              <div 
                onClick={() => setShowSettingsModal(true)}
                className="text-right hidden md:block cursor-pointer hover:opacity-80 transition"
                title="Open Security & Notification Settings"
              >
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
                onClick={() => setShowSettingsModal(true)}
                title="Security & Notification Settings"
                className="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-cyan-400 border border-gray-700 transition"
                aria-label="Notification Settings"
              >
                <Settings className="w-4 h-4" />
              </button>

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

          {/* Mobile Menu Toggle Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 transition"
            aria-label="Toggle Navigation"
          >
            {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </header>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-[#0F172A] border-b border-gray-800 px-6 py-4 space-y-1 z-40">
          {[
            { to: '/dashboard', label: 'Dashboard', icon: Activity },
            { to: '/scans', label: 'Cloud Scans', icon: Radio },
            { to: '/resources', label: 'Discovered Assets', icon: Layers },
            { to: '/findings', label: 'Findings', icon: ShieldAlert },
            { to: '/alerts', label: 'Alerts', icon: Bell },
            { to: '/compliance', label: 'Compliance', icon: ShieldCheck },
            { to: '/rules', label: 'Security Rules', icon: BookOpen },
            { to: '/reports', label: 'Reports', icon: FileText },
            { to: '/audit-logs', label: 'Audit Logs', icon: History },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                      : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                  }`
                }
              >
                <Icon className="w-4 h-4" />
                {item.label}
              </NavLink>
            );
          })}
          <button
            onClick={() => {
              setMobileMenuOpen(false);
              setShowSettingsModal(true);
            }}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-gray-400 hover:text-white hover:bg-gray-800/50 transition-colors"
          >
            <Settings className="w-4 h-4 text-cyan-400" />
            Security & Notification Settings
          </button>
        </div>
      )}

      {/* Navigation Sub-bar (Desktop & Tablet) */}
      <nav className="hidden md:block border-b border-gray-800 bg-[#0E131F] px-6 overflow-x-auto">
        <div className="max-w-7xl mx-auto flex items-center gap-1 min-w-max">
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-cyan-500 text-white bg-cyan-500/5'
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
                  ? 'border-cyan-500 text-white bg-cyan-500/5'
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
            to="/alerts"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-cyan-500 text-white bg-cyan-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <Bell className="w-3.5 h-3.5" />
            Alerts
          </NavLink>

          <NavLink
            to="/compliance"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-white bg-blue-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            Compliance
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

          <NavLink
            to="/reports"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-white bg-blue-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <FileText className="w-3.5 h-3.5" />
            Reports
          </NavLink>

          <NavLink
            to="/audit-logs"
            className={({ isActive }) =>
              `px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-white bg-blue-500/5'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`
            }
          >
            <History className="w-3.5 h-3.5" />
            Audit Logs
          </NavLink>
        </div>
      </nav>

      {/* Main Page Content */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/80 bg-[#0B0F19] px-6 py-4 text-center text-xs text-gray-400">
        Cloud Security Posture Management (CSPM) Platform &bull; Academic Cybersecurity Project &bull; Production Ready
      </footer>

      {/* User Security & Notification Preferences Modal */}
      <UserSettingsModal
        isOpen={showSettingsModal}
        onClose={() => setShowSettingsModal(false)}
      />
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/signup" element={<Navigate to="/register" replace />} />
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
            <Route path="/assets" element={<Resources />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/security-rules" element={<Rules />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/audit-logs" element={<AuditLogs />} />
            <Route path="/accounts" element={<CloudAccounts />} />
            <Route path="/cloud-accounts" element={<CloudAccounts />} />
          </Route>
          <Route path="/" element={<Landing />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
