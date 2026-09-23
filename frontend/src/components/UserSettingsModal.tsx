import React, { useState, useEffect } from 'react';
import { 
  X, 
  Mail, 
  Check, 
  AlertCircle, 
  CheckCircle2, 
  Loader2, 
  Lock, 
  ShieldCheck,
  User as UserIcon,
  Bell
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

interface UserSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const UserSettingsModal: React.FC<UserSettingsModalProps> = ({ isOpen, onClose }) => {
  const { user } = useAuth();
  const [emailAlertsEnabled, setEmailAlertsEnabled] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [saving, setSaving] = useState<boolean>(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setSuccessMsg(null);
      setErrorMsg(null);
      setLoading(true);
      api.get('/auth/preferences')
        .then((res) => {
          setEmailAlertsEnabled(res.data.email_alerts_enabled);
        })
        .catch(() => {
          if (user?.email_alerts_enabled !== undefined) {
            setEmailAlertsEnabled(user.email_alerts_enabled);
          }
        })
        .finally(() => {
          setLoading(false);
        });
    }
  }, [isOpen, user]);

  if (!isOpen || !user) return null;

  const handleSave = async () => {
    setSaving(true);
    setSuccessMsg(null);
    setErrorMsg(null);
    try {
      const res = await api.put('/auth/preferences', {
        email_alerts_enabled: emailAlertsEnabled,
      });
      setEmailAlertsEnabled(res.data.email_alerts_enabled);
      setSuccessMsg('Preferences saved successfully.');
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Failed to update preferences.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#111827] border border-gray-800 rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-gray-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">Security Alert Preferences</h3>
              <p className="text-xs text-gray-400">Manage your tenant-isolated notification settings</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* User Account Info (Read-Only) */}
        <div className="bg-gray-900/60 border border-gray-800/80 rounded-xl p-3.5 space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-gray-400 flex items-center gap-1.5 font-medium">
              <UserIcon className="w-3.5 h-3.5 text-gray-400" />
              Authenticated User:
            </span>
            <span className="text-white font-semibold font-mono">{user.username}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-400 flex items-center gap-1.5 font-medium">
              <Mail className="w-3.5 h-3.5 text-gray-400" />
              Recipient Email:
            </span>
            <div className="flex items-center gap-1.5">
              <span className="text-gray-200 font-mono font-medium select-all">{user.email}</span>
              <span className="flex items-center gap-1 text-[10px] text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded border border-gray-700">
                <Lock className="w-2.5 h-2.5" /> Registered
              </span>
            </div>
          </div>
          <p className="text-[11px] text-gray-500 pt-1 border-t border-gray-800/60 leading-relaxed">
            Security notifications are delivered exclusively to your authenticated registered email for tenant confidentiality.
          </p>
        </div>

        {/* Feedback Alerts */}
        {successMsg && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs rounded-xl flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}
        {errorMsg && (
          <div className="p-3 bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs rounded-xl flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* EMAIL SECURITY ALERTS Section */}
        <div className="bg-[#0F172A] border border-gray-800 rounded-xl p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-1.5">
                <Bell className="w-3.5 h-3.5 text-cyan-400" />
                EMAIL SECURITY ALERTS
              </div>
              <p className="text-[11px] text-gray-400">
                Automatic dispatch to your verified account email
              </p>
            </div>

            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            ) : (
              <button
                type="button"
                onClick={() => setEmailAlertsEnabled(!emailAlertsEnabled)}
                className={`px-3 py-1 text-xs font-mono font-bold rounded-lg border transition flex items-center gap-1.5 ${
                  emailAlertsEnabled
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                    : 'bg-gray-800 text-gray-400 border-gray-700 hover:bg-gray-750'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    emailAlertsEnabled ? 'bg-emerald-400 animate-pulse' : 'bg-gray-500'
                  }`}
                />
                {emailAlertsEnabled ? 'ON' : 'OFF'}
              </button>
            )}
          </div>

          <div className="space-y-2 pt-2 border-t border-gray-800 text-xs">
            <span className="text-gray-300 font-medium block">
              Receive email notifications for:
            </span>
            <ul className="space-y-1.5 text-[11px] text-gray-400">
              <li className="flex items-center gap-2">
                <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span><strong>HIGH / CRITICAL</strong> new findings</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Significant risk increases (reaching HIGH or CRITICAL)</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Continuous monitoring cloud scan failures</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-gray-800">
          <div className="text-[11px] text-gray-500 font-mono flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            Tenant-Isolated Preferences
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-semibold rounded-lg transition"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={saving || loading}
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow transition flex items-center gap-1.5 disabled:opacity-50"
            >
              {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              Save Preferences
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
