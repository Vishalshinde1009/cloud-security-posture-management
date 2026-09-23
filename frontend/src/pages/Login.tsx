import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Shield, Lock, User, Eye, EyeOff, AlertCircle, CheckCircle2, Loader2, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Login: React.FC = () => {
  const location = useLocation();
  const [identifier, setIdentifier] = useState(
    (location.state as { prefillIdentifier?: string })?.prefillIdentifier || ''
  );
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success] = useState<string | null>(
    (location.state as { registeredMessage?: string })?.registeredMessage || null
  );
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier || !password) {
      setError('Please enter both your username/email and password.');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      await login({ username_or_email: identifier, password });
      navigate(from, { replace: true });
    } catch (err: unknown) {
      const errorObj = err as { response?: { data?: { detail?: string } } };
      setError(errorObj.response?.data?.detail || 'Authentication failed. Please check your credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#080C14] cyber-grid-bg flex flex-col justify-center items-center p-4 relative overflow-hidden">
      {/* Background Decorative Ambient Glows */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-10 right-10 w-72 h-72 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md relative z-10 space-y-6">
        {/* Header Branding */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center p-3.5 bg-gradient-to-br from-cyan-500/20 to-blue-600/10 border border-cyan-500/30 rounded-2xl text-cyan-400 shadow-glow-cyan mb-2">
            <Shield className="w-9 h-9" />
          </div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
            Cloud Security <span className="text-gradient-cyan">Posture</span>
          </h1>
          <p className="text-xs md:text-sm text-slate-400">
            Sign in to access the automated cloud security posture engine
          </p>
        </div>

        {/* Login Card */}
        <div className="glass-panel rounded-2xl p-6 md:p-8 shadow-2xl space-y-6 border border-slate-800/80 backdrop-blur-xl">
          {/* Success Banner (e.g. from registration redirect) */}
          {success && (
            <div className="p-3.5 bg-emerald-950/40 border border-emerald-800/60 rounded-xl flex items-start gap-3 text-emerald-300 text-sm">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
              <span>{success}</span>
            </div>
          )}

          {error && (
            <div className="p-3.5 bg-red-950/40 border border-red-800/60 rounded-xl flex items-start gap-3 text-red-300 text-sm">
              <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username / Email Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Username or Email
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  placeholder="name@company.com or username"
                  required
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-950/80 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition"
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full pl-10 pr-10 py-2.5 bg-slate-950/80 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:from-slate-800 disabled:to-slate-800 text-white text-sm font-semibold rounded-xl flex items-center justify-center gap-2 shadow-glow-cyan hover:shadow-glow-cyan transition duration-150"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Sign Up Link */}
          <div className="pt-3 text-center border-t border-slate-800/80">
            <span className="text-xs text-slate-400">Don't have an account? </span>
            <Link
              to="/register"
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition"
            >
              Sign up
            </Link>
          </div>
        </div>

        {/* Security Trust Badges */}
        <div className="flex items-center justify-center gap-4 text-[11px] text-slate-500 pt-1">
          <span className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-cyan-400" /> Zero Secret Storage
          </span>
          <span>•</span>
          <span className="flex items-center gap-1">
            <Shield className="w-3 h-3 text-blue-400" /> Read-Only Scans
          </span>
          <span>•</span>
          <span>STS AssumeRole</span>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-slate-500">
          Cloud Security Posture Management • Phase 3 RBAC Enabled
        </p>
      </div>
    </div>
  );
};
