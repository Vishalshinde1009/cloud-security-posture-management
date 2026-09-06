import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, User, Eye, EyeOff, AlertCircle, Loader2, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Login: React.FC = () => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

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

  const fillDemoCredentials = () => {
    setIdentifier('admin@cspm-security.local');
    setPassword('AdminSecurePass123!');
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] flex flex-col justify-center items-center p-4">
      {/* Background Decorative Gradient */}
      <div className="absolute inset-0 bg-gradient-to-tr from-blue-950/20 via-transparent to-indigo-950/20 pointer-events-none" />

      <div className="w-full max-w-md relative z-10 space-y-6">
        {/* Header Branding */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center p-3 bg-blue-600/10 border border-blue-500/30 rounded-2xl text-blue-400 shadow-lg shadow-blue-500/5 mb-2">
            <Shield className="w-9 h-9" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Cloud Security Posture Management
          </h1>
          <p className="text-sm text-gray-400">
            Sign in to access the automated cloud security posture engine
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 md:p-8 shadow-2xl space-y-6 backdrop-blur">
          {error && (
            <div className="p-3.5 bg-red-950/40 border border-red-800/60 rounded-xl flex items-start gap-3 text-red-300 text-sm">
              <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username / Email Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-gray-300 uppercase tracking-wider">
                Username or Email
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-gray-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  placeholder="admin@cspm-security.local"
                  required
                  className="w-full pl-10 pr-4 py-2.5 bg-gray-900/90 border border-gray-700/80 rounded-xl text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition"
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-gray-300 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-gray-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full pl-10 pr-10 py-2.5 bg-gray-900/90 border border-gray-700/80 rounded-xl text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-gray-500 hover:text-gray-300 transition"
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
              className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white text-sm font-semibold rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 hover:shadow-blue-600/30 transition duration-150"
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

          {/* Development Seed Helper */}
          <div className="pt-4 border-t border-gray-800 text-center space-y-2">
            <span className="text-xs text-gray-400">Development / Evaluation Quick-Fill:</span>
            <div>
              <button
                type="button"
                onClick={fillDemoCredentials}
                className="text-xs px-3 py-1 rounded-lg bg-gray-800/80 hover:bg-gray-700 text-blue-400 border border-gray-700 transition"
              >
                Use Seed Admin Credentials
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-500">
          Cloud Security Posture Management • Phase 3 RBAC Enabled
        </p>
      </div>
    </div>
  );
};
