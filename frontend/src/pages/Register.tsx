import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { 
  Shield, 
  Lock, 
  User, 
  Mail, 
  Eye, 
  EyeOff, 
  AlertCircle, 
  CheckCircle2, 
  Loader2, 
  ArrowRight,
  ShieldCheck
} from 'lucide-react';
import api from '../services/api';

export const Register: React.FC = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const navigate = useNavigate();

  // Password validation checks for real-time visual feedback
  const hasMinLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasDigitOrSymbol = /[0-9\W_]/.test(password);
  const passwordsMatch = password.length > 0 && password === passwordConfirm;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    // Frontend validation guards
    if (!username.trim() || !email.trim() || !password) {
      setError('Please fill in all required fields.');
      return;
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username.trim())) {
      setError('Username may only contain letters, numbers, underscores, and hyphens.');
      return;
    }

    if (username.trim().length < 3 || username.trim().length > 50) {
      setError('Username must be between 3 and 50 characters.');
      return;
    }

    if (!/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(email.trim())) {
      setError('Please enter a valid email address.');
      return;
    }

    if (!hasMinLength || !hasUppercase || !hasLowercase || !hasDigitOrSymbol) {
      setError('Password does not satisfy security requirements.');
      return;
    }

    if (password !== passwordConfirm) {
      setError('Passwords do not match.');
      return;
    }

    setIsSubmitting(true);

    try {
      const res = await api.post('/auth/register', {
        username: username.trim(),
        email: email.trim().toLowerCase(),
        password,
        password_confirm: passwordConfirm,
      });

      setSuccess(res.data.message || 'Account successfully registered!');

      // Redirect to login after 1.5s with persistent banner
      setTimeout(() => {
        navigate('/login', {
          replace: true,
          state: {
            registeredMessage: 'Registration successful! Please sign in with your new credentials.',
            prefillIdentifier: username.trim(),
          },
        });
      }, 1500);
    } catch (err: unknown) {
      const errorObj = err as { response?: { data?: { detail?: string } } };
      setError(
        errorObj.response?.data?.detail || 'Registration failed. Please verify your details.'
      );
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
            Create <span className="text-gradient-cyan">Account</span>
          </h1>
          <p className="text-xs md:text-sm text-slate-400">
            Sign up to monitor cloud posture and security misconfigurations
          </p>
        </div>

        {/* Register Card */}
        <div className="glass-panel rounded-2xl p-6 md:p-8 shadow-2xl space-y-6 border border-slate-800/80 backdrop-blur-xl">
          {/* Error Banner */}
          {error && (
            <div className="p-3.5 bg-red-950/40 border border-red-800/60 rounded-xl flex items-start gap-3 text-red-300 text-sm">
              <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Success Banner */}
          {success && (
            <div className="p-3.5 bg-emerald-950/40 border border-emerald-800/60 rounded-xl flex items-start gap-3 text-emerald-300 text-sm">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-semibold">{success}</p>
                <p className="text-xs text-emerald-400/80 mt-0.5">Redirecting to sign in page...</p>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="analyst_john"
                  required
                  disabled={isSubmitting || !!success}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-950/80 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition"
                />
              </div>
            </div>

            {/* Email Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@company.com"
                  required
                  disabled={isSubmitting || !!success}
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
                  disabled={isSubmitting || !!success}
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

            {/* Confirm Password Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Confirm Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={passwordConfirm}
                  onChange={(e) => setPasswordConfirm(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  disabled={isSubmitting || !!success}
                  className="w-full pl-10 pr-10 py-2.5 bg-slate-950/80 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition"
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Live Password Policy Checklist */}
            {password.length > 0 && (
              <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl space-y-1.5 text-xs">
                <p className="font-medium text-slate-400 text-[11px] uppercase tracking-wider">Password Requirements:</p>
                <div className="grid grid-cols-2 gap-1 text-[11px]">
                  <span className={`flex items-center gap-1.5 ${hasMinLength ? 'text-emerald-400 font-medium' : 'text-slate-500'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${hasMinLength ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                    8+ characters
                  </span>
                  <span className={`flex items-center gap-1.5 ${hasUppercase ? 'text-emerald-400 font-medium' : 'text-slate-500'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${hasUppercase ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                    1 uppercase letter
                  </span>
                  <span className={`flex items-center gap-1.5 ${hasLowercase ? 'text-emerald-400 font-medium' : 'text-slate-500'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${hasLowercase ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                    1 lowercase letter
                  </span>
                  <span className={`flex items-center gap-1.5 ${hasDigitOrSymbol ? 'text-emerald-400 font-medium' : 'text-slate-500'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${hasDigitOrSymbol ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                    1 number or symbol
                  </span>
                </div>
                {passwordConfirm.length > 0 && (
                  <div className={`pt-1 border-t border-slate-800 flex items-center gap-1.5 text-[11px] ${passwordsMatch ? 'text-emerald-400 font-medium' : 'text-rose-400'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${passwordsMatch ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                    {passwordsMatch ? 'Passwords match' : 'Passwords do not match'}
                  </div>
                )}
              </div>
            )}

            {/* Role Notice */}
            <div className="flex items-center gap-2 p-2.5 bg-cyan-950/30 border border-cyan-800/40 rounded-xl text-cyan-300 text-xs">
              <ShieldCheck className="w-4 h-4 shrink-0 text-cyan-400" />
              <span>New accounts receive isolated read-only <strong>Viewer</strong> role by default.</span>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting || !!success}
              className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:from-slate-800 disabled:to-slate-800 text-white text-sm font-semibold rounded-xl flex items-center justify-center gap-2 shadow-glow-cyan hover:shadow-glow-cyan transition duration-150"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Registering Account...</span>
                </>
              ) : (
                <>
                  <span>Create Account</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Already have an account link */}
          <div className="pt-4 border-t border-slate-800/80 text-center">
            <span className="text-xs text-slate-400">Already have an account? </span>
            <Link
              to="/login"
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition"
            >
              Sign In
            </Link>
          </div>
        </div>

        {/* Security Trust Badges */}
        <div className="flex items-center justify-center gap-4 text-[11px] text-slate-500 pt-1">
          <span className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-cyan-400" /> Tenant Isolated
          </span>
          <span>•</span>
          <span className="flex items-center gap-1">
            <Shield className="w-3 h-3 text-blue-400" /> Read-Only Scans
          </span>
          <span>•</span>
          <span>Zero Secret Storage</span>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-slate-500">
          Cloud Security Posture Management &bull; RBAC Protected
        </p>
      </div>
    </div>
  );
};
