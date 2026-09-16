import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import AuthLayout from '../layouts/AuthLayout';
import { useToast } from '../components/Toast';
import { User, Mail, Lock, Briefcase, ShieldAlert, AlertTriangle, Eye, EyeOff, Sparkles, Check, X } from 'lucide-react';
import { evaluatePasswordStrength, getPasswordRulesStatus, generateStrongPassword, isPasswordStrong } from '../utils/passwordUtils';

const REGISTRATION_ROLES = ['VIEWER', 'ANALYST'];

export default function Register() {
  const { register } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [department, setDepartment] = useState('');
  const [role, setRole] = useState('VIEWER');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const strength = evaluatePasswordStrength(password);
  const rulesStatus = getPasswordRulesStatus(password);

  const handleSuggestPassword = () => {
    const suggested = generateStrongPassword();
    setPassword(suggested);
    setShowPassword(true);
    showToast({ type: 'info', message: 'Strong password generated & inserted!' });
  };

  const validate = () => {
    if (!name) {
      setError('Full Name is required');
      return false;
    }
    if (!email) {
      setError('Email address is required');
      return false;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid email address');
      return false;
    }
    if (!password) {
      setError('Password is required');
      return false;
    }
    if (!isPasswordStrong(password)) {
      setError('Password does not meet required security criteria. Please use at least 8 characters, uppercase, lowercase, number, and special character.');
      return false;
    }
    if (!department) {
      setError('Department is required');
      return false;
    }
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!validate()) return;
    if (!REGISTRATION_ROLES.includes(role)) {
      setError('Only analyst and viewer accounts can be registered.');
      return;
    }

    setLoading(true);
    try {
      await register(name, email, password, role, department);
      showToast({ type: 'success', message: 'Registration successful. Please log in.' });
      navigate('/login');
    } catch (err) {
      const message = err.message || 'Registration failed. Please check inputs.';
      setError(message);
      showToast({ type: 'error', message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <form onSubmit={handleSubmit} className="space-y-4 sc-fade-in">
        {error && (
          <div className="flex items-center space-x-2 rounded-2xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div>
          <label className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">Full Name</label>
          <div className="relative">
            <User className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Your Full Name"
              className="glass-input w-full px-4 py-3 pl-11 text-sm"
              disabled={loading}
            />
          </div>
        </div>

        <div>
          <label className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">Email</label>
          <div className="relative">
            <Mail className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@sentinelcore.in"
              className="glass-input w-full px-4 py-3 pl-11 text-sm"
              disabled={loading}
            />
          </div>
        </div>

        <div>
          <label className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">Department</label>
          <div className="relative">
            <Briefcase className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <select
              value={department}
              onChange={(e) => setDepartment(e.target.value)}
              className="glass-input w-full appearance-none cursor-pointer bg-[#0b1220] px-4 py-3 pl-11 text-sm text-white"
              disabled={loading}
            >
              <option value="">Select Department</option>
              <option value="Developer">Developer</option>
              <option value="IT Support">IT Support</option>
              <option value="QA">QA</option>
              <option value="HR">HR</option>
              <option value="Finance">Finance</option>
              <option value="Sales&Marketing">Sales & Marketing</option>
            </select>
          </div>
        </div>

        <div>
          <label className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">Role</label>
          <div className="relative">
            <ShieldAlert className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="glass-input w-full appearance-none cursor-pointer bg-[#0b1220] px-4 py-3 pl-11 text-sm text-white"
              disabled={loading}
            >
              {REGISTRATION_ROLES.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">Password</label>
            <button
              type="button"
              onClick={handleSuggestPassword}
              className="flex items-center space-x-1 text-xs text-sky-400 hover:text-sky-300 font-medium transition cursor-pointer"
            >
              <Sparkles className="h-3.5 w-3.5" />
              <span>Suggest Password</span>
            </button>
          </div>
          <div className="relative">
            <Lock className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Create a strong password"
              className="glass-input w-full px-4 py-3 pl-11 pr-10 text-sm"
              disabled={loading}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition cursor-pointer"
              tabIndex={-1}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>

          {/* Dynamic Password Strength Indicator */}
          {password.length > 0 && (
            <div className="mt-3 space-y-2 rounded-xl bg-slate-900/60 p-3 border border-white/5">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400 font-medium">Password Strength:</span>
                <span className={`font-bold font-mono ${strength.textClass}`}>{strength.label}</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 ${strength.color}`}
                  style={{ width: `${strength.score}%` }}
                />
              </div>

              {/* Rules checklist */}
              <div className="pt-1.5 grid grid-cols-1 gap-1 text-xs">
                {rulesStatus.map((rule) => (
                  <div key={rule.id} className="flex items-center space-x-2">
                    {rule.passed ? (
                      <Check className="h-3.5 w-3.5 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <X className="h-3.5 w-3.5 text-slate-500 flex-shrink-0" />
                    )}
                    <span className={rule.passed ? 'text-emerald-300 font-medium' : 'text-slate-400'}>
                      {rule.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <button
          type="submit"
          disabled={loading}
          className="sc-button-primary mt-2 w-full px-4 py-3 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? (
            <>
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent"></span>
              <span>Creating account...</span>
            </>
          ) : (
            <span>Register</span>
          )}
        </button>

        <div className="mt-4 text-center">
          <p className="text-xs text-slate-400">
            Already registered?{' '}
            <Link to="/login" className="font-semibold text-sky-300 transition hover:text-sky-200">
              Log In
            </Link>
          </p>
        </div>
      </form>
    </AuthLayout>
  );
}
