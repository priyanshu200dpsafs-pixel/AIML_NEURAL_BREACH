import React, { useState } from 'react';
import { api, setAuthToken, setSessionUser } from '../services/api';
import { Shield, Lock, Mail, ArrowRight, CheckCircle2, AlertCircle, Building, User } from 'lucide-react';

export default function Login({ onLoginSuccess }) {
  const [activeMode, setActiveMode] = useState('quick'); // 'quick' | 'account' | 'register'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // 1-Click Instant SOC Analyst Evaluation
  const handleQuickLaunch = () => {
    const user = {
      email: 'evaluator.soc@neuralbreach.local',
      name: 'Professor / SOC Evaluator',
      role: 'Senior SOC Analyst (Observer)',
      org: 'Academic Evaluation Unit'
    };
    setSessionUser(user);
    onLoginSuccess(user);
  };

  // Real Enterprise Authentication via /api/v1/auth/login
  const handleAccountLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await api.login(email, password);
      if (res.access_token) {
        setAuthToken(res.access_token);
        const user = {
          email,
          name: email.split('@')[0],
          role: 'Platform Member',
          token: res.access_token
        };
        setSessionUser(user);
        onLoginSuccess(user);
      } else {
        throw new Error('No access token received from authentication endpoint.');
      }
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  // Real Enterprise Registration via /api/v1/auth/register
  const handleAccountRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await api.register(email, password, orgName || 'Default Org', displayName || email.split('@')[0]);
      if (res.access_token) {
        setAuthToken(res.access_token);
        const user = {
          email,
          name: displayName || email.split('@')[0],
          role: 'Organization Admin',
          token: res.access_token
        };
        setSessionUser(user);
        onLoginSuccess(user);
      }
    } catch (err) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b12] flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden">
      {/* Background Cyber Grid Accent */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-20 pointer-events-none"></div>

      {/* Main Login Card */}
      <div className="w-full max-w-md bg-[#0e1726] border border-[#1b283d] rounded-xl shadow-2xl p-8 space-y-6 relative z-10">
        
        {/* Branding Header */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 flex items-center justify-center mx-auto shadow-[0_0_20px_rgba(0,240,255,0.25)]">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-white">TEAM NEURAL BREACH</h1>
          <p className="text-xs text-slate-400">AI/ML-Powered Intrusion Defense & Threat Intelligence Platform</p>
        </div>

        {/* Governance Notice */}
        <div className="p-2.5 bg-indigo-950/40 border border-indigo-800/40 rounded text-center text-xs text-indigo-200">
          <span className="font-semibold text-cyan-300">OBSERVE-ONLY GOVERNANCE:</span> Automated packet blocking is disabled.
        </div>

        {/* Mode Selector */}
        <div className="bg-slate-900 p-1 rounded-lg border border-slate-800 flex text-xs">
          <button
            onClick={() => { setActiveMode('quick'); setError(null); }}
            className={`flex-1 py-1.5 rounded-md font-medium transition ${
              activeMode === 'quick' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400'
            }`}
          >
            1-Click Evaluator
          </button>
          <button
            onClick={() => { setActiveMode('account'); setError(null); }}
            className={`flex-1 py-1.5 rounded-md font-medium transition ${
              activeMode === 'account' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400'
            }`}
          >
            Platform Sign In
          </button>
          <button
            onClick={() => { setActiveMode('register'); setError(null); }}
            className={`flex-1 py-1.5 rounded-md font-medium transition ${
              activeMode === 'register' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400'
            }`}
          >
            Register Org
          </button>
        </div>

        {error && (
          <div className="p-3 bg-rose-950/40 border border-rose-800/50 rounded text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Mode 1: 1-Click Evaluator */}
        {activeMode === 'quick' && (
          <div className="space-y-4 pt-2">
            <p className="text-xs text-slate-400 leading-relaxed text-center">
              Designed for direct academic evaluation. Launches a pre-authorized observer session with full access to live telemetry, inference engines, and SHAP diagnostics without password friction.
            </p>

            <button
              onClick={handleQuickLaunch}
              className="btn-cyber w-full justify-center py-2.5 text-sm font-semibold shadow-[0_0_15px_rgba(0,240,255,0.2)]"
            >
              <span>Launch SOC Analyst Console</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            <div className="text-center pt-2">
              <span className="text-[11px] text-slate-500 font-mono">Role: Senior SOC Analyst (Observer)</span>
            </div>
          </div>
        )}

        {/* Mode 2: Multi-Tenant Sign In */}
        {activeMode === 'account' && (
          <form onSubmit={handleAccountLogin} className="space-y-4 pt-2">
            <div className="space-y-1">
              <label className="text-xs text-slate-300 font-medium">Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="email"
                  required
                  placeholder="analyst@neuralbreach.org"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-soc pl-9 text-xs"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-slate-300 font-medium">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-soc pl-9 text-xs"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-cyber w-full justify-center py-2 text-xs font-semibold"
            >
              {loading ? 'Authenticating...' : 'Sign In via Platform Auth'}
            </button>
          </form>
        )}

        {/* Mode 3: Multi-Tenant Registration */}
        {activeMode === 'register' && (
          <form onSubmit={handleAccountRegister} className="space-y-3 pt-2">
            <div className="space-y-1">
              <label className="text-xs text-slate-300 font-medium">Organization Name</label>
              <div className="relative">
                <Building className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  required
                  placeholder="Acme Security SOC"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  className="input-soc pl-9 text-xs"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-slate-300 font-medium">Display Name</label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Jane Analyst"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="input-soc pl-9 text-xs"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-slate-300 font-medium">Work Email</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="email"
                  required
                  placeholder="jane@acme-soc.org"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-soc pl-9 text-xs"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-slate-300 font-medium">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="password"
                  required
                  placeholder="Minimum 8 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-soc pl-9 text-xs"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-cyber w-full justify-center py-2 text-xs font-semibold"
            >
              {loading ? 'Creating Organization...' : 'Register Organization & Tenant'}
            </button>
          </form>
        )}

        <div className="pt-2 text-center text-[10px] text-slate-500 border-t border-slate-800/80">
          Team Neural Breach • Research Prototype v2.0 • Observe-Only Mode
        </div>
      </div>
    </div>
  );
}

