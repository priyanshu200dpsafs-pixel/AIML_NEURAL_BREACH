import React from 'react';
import { Shield, Activity, Radio, AlertTriangle, Search, BarChart3, Cpu, PlayCircle, LogOut } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, wsStatus, sessionUser, onLogout }) {
  const tabs = [
    { id: 'dashboard', label: 'SOC Overview', icon: Activity },
    { id: 'alerts', label: 'Alert Feed', icon: Radio },
    { id: 'investigate', label: 'Investigation', icon: Search },
    { id: 'analytics', label: 'Analytics', icon: BarChart3 },
    { id: 'health', label: 'System Health', icon: Cpu },
    { id: 'demo', label: 'Demo Scenarios', icon: PlayCircle },
  ];

  return (
    <header className="border-b border-[#1b283d] bg-[#09101b] sticky top-0 z-50">
      {/* Observe-Only Governance Banner */}
      <div className="observe-only-banner">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-semibold text-slate-200">OBSERVE-ONLY GOVERNANCE INVARIANT:</span>
          <span className="text-slate-400">Automated packet blocking is permanently disabled. Action enforced:</span>
          <code className="text-cyan-300 font-mono bg-cyan-950/60 px-1.5 py-0.5 rounded text-[11px] border border-cyan-800/50">NONE_OBSERVE_ONLY</code>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[11px] text-slate-400">Research Prototype v2.0</span>
          <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
            <span className={`w-2 h-2 rounded-full ${wsStatus === 'CONNECTED' ? 'bg-emerald-400 shadow-[0_0_8px_#10b981]' : 'bg-amber-400'}`}></span>
            <span className="font-mono text-slate-300">WS: {wsStatus}</span>
          </div>
        </div>
      </div>

      {/* Main Header Navigation Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Logo and Brand */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 flex items-center justify-center shadow-[0_0_12px_rgba(0,240,255,0.2)]">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-wider text-base text-white">NEURAL BREACH</span>
                <span className="bg-cyan-500/20 text-cyan-300 text-[10px] font-mono font-semibold px-1.5 py-0.2 rounded border border-cyan-500/30">SOC AI</span>
              </div>
              <p className="text-[10px] text-slate-400 -mt-0.5">Autonomous Intrusion Defense & Explainable AI</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`nav-tab ${isActive ? 'active' : ''}`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>

          {/* User Session Info & Logout */}
          <div className="flex items-center gap-3">
            {sessionUser && (
              <div className="text-right hidden sm:block">
                <div className="text-xs font-semibold text-slate-200">{sessionUser.name || sessionUser.email}</div>
                <div className="text-[10px] text-cyan-400 font-mono">{sessionUser.role || 'SOC Observer'}</div>
              </div>
            )}
            <button
              onClick={onLogout}
              title="Sign Out / Switch Session"
              className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
