import React, { useState, useEffect, useRef } from 'react';
import Navbar from './components/Navbar';
import Dashboard from './components/Dashboard';
import AlertFeed from './components/AlertFeed';
import AlertInvestigation from './components/AlertInvestigation';
import Analytics from './components/Analytics';
import SystemHealth from './components/SystemHealth';
import DemoSuite from './components/DemoSuite';
import Login from './components/Login';
import { getSessionUser, setSessionUser, setAuthToken, AlertWebSocket } from './services/api';

export default function App() {
  const [sessionUser, setSessionUserState] = useState(getSessionUser);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [wsStatus, setWsStatus] = useState('DISCONNECTED');
  const [isStreamPaused, setIsStreamPaused] = useState(false);
  const wsRef = useRef(null);

  // Initialize WebSocket Alert Stream
  useEffect(() => {
    if (!sessionUser) return;

    const ws = new AlertWebSocket(
      (newAlert) => {
        if (!isStreamPaused) {
          setLiveAlerts((prev) => [newAlert, ...prev.slice(0, 499)]); // Keep up to 500 in memory
        }
      },
      (status) => {
        setWsStatus(status);
      }
    );

    ws.connect();
    wsRef.current = ws;

    return () => {
      ws.disconnect();
    };
  }, [sessionUser, isStreamPaused]);

  const handleLogout = () => {
    setAuthToken(null);
    setSessionUser(null);
    setSessionUserState(null);
    if (wsRef.current) wsRef.current.disconnect();
  };

  const handleLoginSuccess = (user) => {
    setSessionUserState(user);
    setActiveTab('dashboard');
  };

  const handleSelectAlert = (alert) => {
    setSelectedAlert(alert);
    setActiveTab('investigate');
  };

  const handleClearFeed = () => {
    setLiveAlerts([]);
  };

  if (!sessionUser) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-[#070b12] text-slate-100 flex flex-col">
      {/* Navigation & Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        wsStatus={wsStatus}
        sessionUser={sessionUser}
        onLogout={handleLogout}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'dashboard' && (
          <Dashboard
            liveAlerts={liveAlerts}
            onSelectAlert={handleSelectAlert}
            setActiveTab={setActiveTab}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertFeed
            liveAlerts={liveAlerts}
            onSelectAlert={handleSelectAlert}
            setActiveTab={setActiveTab}
            isStreamPaused={isStreamPaused}
            setIsStreamPaused={setIsStreamPaused}
            onClearFeed={handleClearFeed}
          />
        )}

        {activeTab === 'investigate' && (
          <AlertInvestigation
            selectedAlert={selectedAlert}
            liveAlerts={liveAlerts}
            onSelectAlert={handleSelectAlert}
            setActiveTab={setActiveTab}
          />
        )}

        {activeTab === 'analytics' && (
          <Analytics
            liveAlerts={liveAlerts}
          />
        )}

        {activeTab === 'health' && (
          <SystemHealth />
        )}

        {activeTab === 'demo' && (
          <DemoSuite
            onSelectAlert={handleSelectAlert}
            setActiveTab={setActiveTab}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1b283d] bg-[#09101b] py-3 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>Team Neural Breach • AI/ML-Based Network Intrusion Detection & Threat Intelligence Platform</span>
          <span className="font-mono text-[11px] text-slate-400">
            Governance: <span className="text-cyan-400">Observe-Only</span> • Certified Research Prototype
          </span>
        </div>
      </footer>
    </div>
  );
}
