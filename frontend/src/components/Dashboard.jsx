import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { 
  AlertTriangle, ShieldAlert, Cpu, Radio, Activity, Eye, 
  ExternalLink, ArrowUpRight, Zap, RefreshCw, BarChart2, CheckCircle2 
} from 'lucide-react';

export default function Dashboard({ liveAlerts, onSelectAlert, setActiveTab }) {
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchSOCData = async () => {
    try {
      setLoading(true);
      const [statsData, healthData] = await Promise.all([
        api.getStats().catch(() => null),
        api.getHealth().catch(() => null),
      ]);
      setStats(statsData);
      setHealth(healthData);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSOCData();
    const interval = setInterval(fetchSOCData, 10000);
    return () => clearInterval(interval);
  }, []);

  const totalAlerts = stats?.total_alerts_stored ?? liveAlerts.length;
  const criticalCount = stats?.threat_level_counts?.CRITICAL ?? liveAlerts.filter(a => a.threat_level === 'CRITICAL').length;
  const highCount = stats?.threat_level_counts?.HIGH ?? liveAlerts.filter(a => a.threat_level === 'HIGH').length;
  const mediumCount = stats?.threat_level_counts?.MEDIUM ?? liveAlerts.filter(a => a.threat_level === 'MEDIUM').length;
  const lowCount = stats?.threat_level_counts?.LOW ?? liveAlerts.filter(a => a.threat_level === 'LOW').length;
  const totalAnomalies = stats?.total_anomalies ?? liveAlerts.filter(a => a.anomaly_detection?.is_anomaly).length;

  const severityTotal = (criticalCount + highCount + mediumCount + lowCount) || 1;
  const critPct = Math.round((criticalCount / severityTotal) * 100);
  const highPct = Math.round((highCount / severityTotal) * 100);
  const medPct = Math.round((mediumCount / severityTotal) * 100);
  const lowPct = Math.max(0, 100 - (critPct + highPct + medPct));

  return (
    <div className="space-y-6">
      {/* Page Title & Status Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Security Operations Center (SOC) Command Console
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-model intrusion detection, explainable AI diagnostics, and MITRE ATT&CK telemetry.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button 
            onClick={fetchSOCData}
            className="btn-secondary text-xs"
            title="Refresh statistics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>

          <button 
            onClick={() => setActiveTab('demo')}
            className="btn-cyber text-xs"
          >
            <Zap className="w-3.5 h-3.5" />
            Run Live Simulation
          </button>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="kpi-card">
          <span className="kpi-title">Total Alerts</span>
          <span className="kpi-value text-cyan-400">{totalAlerts}</span>
          <span className="text-[11px] text-slate-400">Stored & active</span>
        </div>

        <div className="kpi-card border-rose-900/40 bg-rose-950/10">
          <span className="kpi-title text-rose-400">Critical Threats</span>
          <span className="kpi-value text-rose-400">{criticalCount}</span>
          <span className="text-[11px] text-rose-300/70">Score ≥ 80.0</span>
        </div>

        <div className="kpi-card border-amber-900/40 bg-amber-950/10">
          <span className="kpi-title text-amber-400">High Threats</span>
          <span className="kpi-value text-amber-400">{highCount}</span>
          <span className="text-[11px] text-amber-300/70">Score 60 - 79</span>
        </div>

        <div className="kpi-card border-violet-900/40 bg-violet-950/10">
          <span className="kpi-title text-violet-400">Med / Low</span>
          <span className="kpi-value text-violet-300">{mediumCount + lowCount}</span>
          <span className="text-[11px] text-slate-400">Score &lt; 60.0</span>
        </div>

        <div className="kpi-card border-emerald-900/40 bg-emerald-950/10">
          <span className="kpi-title text-emerald-400">Anomaly Detections</span>
          <span className="kpi-value text-emerald-400">{totalAnomalies}</span>
          <span className="text-[11px] text-emerald-300/70">IF + Autoencoder</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-title">Service Health</span>
          <span className="kpi-value text-emerald-400 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981]"></span>
            {health?.status || 'ONLINE'}
          </span>
          <span className="text-[11px] text-slate-400 font-mono">Uptime: {Math.round(health?.uptime_seconds || 0)}s</span>
        </div>
      </div>

      {/* Main Content Grid: Severity Distribution & Live Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution & Telemetry Overview */}
        <div className="soc-card space-y-4">
          <div className="flex items-center justify-between border-b border-[#1b283d] pb-3">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-cyan-400" />
              Threat Severity Distribution
            </h2>
            <span className="text-[11px] text-slate-400">Composite Score</span>
          </div>

          {/* Stacked Percentage Bar */}
          <div className="space-y-2">
            <div className="h-4 w-full bg-slate-900 rounded overflow-hidden flex">
              <div style={{ width: `${critPct}%` }} className="bg-rose-500 h-full" title={`Critical: ${critPct}%`}></div>
              <div style={{ width: `${highPct}%` }} className="bg-amber-500 h-full" title={`High: ${highPct}%`}></div>
              <div style={{ width: `${medPct}%` }} className="bg-violet-500 h-full" title={`Medium: ${medPct}%`}></div>
              <div style={{ width: `${lowPct}%` }} className="bg-cyan-500 h-full" title={`Low: ${lowPct}%`}></div>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs pt-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded bg-rose-500"></span>
                <span className="text-slate-300">Critical ({criticalCount})</span>
                <span className="text-slate-500 font-mono text-[11px] ml-auto">{critPct}%</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded bg-amber-500"></span>
                <span className="text-slate-300">High ({highCount})</span>
                <span className="text-slate-500 font-mono text-[11px] ml-auto">{highPct}%</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded bg-violet-500"></span>
                <span className="text-slate-300">Medium ({mediumCount})</span>
                <span className="text-slate-500 font-mono text-[11px] ml-auto">{medPct}%</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded bg-cyan-500"></span>
                <span className="text-slate-300">Low/Info ({lowCount})</span>
                <span className="text-slate-500 font-mono text-[11px] ml-auto">{lowPct}%</span>
              </div>
            </div>
          </div>

          {/* Model Pipeline Specs */}
          <div className="border-t border-[#1b283d] pt-3 space-y-2 text-xs">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">Detection Pipeline Engine</span>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Supervised Model</span>
              <span className="font-mono text-cyan-300 font-semibold">{health?.classifier_type?.toUpperCase() || 'LIGHTGBM'}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">FPR Budget Constraint</span>
              <span className="font-mono text-emerald-400">{health?.fpr_budget || '1%'}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Feature Dimensions</span>
              <span className="font-mono text-slate-200">{health?.expected_features_count || 77} Flow Features</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Unsupervised Ensembles</span>
              <span className="font-mono text-slate-200">Isolation Forest + Autoencoder</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Explainable AI</span>
              <span className="font-mono text-violet-300">SHAP TreeExplainer + LIME</span>
            </div>
          </div>
        </div>

        {/* Live Incoming Alert Ticker */}
        <div className="soc-card lg:col-span-2 space-y-3 flex flex-col">
          <div className="flex items-center justify-between border-b border-[#1b283d] pb-3">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
              <h2 className="text-sm font-semibold text-white">Live Threat Detection Feed</h2>
              <span className="text-[11px] bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded font-mono">
                {liveAlerts.length} in stream
              </span>
            </div>
            <button
              onClick={() => setActiveTab('alerts')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
            >
              Full Feed <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex-1 overflow-x-auto min-h-[260px]">
            {liveAlerts.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-8 text-slate-500">
                <Radio className="w-8 h-8 text-slate-600 mb-2 animate-bounce" />
                <p className="text-sm text-slate-400 font-medium">Waiting for live network flows...</p>
                <p className="text-xs text-slate-500 max-w-sm mt-1">
                  Connect to live network ingestion or launch an authorized CSE-CIC-IDS2018 benchmark stream.
                </p>
                <button
                  onClick={() => setActiveTab('demo')}
                  className="mt-4 btn-cyber text-xs"
                >
                  <Zap className="w-3.5 h-3.5" />
                  Launch Benchmark Simulation
                </button>
              </div>
            ) : (
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Threat Level</th>
                    <th>Detection / Attack Type</th>
                    <th>Confidence</th>
                    <th>Priority Score</th>
                    <th>Source / Target</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {liveAlerts.slice(0, 6).map((alert, idx) => {
                    const level = alert.threat_level || alert.threat_priority?.level || 'INFO';
                    const score = alert.composite_priority_score ?? alert.threat_priority?.score ?? 0.0;
                    const attackName = alert.prediction?.label || alert.prediction?.attack_type || alert.attack_type || 'Unknown Flow';
                    const badgeClass = 
                      level === 'CRITICAL' ? 'badge-critical' :
                      level === 'HIGH' ? 'badge-high' :
                      level === 'MEDIUM' ? 'badge-medium' :
                      level === 'LOW' ? 'badge-low' : 'badge-info';

                    return (
                      <tr key={alert.alert_id || idx} className="hover:bg-slate-800/40">
                        <td className="font-mono text-xs text-slate-400 whitespace-nowrap">
                          {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Just now'}
                        </td>
                        <td>
                          <span className={`badge ${badgeClass}`}>{level}</span>
                        </td>
                        <td className="font-semibold text-slate-200">
                          {attackName}
                        </td>
                        <td className="font-mono text-xs text-slate-300">
                          {alert.prediction?.confidence ? `${(alert.prediction.confidence * 100).toFixed(1)}%` : '—'}
                        </td>
                        <td className="font-mono text-xs font-bold text-cyan-400">
                          {typeof score === 'number' ? score.toFixed(1) : score}
                        </td>
                        <td className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
                          {alert.network_context 
                            ? `${alert.network_context.src_ip}:${alert.network_context.src_port}` 
                            : (alert.flow_metadata ? `Flow #${alert.flow_metadata.flow_index}` : '10.0.0.1:443')}
                        </td>
                        <td>
                          <button
                            onClick={() => {
                              onSelectAlert(alert);
                              setActiveTab('investigate');
                            }}
                            className="p-1 rounded bg-slate-800 hover:bg-cyan-950 text-cyan-400 hover:text-cyan-300 transition"
                            title="Investigate with SHAP & MITRE"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Intelligence Mapping Overview */}
      <div className="soc-card space-y-4">
        <div className="flex items-center justify-between border-b border-[#1b283d] pb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-violet-400" />
            <h2 className="text-sm font-semibold text-white">Top MITRE ATT&CK Techniques Correlated</h2>
          </div>
          <span className="text-xs text-slate-400">Enterprise Matrix v14 (STIX 2.1)</span>
        </div>

        {stats?.top_mitre_techniques?.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {stats.top_mitre_techniques.slice(0, 4).map((tech, idx) => (
              <div key={idx} className="p-3 bg-slate-900/60 rounded border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-violet-400">{tech.technique_id}</span>
                    <span className="text-xs font-mono text-slate-400">{tech.count} detections</span>
                  </div>
                  <h3 className="text-xs font-semibold text-slate-200 mt-1">{tech.technique_name}</h3>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
                  <span className="text-slate-500 font-mono">Observe-Only Mode</span>
                  <a 
                    href={`https://attack.mitre.org/techniques/${tech.technique_id.replace('.', '/')}`} 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-cyan-400 hover:underline flex items-center gap-0.5"
                  >
                    MITRE <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-4 bg-slate-900/40 rounded border border-dashed border-slate-800 text-center text-xs text-slate-400">
            MITRE ATT&CK techniques will populate automatically as alerts are ingested or simulated.
          </div>
        )}
      </div>
    </div>
  );
}
