import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { BarChart3, PieChart, ShieldAlert, Cpu, Activity, RefreshCw } from 'lucide-react';

export default function Analytics({ liveAlerts }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const data = await api.getStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load stats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const categoryCounts = stats?.attack_category_counts || {};
  const categories = Object.keys(categoryCounts);
  const totalCategoryDetections = Object.values(categoryCounts).reduce((a, b) => a + b, 0) || 1;

  const threatLevels = stats?.threat_level_counts || {};
  const techniques = stats?.top_mitre_techniques || [];

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            Threat Intelligence & Detection Analytics
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Aggregated telemetry, attack vector distributions, and MITRE ATT&CK correlation matrix.
          </p>
        </div>

        <button onClick={fetchStats} className="btn-secondary text-xs self-start md:self-auto">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Metrics
        </button>
      </div>

      {/* Grid: Attack Category Distribution & Threat Levels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Attack Category Breakdown */}
        <div className="soc-card space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-[#1b283d] pb-3">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            Attack Category Distribution (Benchmark Ground Truth & Inferred)
          </h2>

          <div className="space-y-3 pt-1">
            {categories.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded">
                No categorical attack telemetry logged yet. Execute simulated streams to populate.
              </div>
            ) : (
              categories.map((cat, idx) => {
                const count = categoryCounts[cat];
                const pct = Math.round((count / totalCategoryDetections) * 100);

                return (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-medium text-slate-200">{cat}</span>
                      <span className="font-mono text-slate-400">
                        {count} events ({pct}%)
                      </span>
                    </div>
                    <div className="h-2 w-full bg-slate-900 rounded overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded"
                        style={{ width: `${Math.max(4, pct)}%` }}
                      ></div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Threat Level & Severity Breakdown */}
        <div className="soc-card space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-[#1b283d] pb-3">
            <Activity className="w-4 h-4 text-rose-400" />
            Severity & Prioritization Matrix
          </h2>

          <div className="grid grid-cols-2 gap-3 pt-1">
            <div className="p-4 bg-slate-900/60 rounded border border-rose-900/30 space-y-1">
              <span className="text-[10px] font-semibold text-rose-400 uppercase tracking-wider block">
                Critical Threats
              </span>
              <div className="font-mono text-2xl font-bold text-rose-400">
                {threatLevels.CRITICAL || 0}
              </div>
              <p className="text-[11px] text-slate-400">Composite Score ≥ 80.0</p>
            </div>

            <div className="p-4 bg-slate-900/60 rounded border border-amber-900/30 space-y-1">
              <span className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider block">
                High Threats
              </span>
              <div className="font-mono text-2xl font-bold text-amber-400">
                {threatLevels.HIGH || 0}
              </div>
              <p className="text-[11px] text-slate-400">Composite Score 60.0 - 79.9</p>
            </div>

            <div className="p-4 bg-slate-900/60 rounded border border-violet-900/30 space-y-1">
              <span className="text-[10px] font-semibold text-violet-400 uppercase tracking-wider block">
                Medium Threats
              </span>
              <div className="font-mono text-2xl font-bold text-violet-300">
                {threatLevels.MEDIUM || 0}
              </div>
              <p className="text-[11px] text-slate-400">Composite Score 40.0 - 59.9</p>
            </div>

            <div className="p-4 bg-slate-900/60 rounded border border-cyan-900/30 space-y-1">
              <span className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider block">
                Low / Info
              </span>
              <div className="font-mono text-2xl font-bold text-cyan-300">
                {(threatLevels.LOW || 0) + (threatLevels.INFO || 0)}
              </div>
              <p className="text-[11px] text-slate-400">Composite Score &lt; 40.0</p>
            </div>
          </div>

          <div className="p-3 bg-slate-950/50 rounded border border-slate-800 text-xs text-slate-400">
            Composite score fuses supervised confidence (40%), anomaly deviation (35%), and MITRE attack severity weighting (25%).
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix Table */}
      <div className="soc-card space-y-4">
        <div className="flex items-center justify-between border-b border-[#1b283d] pb-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-violet-400" />
            Top MITRE ATT&CK Enterprise Techniques Correlated
          </h2>
          <span className="text-xs font-mono text-slate-400">STIX 2.1 Taxonomy</span>
        </div>

        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>Correlated Detections</th>
                <th>Tactic Category</th>
                <th>Governance Enforcement</th>
                <th>STIX Link</th>
              </tr>
            </thead>
            <tbody>
              {techniques.length === 0 ? (
                <tr>
                  <td colSpan="6" className="text-center py-6 text-slate-500">
                    No MITRE techniques correlated yet. Launch simulated flows from the Demo tab.
                  </td>
                </tr>
              ) : (
                techniques.map((t, idx) => (
                  <tr key={idx}>
                    <td className="font-mono text-xs font-bold text-violet-400">{t.technique_id}</td>
                    <td className="font-semibold text-slate-200">{t.technique_name}</td>
                    <td className="font-mono text-xs text-cyan-400">{t.count}</td>
                    <td className="text-xs text-slate-400">Initial Access / Lateral Movement</td>
                    <td>
                      <span className="text-[10px] font-mono bg-indigo-950/70 text-indigo-300 px-1.5 py-0.5 rounded border border-indigo-800/40">
                        NONE_OBSERVE_ONLY
                      </span>
                    </td>
                    <td>
                      <a
                        href={`https://attack.mitre.org/techniques/${t.technique_id.replace('.', '/')}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-cyan-400 hover:underline text-xs"
                      >
                        attack.mitre.org →
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

