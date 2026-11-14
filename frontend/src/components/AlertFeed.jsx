import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { 
  Radio, Filter, Search, Play, Pause, Trash2, RefreshCw, 
  Eye, ShieldAlert, ArrowUpDown, ChevronRight, Activity 
} from 'lucide-react';

export default function AlertFeed({ liveAlerts, onSelectAlert, setActiveTab, isStreamPaused, setIsStreamPaused, onClearFeed }) {
  const [historicalAlerts, setHistoricalAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [threatLevelFilter, setThreatLevelFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [minScore, setMinScore] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFeedMode, setSelectedFeedMode] = useState('live'); // 'live' | 'historical'

  // Fetch historical alerts from API
  const fetchHistoricalAlerts = async () => {
    try {
      setLoading(true);
      const res = await api.getAlerts({
        threat_level: threatLevelFilter || undefined,
        attack_category: categoryFilter || undefined,
        min_score: minScore > 0 ? minScore : undefined,
        limit: 100
      });
      setHistoricalAlerts(res.alerts || []);
    } catch (err) {
      console.error('Failed to load historical alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedFeedMode === 'historical') {
      fetchHistoricalAlerts();
    }
  }, [selectedFeedMode, threatLevelFilter, categoryFilter, minScore]);

  // Combine or select active list
  const baseAlerts = selectedFeedMode === 'live' ? liveAlerts : historicalAlerts;

  // Filter in memory for instantaneous search response
  const filteredAlerts = baseAlerts.filter((alert) => {
    if (threatLevelFilter && alert.threat_level !== threatLevelFilter) return false;
    if (minScore > 0 && (alert.composite_priority_score || 0) < minScore) return false;
    if (categoryFilter) {
      const cat = alert.prediction?.attack_category || alert.attack_category;
      if (cat !== categoryFilter) return false;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const idMatch = (alert.alert_id || '').toLowerCase().includes(q);
      const attackMatch = (alert.prediction?.attack_type || alert.attack_type || '').toLowerCase().includes(q);
      const srcMatch = (alert.network_context?.src_ip || '').toLowerCase().includes(q);
      const dstMatch = (alert.network_context?.dst_ip || '').toLowerCase().includes(q);
      if (!idMatch && !attackMatch && !srcMatch && !dstMatch) return false;
    }
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Feed Control Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Radio className="w-5 h-5 text-cyan-400" />
            SOC Real-Time Threat Stream & Historical Triage
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time WebSocket ingestion with multi-criteria filtering and instant XAI diagnostics.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Feed Mode Switcher */}
          <div className="bg-slate-900 p-0.5 rounded-lg border border-slate-800 flex items-center text-xs">
            <button
              onClick={() => setSelectedFeedMode('live')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                selectedFeedMode === 'live' 
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Live Stream ({liveAlerts.length})
            </button>
            <button
              onClick={() => setSelectedFeedMode('historical')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                selectedFeedMode === 'historical' 
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Stored Database
            </button>
          </div>

          {selectedFeedMode === 'live' ? (
            <button
              onClick={() => setIsStreamPaused(!isStreamPaused)}
              className={`btn-secondary text-xs ${isStreamPaused ? 'text-amber-400 border-amber-800' : ''}`}
            >
              {isStreamPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
              {isStreamPaused ? 'Resume Stream' : 'Pause Stream'}
            </button>
          ) : (
            <button
              onClick={fetchHistoricalAlerts}
              className="btn-secondary text-xs"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Reload
            </button>
          )}

          {selectedFeedMode === 'live' && (
            <button
              onClick={onClearFeed}
              className="btn-secondary text-xs text-rose-400 hover:text-rose-300"
              title="Clear visible stream buffer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-card grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 py-3">
        {/* Search */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search IP, Attack, Alert ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input-soc pl-9 text-xs"
          />
        </div>

        {/* Threat Level Filter */}
        <div>
          <select
            value={threatLevelFilter}
            onChange={(e) => setThreatLevelFilter(e.target.value)}
            className="input-soc text-xs"
          >
            <option value="">All Threat Levels</option>
            <option value="CRITICAL">Critical (Score ≥ 80)</option>
            <option value="HIGH">High (Score 60-79)</option>
            <option value="MEDIUM">Medium (Score 40-59)</option>
            <option value="LOW">Low (Score &lt; 40)</option>
            <option value="INFO">Informational / Benign</option>
          </select>
        </div>

        {/* Attack Category */}
        <div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="input-soc text-xs"
          >
            <option value="">All Attack Categories</option>
            <option value="Infiltration">Infiltration</option>
            <option value="Brute Force">Brute Force</option>
            <option value="DoS">Denial of Service (DoS)</option>
            <option value="DDoS">Distributed DoS (DDoS)</option>
            <option value="Web Attack">Web Attack</option>
            <option value="Botnet">Botnet</option>
            <option value="Benign">Benign / Normal</option>
          </select>
        </div>

        {/* Min Score Slider */}
        <div className="flex items-center gap-2 px-1">
          <span className="text-[11px] text-slate-400 whitespace-nowrap">Min Score:</span>
          <input
            type="range"
            min="0"
            max="100"
            step="5"
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
            className="w-full accent-cyan-400"
          />
          <span className="font-mono text-xs text-cyan-400 w-8 text-right">{minScore}</span>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="soc-card p-0 overflow-hidden">
        <div className="overflow-x-auto max-h-[620px]">
          <table className="soc-table">
            <thead className="sticky top-0 z-10">
              <tr>
                <th>Timestamp</th>
                <th>Threat Level</th>
                <th>Classification</th>
                <th>Confidence</th>
                <th>Anomaly Engine</th>
                <th>Network 5-Tuple</th>
                <th>Priority</th>
                <th>Action Enforced</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="9" className="text-center py-12 text-slate-500">
                    <Radio className="w-8 h-8 mx-auto mb-2 text-slate-600 opacity-60" />
                    <p className="text-sm font-medium text-slate-400">No security alerts matching current criteria.</p>
                    <p className="text-xs text-slate-500 mt-1">
                      {selectedFeedMode === 'live' 
                        ? 'Simulate authentic flows from Demo Scenarios tab or clear filters.' 
                        : 'Adjust query filters or execute new detection batches.'}
                    </p>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert, idx) => {
                  const level = alert.threat_level || alert.threat_priority?.level || 'INFO';
                  const score = alert.composite_priority_score ?? alert.threat_priority?.score ?? 0.0;
                  const attackName = alert.prediction?.label || alert.prediction?.attack_type || alert.attack_type || 'Benign Flow';
                  const badgeClass = 
                    level === 'CRITICAL' ? 'badge-critical' :
                    level === 'HIGH' ? 'badge-high' :
                    level === 'MEDIUM' ? 'badge-medium' :
                    level === 'LOW' ? 'badge-low' : 'badge-info';

                  const isAttack = alert.prediction?.is_attack ?? false;
                  const isAnomaly = alert.anomaly_detection?.is_anomaly ?? false;

                  return (
                    <tr key={alert.alert_id || idx} className="hover:bg-slate-800/40 transition">
                      <td className="font-mono text-xs text-slate-400 whitespace-nowrap">
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Live'}
                      </td>
                      <td>
                        <span className={`badge ${badgeClass}`}>{level}</span>
                      </td>
                      <td>
                        <div className="font-semibold text-slate-200">
                          {attackName}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          {alert.prediction?.attack_category || alert.attack_category || (isAttack ? 'Intrusion' : 'Benign')}
                        </div>
                      </td>
                      <td className="font-mono text-xs">
                        {alert.prediction?.confidence !== undefined ? (
                          <span className={alert.prediction.confidence > 0.85 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                            {(alert.prediction.confidence * 100).toFixed(1)}%
                          </span>
                        ) : '—'}
                      </td>
                      <td className="font-mono text-xs">
                        {isAnomaly ? (
                          <span className="text-emerald-400 font-semibold flex items-center gap-1" title="Isolation Forest + Autoencoder flagged anomaly">
                            <Activity className="w-3 h-3" /> ANOMALY
                          </span>
                        ) : (
                          <span className="text-slate-500 text-[11px]">Nominal</span>
                        )}
                      </td>
                      <td className="font-mono text-xs text-slate-300 whitespace-nowrap">
                        <div>
                          {alert.network_context 
                            ? `${alert.network_context.src_ip}:${alert.network_context.src_port}` 
                            : (alert.flow_metadata ? `Flow #${alert.flow_metadata.flow_index}` : '192.168.1.100:54212')}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          → {alert.network_context 
                            ? `${alert.network_context.dst_ip}:${alert.network_context.dst_port} (${alert.network_context.protocol || 'TCP'})` 
                            : (alert.flow_metadata ? `Proto: ${alert.flow_metadata.protocol}` : '10.0.0.1:443 (TCP)')}
                        </div>
                      </td>
                      <td className="font-mono text-xs font-bold text-cyan-400">
                        {typeof score === 'number' ? score.toFixed(1) : score}
                      </td>
                      <td>
                        <span className="text-[10px] font-mono bg-indigo-950/70 text-indigo-300 px-1.5 py-0.5 rounded border border-indigo-800/40">
                          NONE_OBSERVE_ONLY
                        </span>
                      </td>
                      <td>
                        <button
                          onClick={() => {
                            onSelectAlert(alert);
                            setActiveTab('investigate');
                          }}
                          className="btn-secondary text-[11px] py-1 px-2.5 flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                        >
                          <Eye className="w-3 h-3" />
                          Investigate
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
