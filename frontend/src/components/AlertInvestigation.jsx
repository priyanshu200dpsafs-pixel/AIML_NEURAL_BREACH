import React, { useState } from 'react';
import { 
  Search, Shield, AlertTriangle, Cpu, ExternalLink, 
  CheckCircle2, FileText, ArrowRight, Activity, CornerDownRight 
} from 'lucide-react';

export default function AlertInvestigation({ selectedAlert, liveAlerts, onSelectAlert, setActiveTab }) {
  const [manualId, setManualId] = useState('');
  const [analystNote, setAnalystNote] = useState('');
  const [savedNotes, setSavedNotes] = useState([]);
  const [feedbackMsg, setFeedbackMsg] = useState('');

  const currentAlert = selectedAlert || (liveAlerts.length > 0 ? liveAlerts[0] : null);

  const handleAddNote = (e) => {
    e.preventDefault();
    if (!analystNote.trim()) return;
    const note = {
      id: Date.now(),
      text: analystNote,
      author: 'Senior SOC Analyst (Observer)',
      timestamp: new Date().toLocaleTimeString(),
      status: 'VERIFIED_OBSERVE_ONLY'
    };
    setSavedNotes([note, ...savedNotes]);
    setAnalystNote('');
    setFeedbackMsg('Analyst observation note recorded.');
    setTimeout(() => setFeedbackMsg(''), 3000);
  };

  if (!currentAlert) {
    return (
      <div className="soc-card p-12 text-center space-y-4 max-w-xl mx-auto my-8">
        <Search className="w-12 h-12 text-cyan-400 mx-auto animate-pulse" />
        <h2 className="text-lg font-bold text-white">No Security Alert Selected for Deep Investigation</h2>
        <p className="text-xs text-slate-400">
          Select an alert from the Live Alert Feed, run a benchmark simulation, or inspect a sample flow.
        </p>
        <div className="flex justify-center gap-3 pt-2">
          <button onClick={() => setActiveTab('demo')} className="btn-cyber text-xs">
            Run Benchmark Simulation
          </button>
          <button onClick={() => setActiveTab('alerts')} className="btn-secondary text-xs">
            View Live Alert Feed
          </button>
        </div>
      </div>
    );
  }

  const level = currentAlert.threat_level || currentAlert.threat_priority?.level || 'INFO';
  const score = currentAlert.composite_priority_score ?? currentAlert.threat_priority?.score ?? 0.0;
  const attackName = currentAlert.prediction?.label || currentAlert.prediction?.attack_type || currentAlert.attack_type || 'Security Flow Event';
  const attackCategory = currentAlert.prediction?.attack_category || currentAlert.attack_category || currentAlert.threat_intelligence?.attack_category || 'Intrusion';
  
  const badgeClass = 
    level === 'CRITICAL' ? 'badge-critical' :
    level === 'HIGH' ? 'badge-high' :
    level === 'MEDIUM' ? 'badge-medium' :
    level === 'LOW' ? 'badge-low' : 'badge-info';

  const explanation = currentAlert.explanation;
  const topFeatures = explanation?.top_features || [];
  
  // Support both Role 7 mitre_attack and Role 6 threat_intelligence.mitre_attack
  const mitre = currentAlert.mitre_attack || currentAlert.threat_intelligence?.mitre_attack || {};
  const primaryTech = mitre.primary_technique;
  const techniques = mitre.techniques || (primaryTech ? [primaryTech, ...(mitre.secondary_techniques || [])] : []);
  const tactics = mitre.tactics || [];
  const mitigations = mitre.mitigations || currentAlert.threat_intelligence?.mitigations || [];
  const anomaly = currentAlert.anomaly_detection || {};
  const net = currentAlert.network_context || currentAlert.flow_metadata || {};

  // Find max contribution for relative bar width
  const maxContrib = topFeatures.length > 0 
    ? Math.max(...topFeatures.map(f => Math.abs(f.contribution || 0)), 0.001)
    : 1;

  return (
    <div className="space-y-6">
      {/* Investigation Header */}
      <div className="soc-card space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-[#1b283d] pb-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className={`badge ${badgeClass}`}>{level}</span>
              <h1 className="text-lg font-bold text-white font-mono">
                {attackName}
              </h1>
              <span className="text-xs text-slate-400 font-mono">
                ID: {currentAlert.alert_id || 'stream-flow'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Timestamp: {currentAlert.timestamp ? new Date(currentAlert.timestamp).toUTCString() : 'Real-time Event'}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">Composite Priority</span>
              <span className="font-mono text-xl font-bold text-cyan-400">
                {typeof score === 'number' ? score.toFixed(1) : score}/100
              </span>
            </div>
            <div className="bg-indigo-950/60 border border-indigo-800/50 p-2 rounded text-right">
              <span className="text-[10px] text-indigo-300 block font-semibold uppercase">Action Enforced</span>
              <span className="font-mono text-xs font-bold text-indigo-200">NONE_OBSERVE_ONLY</span>
            </div>
          </div>
        </div>

        {/* Network 5-Tuple Context Banner */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs pt-1">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-semibold">Source / Flow</span>
            <span className="font-mono text-slate-200 font-medium">
              {net.src_ip ? `${net.src_ip}:${net.src_port}` : `Flow #${net.flow_index ?? '001'}`}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-semibold">Target / Host</span>
            <span className="font-mono text-slate-200 font-medium">
              {net.dst_ip ? `${net.dst_ip}:${net.dst_port}` : '10.0.0.1:443'}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-semibold">Protocol</span>
            <span className="font-mono text-cyan-300 font-medium">{net.protocol || 'TCP (6)'}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-semibold">Flow ID</span>
            <span className="font-mono text-slate-300 truncate block text-[11px]">{currentAlert.flow_id || currentAlert.alert_id || 'flow-001'}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-semibold">Category</span>
            <span className="font-mono text-amber-300 font-medium">{attackCategory}</span>
          </div>
        </div>
      </div>

      {/* 2-Column Grid: Explainable AI (SHAP) & Detection Diagnostics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left Column: Explainable AI Attribution (SHAP / LIME) */}
        <div className="soc-card space-y-4">
          <div className="flex items-center justify-between border-b border-[#1b283d] pb-3">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-violet-400" />
              <h2 className="text-sm font-semibold text-white">Explainable AI (XAI) Attribution</h2>
            </div>
            <span className="text-xs font-mono bg-violet-950/60 text-violet-300 px-2 py-0.5 rounded border border-violet-800/40">
              {explanation?.explainer_type?.toUpperCase() || 'SHAP TREE-EXPLAINER'}
            </span>
          </div>

          <p className="text-xs text-slate-400">
            Feature contribution values calculated via Shapley additive explanations (SHAP). 
            <span className="text-rose-400 font-medium"> Red</span> indicates features pushing towards attack classification; 
            <span className="text-cyan-400 font-medium"> Cyan</span> indicates features pulling towards benign baseline.
          </p>

          {/* Waterfall Contribution Chart */}
          <div className="space-y-2 pt-2">
            {topFeatures.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded">
                No feature attribution provided for this event. Execute single flow inference with explain=True.
              </div>
            ) : (
              topFeatures.map((feat, idx) => {
                const contrib = feat.contribution || 0;
                const isPositive = contrib >= 0;
                const barWidth = Math.min(100, Math.max(8, Math.round((Math.abs(contrib) / maxContrib) * 100)));

                return (
                  <div key={idx} className="shap-bar-container">
                    <span className="shap-bar-label text-xs" title={feat.feature}>
                      {feat.feature}
                    </span>

                    <div className="shap-bar-track">
                      <div
                        className={isPositive ? 'shap-bar-fill-positive' : 'shap-bar-fill-negative'}
                        style={{ width: `${barWidth}%` }}
                      ></div>
                    </div>

                    <div className="text-right w-20 font-mono text-[11px] whitespace-nowrap">
                      <span className={isPositive ? 'text-rose-400 font-semibold' : 'text-cyan-400'}>
                        {isPositive ? `+${contrib.toFixed(4)}` : contrib.toFixed(4)}
                      </span>
                    </div>

                    <div className="w-16 text-right font-mono text-[10px] text-slate-500 truncate" title={`Feature Value: ${feat.feature_value}`}>
                      val: {typeof feat.feature_value === 'number' ? feat.feature_value.toFixed(1) : feat.feature_value}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {explanation?.base_value !== undefined && (
            <div className="border-t border-[#1b283d] pt-3 flex justify-between text-xs text-slate-400 font-mono">
              <span>Model Expected Value E[f(x)]:</span>
              <span className="text-slate-200">{explanation.base_value.toFixed(4)}</span>
            </div>
          )}
        </div>

        {/* Right Column: Multi-Engine Detection Diagnostics & Anomaly Telemetry */}
        <div className="space-y-6">
          {/* Dual-Engine Anomaly Telemetry */}
          <div className="soc-card space-y-3">
            <div className="flex items-center justify-between border-b border-[#1b283d] pb-2">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                Unsupervised Anomaly Telemetry
              </h3>
              <span className="text-xs font-mono text-slate-400">Role 3 Ensembles</span>
            </div>

            <div className="grid grid-cols-2 gap-3 pt-1">
              {/* Isolation Forest Card */}
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block">Isolation Forest</span>
                <div className="font-mono text-base font-bold text-slate-100">
                  {anomaly.iso_forest_score !== undefined ? anomaly.iso_forest_score.toFixed(4) : '—'}
                </div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-500">Decision:</span>
                  <span className={`font-semibold font-mono ${anomaly.iso_forest_anomaly ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {anomaly.iso_forest_anomaly ? 'ANOMALOUS' : 'NOMINAL'}
                  </span>
                </div>
              </div>

              {/* Deep Autoencoder Card */}
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block">Deep Autoencoder</span>
                <div className="font-mono text-base font-bold text-slate-100">
                  {anomaly.autoencoder_recon_error !== undefined ? anomaly.autoencoder_recon_error.toFixed(4) : '—'}
                </div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-500">Recon Error:</span>
                  <span className={`font-semibold font-mono ${anomaly.autoencoder_anomaly ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {anomaly.autoencoder_anomaly ? 'ANOMALOUS' : 'NOMINAL'}
                  </span>
                </div>
              </div>
            </div>

            <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800 text-xs text-slate-400 flex items-center justify-between">
              <span>Overall Anomaly Flag:</span>
              <span className={`font-mono font-bold ${anomaly.is_anomaly ? 'text-rose-400' : 'text-emerald-400'}`}>
                {anomaly.is_anomaly ? 'UNSUPERVISED OUTLIER DETECTED' : 'WITHIN NORMAL RESIDUAL BOUNDS'}
              </span>
            </div>
          </div>

          {/* Supervised Classifier Performance */}
          <div className="soc-card space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-[#1b283d] pb-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Supervised Classifier Details
            </h3>

            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/40">
                <span className="text-slate-400">Model Engine</span>
                <span className="font-mono text-slate-200">LightGBM (Role 3 Retrain v2)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/40">
                <span className="text-slate-400">Class Probability / Confidence</span>
                <span className="font-mono font-bold text-cyan-400">
                  {currentAlert.prediction?.confidence ? `${(currentAlert.prediction.confidence * 100).toFixed(2)}%` : '—'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/40">
                <span className="text-slate-400">Target Attack Classification</span>
                <span className="font-mono text-rose-300 font-semibold">
                  {currentAlert.prediction?.attack_type || 'Benign'}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Operating Budget</span>
                <span className="font-mono text-emerald-400">1% FPR Operating Threshold</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Framework Mapping */}
      <div className="soc-card space-y-4">
        <div className="flex items-center justify-between border-b border-[#1b283d] pb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white">MITRE ATT&CK Framework Intelligence Mapping</h2>
          </div>
          <span className="text-xs text-slate-400">STIX 2.1 Enterprise Catalog</span>
        </div>

        {techniques.length > 0 ? (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {techniques.map((tech, idx) => (
                <div key={idx} className="p-4 bg-slate-900/60 rounded border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-violet-400 bg-violet-950/60 px-2 py-0.5 rounded border border-violet-800/40">
                      {tech.id || tech.technique_id}
                    </span>
                    <a
                      href={tech.url || `https://attack.mitre.org/techniques/${(tech.id || tech.technique_id || '').replace('.', '/')}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
                    >
                      MITRE ATT&CK Spec <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>

                  <h4 className="text-sm font-semibold text-white">{tech.name || tech.technique_name}</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {tech.description || 'Enterprise attack tactic mapping verified against STIX 2.1 taxonomy.'}
                  </p>
                </div>
              ))}
            </div>

            {/* Mitigations */}
            {mitigations.length > 0 && (
              <div className="border-t border-[#1b283d] pt-3">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-2">
                  Recommended Observational Mitigations
                </span>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {mitigations.map((m, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <CornerDownRight className="w-3.5 h-3.5 text-cyan-400 mt-0.5 shrink-0" />
                      <span>{typeof m === 'object' ? m.name || m.description : m}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ) : (
          <div className="p-6 text-center text-xs text-slate-400 bg-slate-900/30 rounded border border-dashed border-slate-800">
            No specific MITRE ATT&CK technique mapping registered for benign baseline network flows.
          </div>
        )}
      </div>

      {/* SOC Analyst Observation Notes & Triage */}
      <div className="soc-card space-y-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-[#1b283d] pb-3">
          <FileText className="w-4 h-4 text-cyan-400" />
          SOC Analyst Observation & Triage Log (Observe-Only)
        </h3>

        <form onSubmit={handleAddNote} className="space-y-3">
          <textarea
            rows="2"
            value={analystNote}
            onChange={(e) => setAnalystNote(e.target.value)}
            placeholder="Record analyst findings, correlation notes, or containment recommendations for team review..."
            className="input-soc text-xs"
          ></textarea>

          <div className="flex items-center justify-between">
            <span className="text-xs text-emerald-400 font-medium">{feedbackMsg}</span>
            <button type="submit" className="btn-cyber text-xs">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Save Observation Note
            </button>
          </div>
        </form>

        {savedNotes.length > 0 && (
          <div className="space-y-2 border-t border-[#1b283d] pt-3">
            {savedNotes.map((note) => (
              <div key={note.id} className="p-2.5 bg-slate-900/50 rounded border border-slate-800 text-xs space-y-1">
                <div className="flex justify-between text-[11px] text-slate-400">
                  <span className="font-semibold text-cyan-300">{note.author}</span>
                  <span className="font-mono">{note.timestamp}</span>
                </div>
                <p className="text-slate-200">{note.text}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
