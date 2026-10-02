import React from 'react';
import { Activity, ShieldAlert, CheckCircle2, AlertOctagon, HelpCircle } from 'lucide-react';

export default function IntelReportCard({ virustotal, otx }) {
  const getVtContent = () => {
    if (!virustotal) return <p style={{ color: 'var(--text-light, #94a3b8)' }}>No report available</p>;
    if (virustotal.status === 'unconfigured') {
      return (
        <div className="intel-status-unconfigured" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-muted, #64748b)', background: '#f1f5f9', padding: '0.6rem 0.85rem', borderRadius: '6px' }}>
          <HelpCircle size={16} style={{ flexShrink: 0 }} />
          <span>VirusTotal API key is not configured in backend .env</span>
        </div>
      );
    }
    if (virustotal.status === 'scanning') {
      return (
        <div className="intel-status-unconfigured" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-muted, #64748b)', background: '#f1f5f9', padding: '0.6rem 0.85rem', borderRadius: '6px' }}>
          <Activity size={16} className="animate-pulse" style={{ flexShrink: 0 }} />
          <span>URL submitted to VirusTotal. Analysis in progress...</span>
        </div>
      );
    }
    if (virustotal.status !== 'success') {
      return <p style={{ color: 'var(--status-danger, #dc2626)', fontSize: '0.85rem' }}>Error: {virustotal.message}</p>;
    }

    const { malicious, harmless, undetected, reputation } = virustotal;
    const hasThreat = malicious > 0;

    return (
      <div className="vt-report-details" style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
        <div className="vt-stats-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem' }}>
          <div className="vt-stat-box" style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', padding: '0.5rem', borderRadius: '6px', textAlign: 'center' }}>
            <div style={{ color: '#16a34a', fontWeight: 'bold', fontSize: '1.1rem' }}>{harmless}</div>
            <div style={{ fontSize: '0.75rem', color: '#16a34a' }}>Clean</div>
          </div>
          <div className="vt-stat-box" style={{ 
            background: hasThreat ? 'var(--status-danger-bg)' : '#f8fafc', 
            border: hasThreat ? '1px solid var(--status-danger-border)' : '1px solid var(--border-color)', 
            padding: '0.5rem', 
            borderRadius: '6px', 
            textAlign: 'center' 
          }}>
            <div style={{ color: hasThreat ? 'var(--status-danger)' : 'var(--text-muted)', fontWeight: 'bold', fontSize: '1.1rem' }}>{malicious}</div>
            <div style={{ fontSize: '0.75rem', color: hasThreat ? 'var(--status-danger)' : 'var(--text-muted)' }}>Malicious</div>
          </div>
          <div className="vt-stat-box" style={{ background: '#f8fafc', border: '1px solid var(--border-color)', padding: '0.5rem', borderRadius: '6px', textAlign: 'center' }}>
            <div style={{ color: 'var(--text-muted)', fontWeight: 'bold', fontSize: '1.1rem' }}>{undetected}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Undetected</div>
          </div>
        </div>
        <div className="vt-reputation" style={{ fontSize: '0.85rem', marginTop: '0.25rem' }}>
          Reputation Score: <strong style={{ color: reputation < 0 ? 'var(--status-danger)' : 'var(--status-safe)' }}>{reputation}</strong>
        </div>
      </div>
    );
  };

  const getOtxContent = () => {
    if (!otx) return <p style={{ color: 'var(--text-light, #94a3b8)' }}>No report available</p>;
    if (otx.status !== 'success') {
      return (
        <div className="intel-status-unconfigured" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-muted, #64748b)', background: '#f1f5f9', padding: '0.6rem 0.85rem', borderRadius: '6px' }}>
          <HelpCircle size={16} style={{ flexShrink: 0 }} />
          <span>{otx.message || "OTX API is unconfigured or unavailable."}</span>
        </div>
      );
    }

    const { pulse_count, tags, threat_level } = otx;

    return (
      <div className="otx-report-details" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem' }}>
          <span>Active Threat Pulses:</span>
          <strong style={{ color: pulse_count > 0 ? 'var(--status-danger)' : 'var(--status-safe)' }}>{pulse_count}</strong>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.875rem' }}>
          <span>OTX Threat Level:</span>
          <span className={`severity-pill ${threat_level === 'High' ? 'status-danger' : (threat_level === 'Medium' ? 'status-warning' : 'status-safe')}`}>
            {threat_level}
          </span>
        </div>
        {tags && tags.length > 0 && (
          <div className="otx-tags" style={{ marginTop: '0.25rem' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)' }}>Tags:</div>
            <div className="otx-tag-list" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.25rem' }}>
              {tags.map((tag, idx) => (
                <span key={idx} className="preset-chip" style={{ margin: 0, padding: '0.15rem 0.45rem', fontSize: '0.7rem' }}>
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="glass-card intel-card">
      <h3 className="section-title">
        <Activity size={20} style={{ color: 'var(--primary-cyan, #06b6d4)' }} />
        <span>Threat Intelligence Feeds</span>
      </h3>

      <div className="intel-grids">
        {/* VirusTotal Panel */}
        <div className="intel-panel">
          <h4 className="intel-panel-title">
            <AlertOctagon size={16} />
            <span>VirusTotal Scan Report</span>
          </h4>
          {getVtContent()}
        </div>

        {/* AlienVault OTX Panel */}
        <div className="intel-panel">
          <h4 className="intel-panel-title">
            <ShieldAlert size={16} />
            <span>AlienVault OTX Intelligence</span>
          </h4>
          {getOtxContent()}
        </div>
      </div>
    </div>
  );
}
