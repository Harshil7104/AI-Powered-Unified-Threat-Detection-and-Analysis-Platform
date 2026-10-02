import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, ShieldCheck } from 'lucide-react';

export default function CheckDetails({ checks, scannedUrl }) {
  const getIcon = (severity, passed) => {
    if (passed && severity === 'safe') {
      return <CheckCircle2 className="check-icon" style={{ color: 'var(--status-safe)' }} size={22} />;
    }
    if (severity === 'warning') {
      return <AlertTriangle className="check-icon" style={{ color: 'var(--status-warning)' }} size={22} />;
    }
    return <XCircle className="check-icon" style={{ color: 'var(--status-danger)' }} size={22} />;
  };

  const getPillStyle = (severity) => {
    if (severity === 'safe') return { bg: 'var(--status-safe-bg)', color: 'var(--status-safe)' };
    if (severity === 'warning') return { bg: 'var(--status-warning-bg)', color: 'var(--status-warning)' };
    return { bg: 'var(--status-danger-bg)', color: 'var(--status-danger)' };
  };

  return (
    <div className="glass-card">
      <div className="checks-card-header">
        <h3 className="section-title">
          <ShieldCheck size={22} style={{ color: 'var(--primary-cyan, #06b6d4)' }} />
          Security Rule Evaluation
        </h3>
      </div>

      <div className="scanned-url-display">
        <strong>Scanned URL:</strong> {scannedUrl}
      </div>

      <div className="checks-list">
        {checks.map((item, idx) => {
          const pill = getPillStyle(item.severity);
          return (
            <div className="check-item" key={idx}>
              {getIcon(item.severity, item.passed)}
              <div className="check-content">
                <div className="check-title-row">
                  <span className="check-name">{item.name}</span>
                  <span 
                    className="severity-pill" 
                    style={{ background: pill.bg, color: pill.color }}
                  >
                    {item.severity}
                  </span>
                </div>
                <p className="check-desc">{item.message}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
