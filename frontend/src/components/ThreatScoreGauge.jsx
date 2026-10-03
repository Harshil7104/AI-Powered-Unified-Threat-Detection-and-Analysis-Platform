import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

export default function ThreatScoreGauge({ score, status }) {
  const getStatusColor = () => {
    if (status === 'Safe') return 'var(--status-safe)';
    if (status === 'Suspicious') return 'var(--status-warning)';
    return 'var(--status-danger)';
  };

  const getStatusClass = () => {
    if (status === 'Safe') return 'status-safe';
    if (status === 'Suspicious') return 'status-warning';
    return 'status-danger';
  };

  const renderIcon = () => {
    if (status === 'Safe') return <ShieldCheck size={20} />;
    if (status === 'Suspicious') return <AlertTriangle size={20} />;
    return <ShieldAlert size={20} />;
  };

  const color = getStatusColor();

  return (
    <div className="glass-card score-card">
      <div className="score-circle" style={{ color: color }}>
        <span className="score-number">{score}</span>
        <span className="score-label">Risk Index</span>
      </div>

      <div className={`status-badge ${getStatusClass()}`}>
        {renderIcon()}
        <span>{status}</span>
      </div>
    </div>
  );
}
