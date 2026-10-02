import React from 'react';
import { Globe2, FileText, CalendarRange, Landmark } from 'lucide-react';

export default function WhoisDetailsCard({ whoisInfo }) {
  if (!whoisInfo) return null;

  return (
    <div className="glass-card whois-card">
      <h3 className="section-title">
        <Globe2 size={20} style={{ color: 'var(--primary-cyan, #06b6d4)' }} />
        <span>WHOIS Domain Registry</span>
      </h3>

      <div className="whois-info-grid" style={{ marginTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div className="whois-info-item">
          <span className="whois-info-label">
            <Landmark size={15} style={{ marginRight: '0.35rem' }} />
            <strong>Registrar:</strong>
          </span>
          <span className="whois-info-value">{whoisInfo.registrar}</span>
        </div>

        <div className="whois-info-item">
          <span className="whois-info-label">
            <CalendarRange size={15} style={{ marginRight: '0.35rem' }} />
            <strong>Creation Date:</strong>
          </span>
          <span className="whois-info-value" style={{ fontFamily: 'var(--font-mono)' }}>{whoisInfo.created_date}</span>
        </div>

        <div className="whois-info-item">
          <span className="whois-info-label">
            <CalendarRange size={15} style={{ marginRight: '0.35rem' }} />
            <strong>Expiration Date:</strong>
          </span>
          <span className="whois-info-value" style={{ fontFamily: 'var(--font-mono)' }}>{whoisInfo.expiry_date}</span>
        </div>

        <div className="whois-info-item">
          <span className="whois-info-label">
            <FileText size={15} style={{ marginRight: '0.35rem' }} />
            <strong>Registry Server:</strong>
          </span>
          <span className="whois-info-value" style={{ fontSize: '0.85rem' }}>{whoisInfo.whois_server || "Unknown"}</span>
        </div>
      </div>
    </div>
  );
}
