import React from 'react';
import { ShieldCheck, ShieldAlert, Calendar, User, KeyRound } from 'lucide-react';

export default function SslDetailsCard({ sslInfo }) {
  if (!sslInfo) return null;

  const isError = !sslInfo.is_valid || sslInfo.status === "No SSL/Error" || sslInfo.status === "No SSL (Raw IP)";

  return (
    <div className="glass-card ssl-card">
      <h3 className="section-title">
        {isError ? (
          <ShieldAlert size={20} style={{ color: 'var(--status-danger, #dc2626)' }} />
        ) : (
          <ShieldCheck size={20} style={{ color: 'var(--status-safe, #16a34a)' }} />
        )}
        <span>SSL Certificate Details</span>
      </h3>

      {isError ? (
        <div className="ssl-error-content" style={{ marginTop: '1rem' }}>
          <p className="status-badge status-danger" style={{ textTransform: 'none', display: 'inline-flex' }}>
            {sslInfo.status || "Insecure"}
          </p>
          <p className="ssl-error-desc" style={{ fontSize: '0.85rem', marginTop: '0.75rem', color: 'var(--text-muted, #64748b)' }}>
            {sslInfo.error || sslInfo.message || "This host does not support secure HTTPS connection or certificate is missing."}
          </p>
        </div>
      ) : (
        <div className="ssl-info-grid" style={{ marginTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div className="ssl-info-item">
            <span className="ssl-info-label">
              <KeyRound size={15} style={{ marginRight: '0.35rem' }} />
              <strong>Common Name:</strong>
            </span>
            <span className="ssl-info-value">{sslInfo.common_name}</span>
          </div>

          <div className="ssl-info-item">
            <span className="ssl-info-label">
              <User size={15} style={{ marginRight: '0.35rem' }} />
              <strong>Issuer:</strong>
            </span>
            <span className="ssl-info-value">{sslInfo.issuer}</span>
          </div>

          <div className="ssl-info-item">
            <span className="ssl-info-label">
              <Calendar size={15} style={{ marginRight: '0.35rem' }} />
              <strong>Validity:</strong>
            </span>
            <span className="ssl-info-value" style={{ fontFamily: 'var(--font-mono)' }}>
              {sslInfo.valid_from} to {sslInfo.valid_to}
            </span>
          </div>

          <div className="ssl-expiry-warning" style={{ 
            marginTop: '0.5rem', 
            fontSize: '0.85rem', 
            padding: '0.6rem 0.85rem', 
            background: 'var(--status-safe-bg)', 
            border: '1px solid var(--status-safe-border)', 
            borderRadius: '6px', 
            color: 'var(--status-safe)' 
          }}>
            Certificate expires in <strong>{sslInfo.days_remaining} days</strong>.
          </div>
        </div>
      )}
    </div>
  );
}
