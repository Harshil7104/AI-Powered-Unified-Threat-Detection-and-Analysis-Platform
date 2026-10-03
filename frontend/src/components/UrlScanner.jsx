import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Search, Loader2, Code2, AlertTriangle } from 'lucide-react';
import ThreatScoreGauge from './ThreatScoreGauge';
import CheckDetails from './CheckDetails';
import SslDetailsCard from './SslDetailsCard';
import WhoisDetailsCard from './WhoisDetailsCard';
import IntelReportCard from './IntelReportCard';
import './UrlScanner.css';

const PRESET_SAMPLES = [
  { label: '🛡️ Safe HTTPS Site', url: 'https://google.com' },
  { label: '⚠️ IP Host & Keywords', url: 'http://192.168.1.1/login-verify-account-update-billing' },
  { label: '🔗 Shortened Link', url: 'https://bit.ly/3x89a' },
  { label: '🚨 Long Phishing Link', url: 'http://secure-banking-verify-update-user-password-credential-claim-free-bonus.com/update/account' }
];

export default function UrlScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [showJson, setShowJson] = useState(false);
  const navigate = useNavigate();

  const handleScan = async (targetUrl = url) => {
    if (!targetUrl.trim()) return;

    setLoading(true);
    setError(null);
    setScanResult(null);

    const endpoints = [
      '/api/url/scan',
      'http://127.0.0.1:8000/url/scan',
      'http://localhost:8000/url/scan'
    ];

    let success = false;
    let lastError = null;

    for (const endpoint of endpoints) {
      try {
        const response = await axios.post(endpoint, {
          url: targetUrl.trim()
        }, { timeout: 20000 }); // Increase timeout to 20s for WHOIS, SSL, and API lookups
        setScanResult(response.data);
        success = true;
        break;
      } catch (err) {
        lastError = err;
      }
    }

    if (!success && lastError) {
      console.error("URL Scan Error:", lastError);
      if (lastError.response) {
        setError(lastError.response.data.detail || `Server responded with status ${lastError.response.status}`);
      } else {
        setError("Failed to connect to FastAPI backend server. Please run the backend command in terminal: 'py -m uvicorn main:app --reload --port 8000'");
      }
    }

    setLoading(false);
  };


  const handlePresetClick = (sampleUrl) => {
    setUrl(sampleUrl);
    handleScan(sampleUrl);
  };

  return (
    <div className="scanner-section">
      {/* Scanner Input Card */}
      <div className="glass-card scanner-card">
        <label className="input-label">
          <Search size={18} style={{ color: 'var(--primary-cyan, #06b6d4)' }} />
          <span>Enter URL for Threat Analysis</span>
        </label>

        <div className="input-wrapper">
          <input
            type="text"
            className="url-input"
            placeholder="e.g. https://example.com or 192.168.1.1/login"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
          />
          <button
            className="scan-btn"
            onClick={() => handleScan()}
            disabled={loading || !url.trim()}
          >
            {loading ? (
              <>
                <Loader2 size={18} className="animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Search size={18} />
                <span>Scan URL</span>
              </>
            )}
          </button>
        </div>

        {/* Quick Presets */}
        <div className="preset-container">
          <span className="preset-title">Sample Tests:</span>
          {PRESET_SAMPLES.map((preset, idx) => (
            <button
              key={idx}
              className="preset-chip"
              onClick={() => handlePresetClick(preset.url)}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="error-banner">
          <AlertTriangle size={22} style={{ color: '#ef4444' }} />
          <div>
            <strong>Scan Failed:</strong> {error}
          </div>
        </div>
      )}

      {/* Results View */}
      {scanResult && (
        <>
          {/* Section 1: Standard Evaluation */}
          <div className="results-grid">
            <ThreatScoreGauge
              score={scanResult.risk_score}
              status={scanResult.status}
            />
            <CheckDetails
              checks={scanResult.checks}
              scannedUrl={scanResult.url}
            />
          </div>

          {/* Section 2: Domain and SSL Details */}
          <div className="advanced-results-grid">
            <SslDetailsCard sslInfo={scanResult.ssl_info} />
            <WhoisDetailsCard whoisInfo={scanResult.whois_info} />
          </div>

          {/* Section 3: Threat Intelligence Feeds */}
          <div style={{ marginTop: '1.5rem' }}>
            <IntelReportCard virustotal={scanResult.virustotal} otx={scanResult.otx} />
          </div>

          {/* Ask AI Threat Assistant */}
          <div style={{ marginTop: '1rem' }}>
            <button
              onClick={() => navigate('/ai-chat', { state: { scanContext: { ...scanResult, scan_type: 'url', target: scanResult.url } } })}
              style={{
                width: '100%',
                padding: '0.75rem 1.25rem',
                borderRadius: '8px',
                border: '1px solid rgba(6, 182, 212, 0.4)',
                backgroundColor: 'rgba(6, 182, 212, 0.1)',
                color: '#38bdf8',
                fontSize: '0.85rem',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                fontFamily: 'monospace',
                transition: 'all 0.2s ease'
              }}
            >
              <span>🤖</span>
              <span>Ask AI to Explain This URL Threat & Recommendations</span>
            </button>
          </div>

          {/* Raw API Response View (Week 2 Axios & FastAPI Integration requirement) */}
          <div style={{ marginTop: '1.5rem' }}>
            <button
              className="json-toggle-btn"
              onClick={() => setShowJson(!showJson)}
            >
              <Code2 size={16} />
              <span>{showJson ? "Hide Raw FastAPI Axios Response" : "View Raw FastAPI Axios Response"}</span>
            </button>

            {showJson && (
              <pre className="json-viewer">
                {JSON.stringify(scanResult, null, 2)}
              </pre>
            )}
          </div>
        </>
      )}
    </div>
  );
}
