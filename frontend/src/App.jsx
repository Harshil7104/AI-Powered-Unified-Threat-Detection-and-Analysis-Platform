import React from 'react';
import UrlScanner from './components/UrlScanner';

export default function App() {
  return (
    <div className="app-container">
      <header className="app-header">
        <h1 className="app-title">Unified Threat Detection Platform</h1>
        <p className="app-subtitle">
          Rule-based URL analysis evaluating HTTPS protocol, URL length, host IP addresses, phishing keywords, and URL shorteners.
        </p>
      </header>

      <main>
        <UrlScanner />
      </main>

      <footer className="app-footer">
        <p>AI-Powered Unified Threat Detection Platform &copy; FastAPI + React (Axios)</p>
      </footer>
    </div>
  );
}
